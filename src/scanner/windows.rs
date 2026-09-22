/// Windows WeChat 进程内存密钥扫描器
///
/// 使用 Windows API：
/// - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
/// - OpenProcess: 获取进程句柄（需要 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION）
/// - VirtualQueryEx: 枚举内存区域
/// - ReadProcessMemory: 读取内存内容
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_salt_hex, is_writable_readable_page,
    match_key_hexes, scan_key_patterns, unique_key_hexes, KeyEntry, MAX_PATTERN_BYTES,
};

const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// 枚举所有 Weixin.exe 进程 PID。
///
/// 微信 4.x 是多进程架构（UI / 渲染 / 网络服务等），SQLCipher 密钥不一定
/// 在快照枚举到的第一个进程里，必须逐个扫描。
pub(crate) fn find_wechat_pids() -> Vec<u32> {
    let mut pids = Vec::new();

    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let Some(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok() }) else {
        return pids;
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_ok() {
            loop {
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy();
                if name.eq_ignore_ascii_case("Weixin.exe") {
                    pids.push(entry.th32ProcessID);
                }
                if Process32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pids = find_wechat_pids();
    if pids.is_empty() {
        bail!("找不到 Weixin.exe 进程，请确认微信正在运行");
    }
    eprintln!("找到 {} 个 Weixin.exe 进程: {:?}", pids.len(), pids);

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());
    if db_salts.is_empty() {
        bail!("数据目录中没有加密的 .db 文件: {}", db_dir.display());
    }

    let salt_bytes: Vec<[u8; 16]> = db_salts
        .iter()
        .filter_map(|(s, _)| decode_salt_hex(s))
        .collect();

    let mut raw_keys: Vec<(String, String)> = Vec::new();
    let mut extra_keys: Vec<String> = Vec::new();
    let mut seen_extra: HashSet<String> = HashSet::new();
    let mut opened = 0usize;

    for pid in &pids {
        // SAFETY: OpenProcess 请求读取权限；单个进程失败（已退出/权限不足）跳过，不阻断其余
        let process = match unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, *pid)
        } {
            Ok(h) => h,
            Err(e) => {
                eprintln!("警告: OpenProcess(PID {pid}) 失败（{e}），跳过该进程");
                continue;
            }
        };
        opened += 1;
        eprintln!("扫描进程内存 (PID {pid})...");
        scan_memory(
            process,
            &salt_bytes,
            &mut raw_keys,
            &mut extra_keys,
            &mut seen_extra,
        );
        // SAFETY: 关闭进程句柄
        unsafe {
            let _ = CloseHandle(process);
        }
    }
    if opened == 0 {
        bail!(
            "OpenProcess 失败（{} 个 Weixin.exe 进程均无法打开），请以管理员身份运行",
            pids.len()
        );
    }

    eprintln!(
        "内存扫描完成：x'hex' 候选 {} 个，salt 邻接候选 {} 个",
        raw_keys.len(),
        extra_keys.len()
    );

    // 合并两类候选后统一匹配：salt 配对优先（x'key+salt' 旧路径），
    // 其余候选兜底（新版 WCDB 不再保留 PRAGMA 字符串，key 以二进制形式邻接 salt）。
    let mut all_key_hexes = unique_key_hexes(&raw_keys);
    for k in &extra_keys {
        if !all_key_hexes.iter().any(|x| x == k) {
            all_key_hexes.push(k.clone());
        }
    }

    let entries = if all_key_hexes.is_empty() {
        Vec::new()
    } else {
        match_key_hexes(db_dir, &all_key_hexes, &raw_keys, &db_salts)
    };
    eprintln!(
        "匹配到 {}/{} 个数据库密钥（候选 key {} 个）",
        entries.len(),
        db_salts.len(),
        all_key_hexes.len()
    );
    Ok(entries)
}

fn scan_memory(
    process: HANDLE,
    salts: &[[u8; 16]],
    raw_keys: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) {
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;

        // 只扫描已提交的可读可写页面（含 WRITECOPY / EXECUTE_*WRITE*；见
        // `is_writable_readable_page`，从 old-main #54 捞回）。
        if mbi.State == MEM_COMMIT && is_writable_readable_page(mbi.Protect.0) {
            scan_region(
                process,
                base,
                region_size,
                salts,
                raw_keys,
                extra_keys,
                seen_extra,
            );
        }

        addr = base.saturating_add(region_size);
        if addr == 0 {
            break; // overflow
        }
    }
}

fn scan_region(
    process: HANDLE,
    base: usize,
    size: usize,
    salts: &[[u8; 16]],
    raw_keys: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) {
    let overlap = MAX_PATTERN_BYTES;
    let mut offset = 0usize;

    loop {
        if offset >= size {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let addr = base + offset;
        let mut buf = vec![0u8; chunk_size];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory 读取目标进程内存
        let ok = unsafe {
            ReadProcessMemory(
                process,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                chunk_size,
                Some(&mut bytes_read),
            )
            .is_ok()
        };

        if ok && bytes_read > 0 {
            buf.truncate(bytes_read);
            // 1) 旧版 WCDB 缓存的 `x'<key><salt>'` PRAGMA 字符串
            scan_key_patterns(&buf, raw_keys);
            // 2) 新版堆上的「key||salt」/「salt||key」二进制邻接（与 macOS 扫描器同源）
            collect_salt_adjacent_keys(&buf, salts, extra_keys, seen_extra);
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}
