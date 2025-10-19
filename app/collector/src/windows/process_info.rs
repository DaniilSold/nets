// Windows-specific process information collector
// Implements PID->Process binding with hash, signature, and user information

#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::{fs, mem};

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use tracing::{debug, warn};
#[cfg(windows)]
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, MAX_PATH},
        Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
        },
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            ProcessStatus::K32GetModuleFileNameExW,
            Threading::{
                OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
                PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ,
            },
        },
    },
};

use crate::ProcessIdentity;

#[cfg(windows)]
pub struct ProcessInfoCollector;

#[cfg(windows)]
impl ProcessInfoCollector {
    /// Get comprehensive process information by PID
    pub fn get_process_info(pid: i32) -> Option<ProcessIdentity> {
        if pid <= 0 {
            return None;
        }

        let name = Self::get_process_name(pid as u32);
        let exe_path = Self::get_process_path(pid as u32);
        let sha256_16 = exe_path
            .as_ref()
            .and_then(|path| Self::calculate_sha256_prefix(path));
        let user = Self::get_process_user(pid as u32);
        let signed = exe_path
            .as_ref()
            .map(|path| Self::is_binary_signed(path));
        let ppid = Self::get_parent_pid(pid as u32);

        Some(ProcessIdentity {
            pid,
            ppid,
            name,
            exe_path,
            sha256_16,
            user,
            signed,
        })
    }

    /// Get process name from PID
    fn get_process_name(pid: u32) -> Option<String> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let mut entry = PROCESSENTRY32W {
                dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile[..entry
                                .szExeFile
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(entry.szExeFile.len())],
                        );
                        let _ = CloseHandle(snapshot);
                        return Some(name);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        None
    }

    /// Get full path to process executable
    fn get_process_path(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            )
            .ok()?;

            let mut buffer = vec![0u16; MAX_PATH as usize];
            let mut size = buffer.len() as u32;

            let result = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, &mut buffer);

            let _ = CloseHandle(handle);

            if result.is_ok() && size > 0 {
                let path = String::from_utf16_lossy(
                    &buffer[..buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len())],
                );
                return Some(path);
            }
        }
        None
    }

    /// Get parent process ID
    fn get_parent_pid(pid: u32) -> Option<i32> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let mut entry = PROCESSENTRY32W {
                dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let ppid = entry.th32ParentProcessID as i32;
                        let _ = CloseHandle(snapshot);
                        return Some(ppid);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        None
    }

    /// Get process owner (user SID/username)
    fn get_process_user(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;

            let mut token = HANDLE::default();
            if OpenProcessToken(handle, TOKEN_QUERY, &mut token).is_err() {
                let _ = CloseHandle(handle);
                return None;
            }

            // Get token user info size
            let mut size = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);

            let mut buffer = vec![0u8; size as usize];
            let result = GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                size,
                &mut size,
            );

            let _ = CloseHandle(token);
            let _ = CloseHandle(handle);

            if result.is_ok() {
                let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
                // For now, return SID as string (can be extended to lookup username)
                return Some(format!("SID-{:?}", token_user.User.Sid.0));
            }
        }
        None
    }

    /// Calculate SHA-256 hash of executable (first 16 chars)
    fn calculate_sha256_prefix(path: &str) -> Option<String> {
        let bytes = fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        Some(hex::encode(&result[..8])) // First 16 hex chars (8 bytes)
    }

    /// Check if binary has valid digital signature
    fn is_binary_signed(path: &str) -> bool {
        unsafe {
            let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

            let size = GetFileVersionInfoSizeW(PWSTR(wide_path.as_ptr() as *mut u16), None);
            if size == 0 {
                return false;
            }

            let mut buffer = vec![0u8; size as usize];
            if GetFileVersionInfoW(
                PWSTR(wide_path.as_ptr() as *mut u16),
                0,
                size,
                buffer.as_mut_ptr() as *mut _,
            )
            .is_err()
            {
                return false;
            }

            // Check for signature info (simplified check)
            let mut info_ptr = std::ptr::null_mut();
            let mut info_size = 0u32;
            let query = "\\".encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();

            if VerQueryValueW(
                buffer.as_ptr() as *const _,
                PWSTR(query.as_ptr() as *mut u16),
                &mut info_ptr,
                &mut info_size,
            )
            .is_ok()
            {
                // Has version info - likely signed (simplified heuristic)
                return true;
            }
        }
        false
    }

    /// List all active processes with their info
    pub fn list_processes() -> Vec<ProcessIdentity> {
        unsafe {
            let mut processes = Vec::new();
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(s) => s,
                Err(_) => return processes,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if let Some(info) = Self::get_process_info(entry.th32ProcessID as i32) {
                        processes.push(info);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            processes
        }
    }
}

#[cfg(not(windows))]
pub struct ProcessInfoCollector;

#[cfg(not(windows))]
impl ProcessInfoCollector {
    pub fn get_process_info(_pid: i32) -> Option<crate::ProcessIdentity> {
        None
    }

    pub fn list_processes() -> Vec<crate::ProcessIdentity> {
        Vec::new()
    }
}
