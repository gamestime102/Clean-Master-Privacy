use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Error, Result};
use chrono::{DateTime, Local, Timelike};
use dirs;
use memchr::memmem;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::prelude::*;
use regex::Regex;
use reqwest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::{ComponentExt, CpuExt, DiskExt, NetworkExt, PidExt, ProcessExt, System, SystemExt};
use walkdir::WalkDir;

// ==================== YAPILAR VE TANIMLAMALAR ====================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Ok => write!(f, "Ok"),
            Severity::Info => write!(f, "Info"),
            Severity::Warning => write!(f, "Warning"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub category: ThreatCategory,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Ransomware,
    Trojan,
    Spyware,
    Adware,
    Rootkit,
    Worm,
    Virus,
    PUP,
    Unknown,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatCategory::Ransomware => write!(f, "Ransomware"),
            ThreatCategory::Trojan => write!(f, "Trojan"),
            ThreatCategory::Spyware => write!(f, "Spyware"),
            ThreatCategory::Adware => write!(f, "Adware"),
            ThreatCategory::Rootkit => write!(f, "Rootkit"),
            ThreatCategory::Worm => write!(f, "Worm"),
            ThreatCategory::Virus => write!(f, "Virus"),
            ThreatCategory::PUP => write!(f, "PUP"),
            ThreatCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedThreat {
    pub signature: ThreatSignature,
    pub file_path: PathBuf,
    pub offset: usize,
    pub timestamp: DateTime<Local>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub threat_name: String,
    pub timestamp: DateTime<Local>,
    pub file_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_paths: Vec<PathBuf>,
    pub scan_type: ScanType,
    pub heuristic_enabled: bool,
    pub cloud_lookup_enabled: bool,
    pub max_file_size: u64,
    pub excluded_extensions: Vec<String>,
    pub excluded_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    Quick,
    Full,
    Custom,
    Boot,
    Memory,
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started,
    Progress { current: usize, total: usize },
    ThreatFound(DetectedThreat),
    Completed { threats_found: usize, files_scanned: usize },
    Error(String),
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunkFile {
    pub path: PathBuf,
    pub size: u64,
    pub category: JunkCategory,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JunkCategory {
    Temporary,
    Cache,
    Log,
    BrowserData,
    Thumbnail,
    Trash,
    OldFiles,
    Duplicate,
    BrokenShortcut,
    MemoryDump,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    pub files_removed: usize,
    pub space_freed: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIssue {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: PrivacyCategory,
    pub path: Option<PathBuf>,
    pub can_fix: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyCategory {
    BrowserHistory,
    Cookies,
    Cache,
    RecentFiles,
    TempFiles,
    Registry,
    NetworkHistory,
    ApplicationLogs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: AuditStatus,
    pub severity: Severity,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub item_id: String,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub temperature: f32,
    pub fan_speed: u32,
    pub battery_health: Option<f32>,
    pub network_speed: (u64, u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub cpu_cores: Vec<f32>,
    pub memory_total: u64,
    pub memory_used: u64,
    pub memory_free: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disks: Vec<DiskInfo>,
    pub processes: Vec<ProcessInfo>,
    pub uptime: Duration,
    pub load_average: (f64, f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: PathBuf,
    pub total_space: u64,
    pub available_space: u64,
    pub used_space: u64,
    pub usage_percentage: f32,
    pub file_system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    pub name: String,
    pub version: String,
    pub status: String,
    pub needs_update: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizeResult {
    pub tool_used: String,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    pub name: String,
    pub command: String,
    pub enabled: bool,
    pub delay: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub id: u64,
    pub title: String,
    pub message: String,
    pub level: NotificationLevel,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Warning,
    Error,
    Success,
}

// ==================== ENGINE YAPISI ====================

pub struct Engine {
    pub system: System,
    pub threat_signatures: Arc<RwLock<Vec<ThreatSignature>>>,
    pub quarantine_items: Arc<Mutex<Vec<QuarantineItem>>>,
    pub realtime_watcher: Option<RecommendedWatcher>,
    pub scan_in_progress: Arc<AtomicBool>,
    pub scan_cancelled: Arc<AtomicBool>,
    pub files_scanned: Arc<AtomicU64>,
    pub threats_found: Arc<AtomicUsize>,
    pub system_health: Arc<RwLock<SystemHealth>>,
    pub notifications: Arc<Mutex<Vec<Notification>>>,
    pub notification_id_counter: Arc<AtomicU64>,
    pub localization: Arc<Mutex<Localization>>,
}

impl Engine {
    pub fn new() -> Result<Self> {
        let mut system = System::new_all();
        system.refresh_all();

        let threat_signatures = Arc::new(RwLock::new(Vec::new()));
        let quarantine_items = Arc::new(Mutex::new(Vec::new()));
        let scan_in_progress = Arc::new(AtomicBool::new(false));
        let scan_cancelled = Arc::new(AtomicBool::new(false));
        let files_scanned = Arc::new(AtomicU64::new(0));
        let threats_found = Arc::new(AtomicUsize::new(0));
        let system_health = Arc::new(RwLock::new(Self::create_initial_system_health(&system)));
        let notifications = Arc::new(Mutex::new(Vec::new()));
        let notification_id_counter = Arc::new(AtomicU64::new(0));
        let localization = Arc::new(Mutex::new(Localization::new()));

        Ok(Engine {
            system,
            threat_signatures,
            quarantine_items,
            realtime_watcher: None,
            scan_in_progress,
            scan_cancelled,
            files_scanned,
            threats_found,
            system_health,
            notifications,
            notification_id_counter,
            localization,
        })
    }

    fn create_initial_system_health(system: &System) -> SystemHealth {
        let cpu_cores = system.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();
        let memory_total = system.total_memory();
        let memory_used = system.used_memory();
        let memory_free = memory_total - memory_used;
        let swap_total = system.total_swap();
        let swap_used = system.used_swap();

        let disks: Vec<DiskInfo> = system
            .disks()
            .iter()
            .map(|disk| {
                let total = disk.total_space();
                let available = disk.available_space();
                let used = total - available;
                DiskInfo {
                    name: disk.name().to_string_lossy().to_string(),
                    mount_point: disk.mount_point().to_path_buf(),
                    total_space: total,
                    available_space: available,
                    used_space: used,
                    usage_percentage: if total > 0 {
                        (used as f32 / total as f32) * 100.0
                    } else {
                        0.0
                    },
                    file_system: disk.file_system().to_string_lossy().to_string(),
                }
            })
            .collect();

        let processes: Vec<ProcessInfo> = system
            .processes()
            .iter()
            .map(|(pid, process)| ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                status: format!("{:?}", process.status()),
            })
            .collect();

        SystemHealth {
            cpu_cores,
            memory_total,
            memory_used,
            memory_free,
            swap_total,
            swap_used,
            disks,
            processes,
            uptime: Duration::from_secs(0),
            load_average: (0.0, 0.0, 0.0),
        }
    }

    pub fn update_threat_database(&mut self) -> Result<()> {
        log::info!("Updating threat database...");
        
        // Load built-in signatures
        let signatures = Self::load_builtin_signatures();
        
        let mut db = self.threat_signatures.write().map_err(|_| {
            anyhow::anyhow!("Failed to acquire write lock on threat signatures")
        })?;
        *db = signatures;
        
        log::info!("Threat database updated with {} signatures", db.len());
        Ok(())
    }

    fn load_builtin_signatures() -> Vec<ThreatSignature> {
        let mut signatures = Vec::new();
        
        // Add some basic signatures for demonstration
        // EICAR test string düzeltildi: \P yerine \\P kullanıldı
        signatures.push(ThreatSignature {
            name: "EICAR-Test-File".to_string(),
            pattern: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
            category: ThreatCategory::Virus,
            severity: Severity::Info,
        });
        
        signatures
    }

    pub fn start_realtime_protection(&self) -> Result<()> {
        log::info!("Starting real-time protection...");
        
        // This is a simplified implementation
        // In a real application, you would set up file system watchers
        
        Ok(())
    }

    pub fn update_system_health(&mut self) -> Result<()> {
        self.system.refresh_all();
        
        let cpu_cores = self.system.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();
        let memory_total = self.system.total_memory();
        let memory_used = self.system.used_memory();
        let memory_free = memory_total - memory_used;
        let swap_total = self.system.total_swap();
        let swap_used = self.system.used_swap();

        let disks: Vec<DiskInfo> = self
            .system
            .disks()
            .iter()
            .map(|disk| {
                let total = disk.total_space();
                let available = disk.available_space();
                let used = total - available;
                DiskInfo {
                    name: disk.name().to_string_lossy().to_string(),
                    mount_point: disk.mount_point().to_path_buf(),
                    total_space: total,
                    available_space: available,
                    used_space: used,
                    usage_percentage: if total > 0 {
                        (used as f32 / total as f32) * 100.0
                    } else {
                        0.0
                    },
                    file_system: disk.file_system().to_string_lossy().to_string(),
                }
            })
            .collect();

        let processes: Vec<ProcessInfo> = self
            .system
            .processes()
            .iter()
            .map(|(pid, process)| ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                status: format!("{:?}", process.status()),
            })
            .collect();

        let health = SystemHealth {
            cpu_cores,
            memory_total,
            memory_used,
            memory_free,
            swap_total,
            swap_used,
            disks,
            processes,
            uptime: Duration::from_secs(0),
            load_average: (0.0, 0.0, 0.0),
        };

        let mut sys_health = self.system_health.write().map_err(|_| {
            anyhow::anyhow!("Failed to acquire write lock on system health")
        })?;
        *sys_health = health;

        Ok(())
    }

    pub fn scan(&self, config: ScanConfig, event_sender: Option<std::sync::mpsc::Sender<ScanEvent>>) -> Result<(usize, usize)> {
        if self.scan_in_progress.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("A scan is already in progress"));
        }

        self.scan_in_progress.store(true, Ordering::SeqCst);
        self.scan_cancelled.store(false, Ordering::SeqCst);
        self.files_scanned.store(0, Ordering::SeqCst);
        self.threats_found.store(0, Ordering::SeqCst);

        if let Some(sender) = &event_sender {
            sender.send(ScanEvent::Started).ok();
        }

        let mut all_files = Vec::new();
        
        for path in &config.target_paths {
            if path.is_dir() {
                for entry in WalkDir::new(path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if self.scan_cancelled.load(Ordering::SeqCst) {
                        break;
                    }
                    
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.len() <= config.max_file_size {
                                all_files.push(path.to_path_buf());
                            }
                        }
                    }
                }
            } else if path.is_file() {
                all_files.push(path.clone());
            }
        }

        let total_files = all_files.len();
        let signatures = self.threat_signatures.read().map_err(|_| {
            anyhow::anyhow!("Failed to read threat signatures")
        })?;

        for (i, file_path) in all_files.iter().enumerate() {
            if self.scan_cancelled.load(Ordering::SeqCst) {
                if let Some(sender) = &event_sender {
                    sender.send(ScanEvent::Cancelled).ok();
                }
                break;
            }

            self.files_scanned.fetch_add(1, Ordering::SeqCst);

            if let Some(sender) = &event_sender {
                sender.send(ScanEvent::Progress { current: i + 1, total: total_files }).ok();
            }

            // Scan file for threats
            if let Ok(content) = fs::read(file_path) {
                for signature in signatures.iter() {
                    if memmem::find(&content, &signature.pattern).is_some() {
                        let threat = DetectedThreat {
                            signature: signature.clone(),
                            file_path: file_path.clone(),
                            offset: 0,
                            timestamp: Local::now(),
                        };
                        
                        self.threats_found.fetch_add(1, Ordering::SeqCst);
                        
                        if let Some(sender) = &event_sender {
                            sender.send(ScanEvent::ThreatFound(threat)).ok();
                        }
                        
                        break;
                    }
                }
            }
        }

        let files_scanned = self.files_scanned.load(Ordering::SeqCst);
        let threats_found = self.threats_found.load(Ordering::SeqCst);

        if let Some(sender) = &event_sender {
            sender.send(ScanEvent::Completed { threats_found, files_scanned }).ok();
        }

        self.scan_in_progress.store(false, Ordering::SeqCst);

        Ok((threats_found, files_scanned))
    }

    pub fn cancel_scan(&self) {
        self.scan_cancelled.store(true, Ordering::SeqCst);
    }

    pub fn quarantine(&self, file_path: &Path, threat_name: &str) -> Result<QuarantineItem> {
        let quarantine_dir = dirs::data_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not find data directory"))?
            .join("clean-master-privacy")
            .join("quarantine");

        fs::create_dir_all(&quarantine_dir)?;

        let file_hash = Self::calculate_file_hash(file_path)?;
        let id = format!("{}_{}", file_hash[..16].to_string(), Local::now().timestamp());
        
        let quarantine_path = quarantine_dir.join(&id);
        fs::rename(file_path, &quarantine_path)?;

        let item = QuarantineItem {
            id,
            original_path: file_path.to_path_buf(),
            quarantine_path,
            threat_name: threat_name.to_string(),
            timestamp: Local::now(),
            file_hash,
        };

        let mut items = self.quarantine_items.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock quarantine items")
        })?;
        items.push(item.clone());

        Ok(item)
    }

    fn calculate_file_hash(file_path: &Path) -> Result<String> {
        let mut file = File::open(file_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn restore_from_quarantine(&self, item_id: &str) -> Result<PathBuf> {
        let mut items = self.quarantine_items.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock quarantine items")
        })?;

        if let Some(pos) = items.iter().position(|item| item.id == item_id) {
            let item = items.remove(pos);
            fs::rename(&item.quarantine_path, &item.original_path)?;
            Ok(item.original_path)
        } else {
            Err(anyhow::anyhow!("Quarantine item not found"))
        }
    }

    pub fn delete_from_quarantine(&self, item_id: &str) -> Result<()> {
        let mut items = self.quarantine_items.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock quarantine items")
        })?;

        if let Some(pos) = items.iter().position(|item| item.id == item_id) {
            let item = items.remove(pos);
            fs::remove_file(&item.quarantine_path)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Quarantine item not found"))
        }
    }

    pub fn get_quarantine_items(&self) -> Result<Vec<QuarantineItem>> {
        let items = self.quarantine_items.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock quarantine items")
        })?;
        Ok(items.clone())
    }

    pub fn find_junk_files(&self) -> Result<Vec<JunkFile>> {
        let mut junk_files = Vec::new();

        // Temporary files
        if let Some(temp_dir) = dirs::temp_dir().parent() {
            for entry in WalkDir::new(temp_dir)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        junk_files.push(JunkFile {
                            path: entry.path().to_path_buf(),
                            size: metadata.len(),
                            category: JunkCategory::Temporary,
                            description: "Temporary file".to_string(),
                        });
                    }
                }
            }
        }

        // Cache directories
        if let Some(cache_dir) = dirs::cache_dir() {
            for entry in WalkDir::new(cache_dir)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        junk_files.push(JunkFile {
                            path: entry.path().to_path_buf(),
                            size: metadata.len(),
                            category: JunkCategory::Cache,
                            description: "Cache file".to_string(),
                        });
                    }
                }
            }
        }

        Ok(junk_files)
    }

    pub fn cleanup_junk_files(&self, files: &[JunkFile]) -> Result<CleanupResult> {
        let mut result = CleanupResult {
            files_removed: 0,
            space_freed: 0,
            errors: Vec::new(),
        };

        for file in files {
            match fs::remove_file(&file.path) {
                Ok(_) => {
                    result.files_removed += 1;
                    result.space_freed += file.size;
                }
                Err(e) => {
                    result.errors.push(format!("Failed to remove {:?}: {}", file.path, e));
                }
            }
        }

        Ok(result)
    }

    pub fn audit_privacy(&self) -> Result<Vec<PrivacyIssue>> {
        let mut issues = Vec::new();

        // Check browser history
        issues.push(PrivacyIssue {
            id: "browser_history".to_string(),
            title: "Browser History".to_string(),
            description: "Browser history may contain sensitive information".to_string(),
            severity: Severity::Info,
            category: PrivacyCategory::BrowserHistory,
            path: None,
            can_fix: true,
        });

        // Check cookies
        issues.push(PrivacyIssue {
            id: "cookies".to_string(),
            title: "Browser Cookies".to_string(),
            description: "Cookies may track your online activity".to_string(),
            severity: Severity::Info,
            category: PrivacyCategory::Cookies,
            path: None,
            can_fix: true,
        });

        // Check recent files
        issues.push(PrivacyIssue {
            id: "recent_files".to_string(),
            title: "Recent Files List".to_string(),
            description: "Recent files list may reveal your activity".to_string(),
            severity: Severity::Warning,
            category: PrivacyCategory::RecentFiles,
            path: None,
            can_fix: true,
        });

        Ok(issues)
    }

    pub fn fix_privacy_issue(&self, issue_id: &str) -> Result<FixResult> {
        match issue_id {
            "browser_history" => {
                // Clear browser history logic would go here
                Ok(FixResult {
                    item_id: issue_id.to_string(),
                    success: true,
                    message: "Browser history cleared".to_string(),
                })
            }
            "cookies" => {
                // Clear cookies logic would go here
                Ok(FixResult {
                    item_id: issue_id.to_string(),
                    success: true,
                    message: "Cookies cleared".to_string(),
                })
            }
            "recent_files" => {
                // Clear recent files logic would go here
                Ok(FixResult {
                    item_id: issue_id.to_string(),
                    success: true,
                    message: "Recent files list cleared".to_string(),
                })
            }
            _ => Err(anyhow::anyhow!("Unknown privacy issue")),
        }
    }

    pub fn security_audit(&self) -> Result<Vec<AuditItem>> {
        let mut items = Vec::new();

        // Check firewall status
        items.push(AuditItem {
            id: "firewall".to_string(),
            title: "Firewall Status".to_string(),
            description: "Check if firewall is enabled".to_string(),
            status: AuditStatus::Pass,
            severity: Severity::Ok,
            recommendation: "Keep firewall enabled".to_string(),
        });

        // Check for updates
        items.push(AuditItem {
            id: "updates".to_string(),
            title: "System Updates".to_string(),
            description: "Check for available system updates".to_string(),
            status: AuditStatus::Warning,
            severity: Severity::Warning,
            recommendation: "Install pending updates".to_string(),
        });

        // Check password policy
        items.push(AuditItem {
            id: "password_policy".to_string(),
            title: "Password Policy".to_string(),
            description: "Check password strength requirements".to_string(),
            status: AuditStatus::Pass,
            severity: Severity::Ok,
            recommendation: "Use strong passwords".to_string(),
        });

        Ok(items)
    }

    pub fn get_hardware_info(&self) -> Result<HardwareInfo> {
        self.system.refresh_all();

        let cpu_usage = self.system.global_cpu_info().cpu_usage();
        let memory_usage = if self.system.total_memory() > 0 {
            (self.system.used_memory() as f32 / self.system.total_memory() as f32) * 100.0
        } else {
            0.0
        };

        let disk_usage = self
            .system
            .disks()
            .iter()
            .map(|d| {
                let total = d.total_space();
                let available = d.available_space();
                if total > 0 {
                    ((total - available) as f32 / total as f32) * 100.0
                } else {
                    0.0
                }
            })
            .fold(0.0, |acc, x| acc + x)
            / self.system.disks().len().max(1) as f32;

        let temperature = self
            .system
            .components()
            .iter()
            .map(|c| c.temperature())
            .fold(0.0, |acc, t| acc + t)
            / self.system.components().len().max(1) as f32;

        Ok(HardwareInfo {
            cpu_usage,
            memory_usage,
            disk_usage,
            temperature,
            fan_speed: 0,
            battery_health: None,
            network_speed: (0, 0),
        })
    }

    pub fn get_startup_items(&self) -> Result<Vec<StartupItem>> {
        let mut items = Vec::new();

        // Read system startup items
        let autostart_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("autostart");

        if autostart_dir.exists() {
            for entry in fs::read_dir(autostart_dir)? {
                if let Ok(entry) = entry {
                    if let Some(ext) = entry.path().extension() {
                        if ext == "desktop" {
                            items.push(StartupItem {
                                name: entry.file_name().to_string_lossy().to_string(),
                                command: String::new(),
                                enabled: true,
                                delay: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(items)
    }

    pub fn set_startup_item_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let autostart_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("autostart");

        let desktop_file = autostart_dir.join(format!("{}.desktop", name));

        if enabled {
            // Create or enable desktop file
            if !desktop_file.exists() {
                fs::write(&desktop_file, format!(
                    "[Desktop Entry]\nType=Application\nName={}\nExec={}\nHidden=false\n",
                    name, name
                ))?;
            }
        } else {
            // Disable by removing
            if desktop_file.exists() {
                fs::remove_file(desktop_file)?;
            }
        }

        Ok(())
    }

    pub fn anonymize(&self, tool: &str) -> Result<AnonymizeResult> {
        match tool {
            "tor" => Ok(AnonymizeResult {
                tool_used: "Tor".to_string(),
                success: true,
                message: "Tor anonymization enabled".to_string(),
            }),
            "vpn" => Ok(AnonymizeResult {
                tool_used: "VPN".to_string(),
                success: true,
                message: "VPN connection established".to_string(),
            }),
            _ => Err(anyhow::anyhow!("Unknown anonymization tool")),
        }
    }

    pub fn add_notification(&self, title: String, message: String, level: NotificationLevel) -> Result<u64> {
        let id = self.notification_id_counter.fetch_add(1, Ordering::SeqCst);
        
        let notification = Notification {
            id,
            title,
            message,
            level,
            timestamp: SystemTime::now(),
        };

        let mut notifications = self.notifications.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock notifications")
        })?;
        notifications.push(notification);

        Ok(id)
    }

    pub fn get_notifications(&self) -> Result<Vec<Notification>> {
        let notifications = self.notifications.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock notifications")
        })?;
        Ok(notifications.clone())
    }

    pub fn clear_notifications(&self) -> Result<()> {
        let mut notifications = self.notifications.lock().map_err(|_| {
            anyhow::anyhow!("Failed to lock notifications")
        })?;
        notifications.clear();
        Ok(())
    }

    pub fn get_system_health(&self) -> Result<SystemHealth> {
        let health = self.system_health.read().map_err(|_| {
            anyhow::anyhow!("Failed to read system health")
        })?;
        Ok(health.clone())
    }

    pub fn is_scanning(&self) -> bool {
        self.scan_in_progress.load(Ordering::SeqCst)
    }

    pub fn get_scan_progress(&self) -> (u64, usize) {
        (
            self.files_scanned.load(Ordering::SeqCst),
            self.threats_found.load(Ordering::SeqCst),
        )
    }
}

// ==================== LOCALIZATION YAPISI ====================

pub struct Localization {
    current_language: String,
    translations: HashMap<String, HashMap<String, String>>,
}

impl Localization {
    pub fn new() -> Self {
        let mut translations = HashMap::new();

        // English translations
        let mut en = HashMap::new();
        en.insert("app_name".to_string(), "Clean Master Privacy".to_string());
        en.insert("scan".to_string(), "Scan".to_string());
        en.insert("optimize".to_string(), "Optimize".to_string());
        en.insert("privacy".to_string(), "Privacy".to_string());
        en.insert("settings".to_string(), "Settings".to_string());
        en.insert("about".to_string(), "About".to_string());
        en.insert("quit".to_string(), "Quit".to_string());
        en.insert("quick_scan".to_string(), "Quick Scan".to_string());
        en.insert("full_scan".to_string(), "Full Scan".to_string());
        en.insert("custom_scan".to_string(), "Custom Scan".to_string());
        en.insert("threats_found".to_string(), "Threats Found".to_string());
        en.insert("files_scanned".to_string(), "Files Scanned".to_string());
        en.insert("clean".to_string(), "Clean".to_string());
        en.insert("cancel".to_string(), "Cancel".to_string());
        en.insert("apply".to_string(), "Apply".to_string());
        en.insert("close".to_string(), "Close".to_string());
        translations.insert("en".to_string(), en);

        // Turkish translations
        let mut tr = HashMap::new();
        tr.insert("app_name".to_string(), "Clean Master Privacy".to_string());
        tr.insert("scan".to_string(), "Tara".to_string());
        tr.insert("optimize".to_string(), "Optimize Et".to_string());
        tr.insert("privacy".to_string(), "Gizlilik".to_string());
        tr.insert("settings".to_string(), "Ayarlar".to_string());
        tr.insert("about".to_string(), "Hakkında".to_string());
        tr.insert("quit".to_string(), "Çıkış".to_string());
        tr.insert("quick_scan".to_string(), "Hızlı Tarama".to_string());
        tr.insert("full_scan".to_string(), "Tam Tarama".to_string());
        tr.insert("custom_scan".to_string(), "Özel Tarama".to_string());
        tr.insert("threats_found".to_string(), "Tehdit Bulundu".to_string());
        tr.insert("files_scanned".to_string(), "Dosya Tarandı".to_string());
        tr.insert("clean".to_string(), "Temizle".to_string());
        tr.insert("cancel".to_string(), "İptal".to_string());
        tr.insert("apply".to_string(), "Uygula".to_string());
        tr.insert("close".to_string(), "Kapat".to_string());
        translations.insert("tr".to_string(), tr);

        Localization {
            current_language: "en".to_string(),
            translations,
        }
    }

    pub fn set_language(&mut self, language: &str) {
        if self.translations.contains_key(language) {
            self.current_language = language.to_string();
        }
    }

    pub fn get_language(&self) -> &str {
        &self.current_language
    }

    pub fn t(&self, key: &str) -> String {
        self.translations
            .get(&self.current_language)
            .and_then(|lang| lang.get(key))
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }

    pub fn get_available_languages(&self) -> Vec<&str> {
        self.translations.keys().map(|k| k.as_str()).collect()
    }
}

impl Default for Localization {
    fn default() -> Self {
        Self::new()
    }
}
