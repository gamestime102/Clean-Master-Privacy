use crate::core::{
    self, AnonymizeResult, AuditItem, CleanupResult, DriverInfo, Engine, FixResult,
    HardwareInfo, JunkFile, Localization, PrivacyIssue, QuarantineItem, ScanConfig,
    ScanEvent, Severity, SystemHealth, ThreatCategory,
};
use adw::prelude::*;
use adw::{
    self, AboutWindow, ActionRow, Application, Avatar, Carousel, CarouselIndicatorDots,
    ComboRow, EntryRow, ExpanderRow, MessageDialog, NavigationView, PasswordEntryRow,
    PreferencesGroup, PreferencesPage, SplitButton, StatusPage, TabBar, TabPage, TabView,
    Toast, ToastOverlay, ToolbarView, ViewStack, ViewSwitcherBar, ViewSwitcherTitle, Window,
    WindowTitle,
};
use chrono::{Datelike, Local, Timelike};
use crossbeam_channel::{self, unbounded, Receiver, Sender};
use gio;
use gtk4::gdk;
use gtk4::{
    glib, Adjustment, Align, ApplicationWindow, Box as GtkBox, Button, Calendar, CheckButton,
    ColorButton, Dialog, DrawingArea, Entry, FileChooserAction, FileChooserDialog, FileFilter,
    FlowBox, FontButton, Grid, HeaderBar, IconLookupFlags, IconTheme, Image, InfoBar, Label,
    LevelBar, ListBox, ListBoxRow, MenuButton, MessageType, Orientation, PolicyType,
    PopoverMenu, ProgressBar, ResponseType, Revealer, Scale, ScrolledWindow, SearchEntry,
    SelectionMode, Separator, Spinner, Switch, TextBuffer, TextView,
};
use native_dialog::{
    MessageDialog as NativeMessageDialog, MessageType as NativeMessageType,
};
use open;
use rand::Rng;
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

// ==================== UYGULAMA KONFİGÜRASYONU ====================

pub struct AppState {
    pub engine: Arc<Mutex<core::Engine>>,
    pub localization: Arc<Mutex<core::Localization>>,
    pub current_scan: Arc<Mutex<Option<Arc<core::AtomicBool>>>>,
    pub scan_progress: Arc<Mutex<ScanProgress>>,
    pub notifications: Arc<Mutex<Vec<Notification>>>,
    pub theme: Arc<Mutex<String>>,
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub current: usize,
    pub total: usize,
    pub threats: usize,
    pub status: String,
    pub active: bool,
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

impl Default for ScanProgress {
    fn default() -> Self {
        ScanProgress {
            current: 0,
            total: 0,
            threats: 0,
            status: String::new(),
            active: false,
        }
    }
}

pub fn run(engine: Arc<Mutex<core::Engine>>, localization: Arc<Mutex<core::Localization>>) -> glib::ExitCode {
    let app = Application::builder()
        .application_id("com.cleanmaster.privacy")
        .build();

    let state = AppState {
        engine,
        localization,
        current_scan: Arc::new(Mutex::new(None)),
        scan_progress: Arc::new(Mutex::new(ScanProgress::default())),
        notifications: Arc::new(Mutex::new(Vec::new())),
        theme: Arc::new(Mutex::new("dark".to_string())),
    };

    app.connect_activate(move |app| {
        build_ui(app, &state);
    });

    app.run()
}

fn build_ui(app: &Application, state: &AppState) {
    let window = Window::builder()
        .application(app)
        .title("Clean Master Privacy")
        .default_width(1200)
        .default_height(800)
        .build();

    let toast_overlay = ToastOverlay::new();

    let main_box = GtkBox::new(Orientation::Vertical, 0);

    // Header
    let header = HeaderBar::new();
    header.set_title_widget(Some(&WindowTitle::new("Clean Master Privacy", "")));

    let menu_button = MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .build();
    header.pack_end(&menu_button);

    // Main content
    let stack = ViewStack::new();

    // Dashboard page
    let dashboard_page = create_dashboard_page(state, &toast_overlay);
    stack.add_titled_with_icon(&dashboard_page, Some("dashboard"), "Dashboard", "dashboard-symbolic");

    // Scan page
    let scan_page = create_scan_page(state, &toast_overlay);
    stack.add_titled_with_icon(&scan_page, Some("scan"), "Scan", "system-search-symbolic");

    // Optimize page
    let optimize_page = create_optimize_page(state, &toast_overlay);
    stack.add_titled_with_icon(&optimize_page, Some("optimize"), "Optimize", "preferences-system-symbolic");

    // Privacy page
    let privacy_page = create_privacy_page(state, &toast_overlay);
    stack.add_titled_with_icon(&privacy_page, Some("privacy"), "Privacy", "security-high-symbolic");

    // System page
    let system_page = create_system_page(state, &toast_overlay);
    stack.add_titled_with_icon(&system_page, Some("system"), "System", "computer-symbolic");

    // View switcher
    let view_switcher = ViewSwitcherTitle::builder()
        .stack(&stack)
        .title("Clean Master Privacy")
        .build();
    header.set_title_widget(Some(&view_switcher));

    main_box.append(&header);
    main_box.append(&stack);

    toast_overlay.set_child(Some(&main_box));
    window.set_content(Some(&toast_overlay));

    window.present();
}

fn create_dashboard_page(state: &AppState, toast_overlay: &ToastOverlay) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 16);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    let status_page = StatusPage::builder()
        .title("Welcome to Clean Master Privacy")
        .description("Your ultimate security, optimization & privacy suite")
        .icon_name("security-high-symbolic")
        .build();

    page.append(&status_page);

    // Quick actions
    let actions_box = GtkBox::new(Orientation::Horizontal, 12);
    actions_box.set_halign(Align::Center);

    let quick_scan_btn = Button::builder()
        .label("Quick Scan")
        .icon_name("system-search-symbolic")
        .css_classes(["suggested-action", "pill"])
        .build();

    let optimize_btn = Button::builder()
        .label("Optimize System")
        .icon_name("preferences-system-symbolic")
        .css_classes(["pill"])
        .build();

    actions_box.append(&quick_scan_btn);
    actions_box.append(&optimize_btn);

    page.append(&actions_box);

    // System status cards
    let cards_box = GtkBox::new(Orientation::Horizontal, 12);
    cards_box.set_halign(Align::Center);
    cards_box.set_margin_top(24);

    // Protection status card
    let protection_card = create_status_card(
        "Protection",
        "Active",
        "security-high-symbolic",
        &["Real-time: On", "Database: Up to date"],
    );
    cards_box.append(&protection_card);

    // System health card
    let health_card = create_status_card(
        "System Health",
        "Good",
        "heart-symbolic",
        &["CPU: Normal", "Memory: Normal"],
    );
    cards_box.append(&health_card);

    // Privacy status card
    let privacy_card = create_status_card(
        "Privacy",
        "Secure",
        "user-not-tracked-symbolic",
        &["Issues: 0", "Last scan: Today"],
    );
    cards_box.append(&privacy_card);

    page.append(&cards_box);

    page
}

fn create_status_card(title: &str, status: &str, icon: &str, details: &[&str]) -> GtkBox {
    let card = GtkBox::new(Orientation::Vertical, 8);
    card.set_css_classes(&["card"]);
    card.set_size_request(200, 150);
    card.set_margin_start(8);
    card.set_margin_end(8);
    card.set_margin_top(8);
    card.set_margin_bottom(8);

    let icon_image = Image::from_icon_name(icon);
    icon_image.set_pixel_size(48);
    icon_image.set_margin_top(12);
    card.append(&icon_image);

    let title_label = Label::new(Some(title));
    title_label.set_css_classes(&["heading"]);
    card.append(&title_label);

    let status_label = Label::new(Some(status));
    status_label.set_css_classes(&["success"]);
    card.append(&status_label);

    for detail in details {
        let detail_label = Label::new(Some(*detail));
        detail_label.set_css_classes(&["caption"]);
        card.append(&detail_label);
    }

    card
}

fn create_scan_page(state: &AppState, toast_overlay: &ToastOverlay) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 16);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    // Scan type selection
    let scan_types_box = GtkBox::new(Orientation::Horizontal, 12);
    scan_types_box.set_halign(Align::Center);

    let quick_scan_btn = Button::builder()
        .label("Quick Scan")
        .icon_name("system-search-symbolic")
        .css_classes(["suggested-action"])
        .build();

    let full_scan_btn = Button::builder()
        .label("Full Scan")
        .icon_name("drive-harddisk-symbolic")
        .build();

    let custom_scan_btn = Button::builder()
        .label("Custom Scan")
        .icon_name("folder-open-symbolic")
        .build();

    scan_types_box.append(&quick_scan_btn);
    scan_types_box.append(&full_scan_btn);
    scan_types_box.append(&custom_scan_btn);

    page.append(&scan_types_box);

    // Progress section
    let progress_box = GtkBox::new(Orientation::Vertical, 8);
    progress_box.set_margin_top(24);

    let progress_label = Label::new(Some("Ready to scan"));
    progress_label.set_css_classes(&["heading"]);
    progress_box.append(&progress_label);

    let progress_bar = ProgressBar::new();
    progress_bar.set_show_text(true);
    progress_box.append(&progress_bar);

    let status_label = Label::new(Some(""));
    status_label.set_css_classes(&["caption"]);
    progress_box.append(&status_label);

    page.append(&progress_box);

    // Results section
    let results_frame = gtk4::Frame::new(Some("Scan Results"));
    let results_box = GtkBox::new(Orientation::Vertical, 8);
    results_box.set_margin_top(12);
    results_box.set_margin_bottom(12);
    results_box.set_margin_start(12);
    results_box.set_margin_end(12);

    let results_label = Label::new(Some("No threats found"));
    results_label.set_css_classes(&["success"]);
    results_box.append(&results_label);

    results_frame.set_child(Some(&results_box));
    page.append(&results_frame);

    // Action buttons
    let action_box = GtkBox::new(Orientation::Horizontal, 12);
    action_box.set_halign(Align::Center);
    action_box.set_margin_top(24);

    let cancel_btn = Button::builder()
        .label("Cancel")
        .sensitive(false)
        .build();

    let quarantine_btn = Button::builder()
        .label("Quarantine All")
        .sensitive(false)
        .build();

    action_box.append(&cancel_btn);
    action_box.append(&quarantine_btn);

    page.append(&action_box);

    // Quick scan button handler
    let state_clone = state.clone();
    let progress_bar_clone = progress_bar.clone();
    let progress_label_clone = progress_label.clone();
    let status_label_clone = status_label.clone();
    let results_label_clone = results_label.clone();
    let cancel_btn_clone = cancel_btn.clone();
    let toast_overlay_clone = toast_overlay.clone();

    quick_scan_btn.connect_clicked(move |_| {
        let state = &state_clone;
        
        // Update UI
        progress_label_clone.set_text("Scanning...");
        cancel_btn_clone.set_sensitive(true);
        
        // Create scan config
        let config = ScanConfig {
            target_paths: vec![PathBuf::from("/home")],
            scan_type: core::ScanType::Quick,
            heuristic_enabled: true,
            cloud_lookup_enabled: false,
            max_file_size: 100 * 1024 * 1024, // 100MB
            excluded_extensions: vec![".tmp".to_string(), ".log".to_string()],
            excluded_paths: vec![],
        };

        // Start scan in background
        let engine = state.engine.clone();
        let (tx, rx) = std::sync::mpsc::channel::<ScanEvent>();

        std::thread::spawn(move || {
            if let Ok(engine) = engine.lock() {
                let _ = engine.scan(config, Some(tx));
            }
        });

        // Handle scan events
        let progress_bar = progress_bar_clone.clone();
        let progress_label = progress_label_clone.clone();
        let status_label = status_label_clone.clone();
        let results_label = results_label_clone.clone();
        let cancel_btn = cancel_btn_clone.clone();
        let toast_overlay = toast_overlay_clone.clone();

        glib::idle_add_local(move || {
            match rx.try_recv() {
                Ok(event) => {
                    match event {
                        ScanEvent::Started => {
                            progress_label.set_text("Scan started...");
                        }
                        ScanEvent::Progress { current, total } => {
                            let fraction = if total > 0 {
                                current as f64 / total as f64
                            } else {
                                0.0
                            };
                            progress_bar.set_fraction(fraction);
                            status_label.set_text(&format!("{} / {} files", current, total));
                        }
                        ScanEvent::ThreatFound(threat) => {
                            let toast = Toast::new(&format!("Threat found: {}", threat.signature.name));
                            toast_overlay.add_toast(toast);
                        }
                        ScanEvent::Completed { threats_found, files_scanned } => {
                            progress_bar.set_fraction(1.0);
                            progress_label.set_text("Scan completed");
                            cancel_btn.set_sensitive(false);
                            
                            if threats_found > 0 {
                                results_label.set_text(&format!("{} threats found in {} files", threats_found, files_scanned));
                                results_label.set_css_classes(&["error"]);
                            } else {
                                results_label.set_text(&format!("No threats found in {} files", files_scanned));
                                results_label.set_css_classes(&["success"]);
                            }
                            
                            let toast = Toast::new("Scan completed");
                            toast_overlay.add_toast(toast);
                        }
                        ScanEvent::Error(msg) => {
                            progress_label.set_text(&format!("Error: {}", msg));
                            cancel_btn.set_sensitive(false);
                        }
                        ScanEvent::Cancelled => {
                            progress_label.set_text("Scan cancelled");
                            cancel_btn.set_sensitive(false);
                        }
                    }
                    glib::ControlFlow::Continue
                }
                Err(_) => glib::ControlFlow::Break,
            }
        });
    });

    // Cancel button handler
    let state_clone = state.clone();
    cancel_btn.connect_clicked(move |_| {
        if let Ok(engine) = state_clone.engine.lock() {
            engine.cancel_scan();
        }
    });

    page
}

fn create_optimize_page(state: &AppState, toast_overlay: &ToastOverlay) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 16);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    // Junk cleaner section
    let junk_group = PreferencesGroup::new();
    junk_group.set_title("Junk Cleaner");
    junk_group.set_description(Some("Clean temporary and unnecessary files"));

    let scan_junk_btn = Button::builder()
        .label("Scan for Junk Files")
        .halign(Align::Start)
        .margin_top(12)
        .build();

    junk_group.add(&scan_junk_btn);

    // Startup manager section
    let startup_group = PreferencesGroup::new();
    startup_group.set_title("Startup Manager");
    startup_group.set_description(Some("Manage startup applications"));
    startup_group.set_margin_top(24);

    let startup_list = ListBox::new();
    startup_list.set_selection_mode(SelectionMode::None);
    startup_list.set_css_classes(&["boxed-list"]);

    // Add sample startup items
    for i in 1..=3 {
        let row = ActionRow::new();
        row.set_title(&format!("Startup Item {}", i));
        row.set_subtitle("Enabled");
        
        let switch = Switch::new();
        switch.set_active(true);
        switch.set_valign(Align::Center);
        row.add_suffix(&switch);
        
        startup_list.append(&row);
    }

    startup_group.add(&startup_list);

    // RAM optimization section
    let ram_group = PreferencesGroup::new();
    ram_group.set_title("Memory Optimization");
    ram_group.set_description(Some("Free up RAM and optimize memory usage"));
    ram_group.set_margin_top(24);

    let ram_box = GtkBox::new(Orientation::Horizontal, 12);
    
    let ram_label = Label::new(Some("Memory Usage: 45%"));
    ram_box.append(&ram_label);

    let optimize_ram_btn = Button::builder()
        .label("Optimize RAM")
        .css_classes(["suggested-action"])
        .build();
    ram_box.append(&optimize_ram_btn);

    ram_group.add(&ram_box);

    page.append(&junk_group);
    page.append(&startup_group);
    page.append(&ram_group);

    // Junk scan handler
    let state_clone = state.clone();
    let toast_overlay_clone = toast_overlay.clone();
    scan_junk_btn.connect_clicked(move |_| {
        if let Ok(engine) = state_clone.engine.lock() {
            match engine.find_junk_files() {
                Ok(files) => {
                    let total_size: u64 = files.iter().map(|f| f.size).sum();
                    let toast = Toast::new(&format!(
                        "Found {} junk files ({:.2} MB)",
                        files.len(),
                        total_size as f64 / 1024.0 / 1024.0
                    ));
                    toast_overlay_clone.add_toast(toast);
                }
                Err(e) => {
                    let toast = Toast::new(&format!("Error: {}", e));
                    toast_overlay_clone.add_toast(toast);
                }
            }
        }
    });

    page
}

fn create_privacy_page(state: &AppState, toast_overlay: &ToastOverlay) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 16);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    // Privacy audit section
    let audit_group = PreferencesGroup::new();
    audit_group.set_title("Privacy Audit");
    audit_group.set_description(Some("Scan for privacy issues"));

    let audit_btn = Button::builder()
        .label("Run Privacy Audit")
        .halign(Align::Start)
        .margin_top(12)
        .css_classes(["suggested-action"])
        .build();

    audit_group.add(&audit_btn);

    // Privacy issues list
    let issues_group = PreferencesGroup::new();
    issues_group.set_title("Privacy Issues");
    issues_group.set_margin_top(24);

    let issues_list = ListBox::new();
    issues_list.set_selection_mode(SelectionMode::None);
    issues_list.set_css_classes(&["boxed-list"]);

    issues_group.add(&issues_list);

    // Anonymization section
    let anon_group = PreferencesGroup::new();
    anon_group.set_title("Anonymization");
    anon_group.set_description(Some("Tools for online privacy"));
    anon_group.set_margin_top(24);

    let anon_box = GtkBox::new(Orientation::Horizontal, 12);

    let tor_btn = Button::builder()
        .label("Enable Tor")
        .build();

    let vpn_btn = Button::builder()
        .label("Connect VPN")
        .build();

    anon_box.append(&tor_btn);
    anon_box.append(&vpn_btn);

    anon_group.add(&anon_box);

    page.append(&audit_group);
    page.append(&issues_group);
    page.append(&anon_group);

    // Audit handler
    let state_clone = state.clone();
    let toast_overlay_clone = toast_overlay.clone();
    let issues_list_clone = issues_list.clone();

    audit_btn.connect_clicked(move |_| {
        // Clear existing items
        while let Some(child) = issues_list_clone.first_child() {
            issues_list_clone.remove(&child);
        }

        if let Ok(engine) = state_clone.engine.lock() {
            match engine.audit_privacy() {
                Ok(issues) => {
                    for issue in issues {
                        let row = ActionRow::new();
                        row.set_title(&issue.title);
                        row.set_subtitle(&issue.description);

                        let fix_btn = Button::builder()
                            .icon_name("emblem-ok-symbolic")
                            .valign(Align::Center)
                            .build();

                        row.add_suffix(&fix_btn);
                        issues_list_clone.append(&row);
                    }

                    let toast = Toast::new(&format!("Found {} privacy issues", issues.len()));
                    toast_overlay_clone.add_toast(toast);
                }
                Err(e) => {
                    let toast = Toast::new(&format!("Error: {}", e));
                    toast_overlay_clone.add_toast(toast);
                }
            }
        }
    });

    page
}

fn create_system_page(state: &AppState, toast_overlay: &ToastOverlay) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 16);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    // Hardware info section
    let hardware_group = PreferencesGroup::new();
    hardware_group.set_title("Hardware Information");

    let cpu_row = ActionRow::new();
    cpu_row.set_title("CPU Usage");
    cpu_row.set_subtitle("Loading...");
    hardware_group.add(&cpu_row);

    let memory_row = ActionRow::new();
    memory_row.set_title("Memory Usage");
    memory_row.set_subtitle("Loading...");
    hardware_group.add(&memory_row);

    let disk_row = ActionRow::new();
    disk_row.set_title("Disk Usage");
    disk_row.set_subtitle("Loading...");
    hardware_group.add(&disk_row);

    let temp_row = ActionRow::new();
    temp_row.set_title("Temperature");
    temp_row.set_subtitle("Loading...");
    hardware_group.add(&temp_row);

    // Security audit section
    let security_group = PreferencesGroup::new();
    security_group.set_title("Security Audit");
    security_group.set_description(Some("Check system security settings"));
    security_group.set_margin_top(24);

    let security_btn = Button::builder()
        .label("Run Security Audit")
        .halign(Align::Start)
        .margin_top(12)
        .css_classes(["suggested-action"])
        .build();

    security_group.add(&security_btn);

    // Quarantine section
    let quarantine_group = PreferencesGroup::new();
    quarantine_group.set_title("Quarantine");
    quarantine_group.set_description(Some("Manage quarantined files"));
    quarantine_group.set_margin_top(24);

    let quarantine_list = ListBox::new();
    quarantine_list.set_selection_mode(SelectionMode::None);
    quarantine_list.set_css_classes(&["boxed-list"]);

    let empty_row = ActionRow::new();
    empty_row.set_title("No quarantined files");
    quarantine_list.append(&empty_row);

    quarantine_group.add(&quarantine_list);

    page.append(&hardware_group);
    page.append(&security_group);
    page.append(&quarantine_group);

    // Update hardware info periodically
    let state_clone = state.clone();
    let cpu_row_clone = cpu_row.clone();
    let memory_row_clone = memory_row.clone();
    let disk_row_clone = disk_row.clone();
    let temp_row_clone = temp_row.clone();

    glib::timeout_add_local(Duration::from_secs(2), move || {
        if let Ok(engine) = state_clone.engine.lock() {
            if let Ok(info) = engine.get_hardware_info() {
                cpu_row_clone.set_subtitle(&format!("{:.1}%", info.cpu_usage));
                memory_row_clone.set_subtitle(&format!("{:.1}%", info.memory_usage));
                disk_row_clone.set_subtitle(&format!("{:.1}%", info.disk_usage));
                temp_row_clone.set_subtitle(&format!("{:.1}°C", info.temperature));
            }
        }
        glib::ControlFlow::Continue
    });

    // Security audit handler
    let state_clone = state.clone();
    let toast_overlay_clone = toast_overlay.clone();
    security_btn.connect_clicked(move |_| {
        if let Ok(engine) = state_clone.engine.lock() {
            match engine.security_audit() {
                Ok(items) => {
                    let passed = items.iter().filter(|i| matches!(i.status, core::AuditStatus::Pass)).count();
                    let failed = items.iter().filter(|i| matches!(i.status, core::AuditStatus::Fail)).count();
                    
                    let toast = Toast::new(&format!(
                        "Security audit: {} passed, {} failed",
                        passed, failed
                    ));
                    toast_overlay_clone.add_toast(toast);
                }
                Err(e) => {
                    let toast = Toast::new(&format!("Error: {}", e));
                    toast_overlay_clone.add_toast(toast);
                }
            }
        }
    });

    page
}

// Clone implementation for AppState
impl Clone for AppState {
    fn clone(&self) -> Self {
        AppState {
            engine: self.engine.clone(),
            localization: self.localization.clone(),
            current_scan: self.current_scan.clone(),
            scan_progress: self.scan_progress.clone(),
            notifications: self.notifications.clone(),
            theme: self.theme.clone(),
        }
    }
}
