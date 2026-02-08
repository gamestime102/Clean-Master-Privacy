mod core;
mod ui;

use gtk4::glib;
use std::sync::{Arc, Mutex};

fn main() -> glib::ExitCode {
    // Initialize logging
    env_logger::init();
    log::info!("Starting Clean Master Privacy v5.0.0");

    // Initialize core engine with error handling
    let engine = match core::Engine::new() {
        Ok(engine) => Arc::new(Mutex::new(engine)),
        Err(e) => {
            eprintln!("Failed to initialize engine: {}", e);
            native_dialog::MessageDialog::new()
                .set_type(native_dialog::MessageType::Error)
                .set_title("Clean Master Privacy - Error")
                .set_text(&format!("Failed to initialize engine:\n{}", e))
                .show_alert()
                .unwrap();
            std::process::exit(1);
        }
    };

    // Initialize localization
    let localization = Arc::new(Mutex::new(core::Localization::new()));

    // Start background services
    start_background_services(engine.clone(), localization.clone());

    // Run the application
    ui::run(engine, localization)
}

fn start_background_services(
    engine: Arc<Mutex<core::Engine>>,
    _localization: Arc<Mutex<core::Localization>>,
) {
    log::info!("Starting background services");

    // Update threat database
    let engine_clone = engine.clone();
    std::thread::spawn(move || {
        log::info!("Updating threat database...");
        if let Ok(mut engine) = engine_clone.lock() {
            if let Err(e) = engine.update_threat_database() {
                log::error!("Failed to update threat database: {}", e);
            }
        }
    });

    // Start real-time protection
    let engine_clone = engine.clone();
    std::thread::spawn(move || {
        log::info!("Starting real-time protection...");
        if let Ok(engine) = engine_clone.lock() {
            if let Err(e) = engine.start_realtime_protection() {
                log::error!("Failed to start real-time protection: {}", e);
            }
        }
    });

    // System health monitoring
    let engine_clone = engine.clone();
    std::thread::spawn(move || {
        log::info!("Starting system health monitoring...");
        loop {
            if let Ok(mut engine) = engine_clone.lock() {
                if let Err(e) = engine.update_system_health() {
                    log::error!("Failed to update system health: {}", e);
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
}
