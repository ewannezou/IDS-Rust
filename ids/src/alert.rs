use chrono::{DateTime, Local};
use std::fmt::{self, Debug};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;
use syslog::{Facility, Formatter3164};

pub struct Alert {
    pub timestamp: SystemTime,
    pub alert_type: AlertType,
    pub risk: Risk,
    pub source_ip: String,
    pub message: String,
    pub count: usize,
}

#[derive(Debug)]
pub enum AlertType {
    SSHBruteForce,
    DDOS,
    PortScan,
    WebEnum,
}

#[derive(Debug)]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Alert {
    pub fn new(
        alert_type: AlertType,
        risk: Risk,
        source_ip: String,
        message: String,
        count: usize,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            alert_type,
            risk,
            source_ip,
            message,
            count,
        }
    }
    pub fn generate_alert(&self) {
        // Formatage du timestamp
        let datetime: DateTime<Local> = self.timestamp.into();
        let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();

        let alert_str = format!(
            "[{}] - [{:?}] - Attempts: {} - Risk: {:?} - Source IP: {} - Message: {}\n",
            timestamp_str,
            self.alert_type,
            self.count,
            self.risk,
            self.source_ip,
            self.message
        );

        println!("{}", alert_str);

        // Écrire dans le fichier d'alertes
        let log_dir = Path::new("/opt/log/ids");

        if !log_dir.exists() {
            if let Err(e) = fs::create_dir_all(log_dir) {
                eprintln!("Impossible de créer /opt/log/ids: {}", e);
            }
        }
        if let Ok(mut file) = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&crate::config::CONFIG.file_alert)
        {
            if let Err(e) = writeln!(file, "{}", alert_str) {
                eprintln!(
                    "Erreur d'écriture dans le fichier d'alertes: {}",
                    e
                );
            }
        } else {
            eprintln!("Impossible d'ouvrir le fichier d'alertes");
        }

        self.log_to_syslog();
    }

    fn log_to_syslog(&self) {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "rust-ids".into(),
            pid: std::process::id(),
        };

        match syslog::unix(formatter) {
            Ok(mut writer) => {
                let syslog_msg = match self.risk {
                    Risk::Critical => format!("CRITICAL: {}", self.message),
                    Risk::High => format!("HIGH: {}", self.message),
                    Risk::Medium => format!("MEDIUM: {}", self.message),
                    Risk::Low => format!("LOW: {}", self.message),
                };

                if let Err(e) = writer.warning(&syslog_msg) {
                    eprintln!("Erreur d'écriture syslog: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Erreur de connexion syslog: {}", e);
            }
        }
    }
}

// Implémentation de Display pour Alert pour un meilleur affichage
impl fmt::Display for Alert {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let datetime: DateTime<Local> = self.timestamp.into();
        let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();

        write!(
            f,
            "[{}] {:?} - {} (Risk: {:?}, IP: {}, Count: {})",
            timestamp_str,
            self.alert_type,
            self.message,
            self.risk,
            self.source_ip,
            self.count
        )
    }
}
