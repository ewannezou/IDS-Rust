use crate::alert::{Alert, AlertType, Risk};
use crate::config::CONFIG;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::{Duration, Instant};

pub struct Detector {
    pub ssh_attempts: HashMap<String, Vec<Instant>>,
    pub web_requests: HashMap<String, Vec<Instant>>,
    pub port_scans: HashMap<String, HashSet<u16>>,
    pub syn_connections: HashMap<String, Vec<Instant>>,
    pub last_positions: HashMap<String, u64>,
}

impl Detector {
    pub fn new() -> Self {
        Self {
            ssh_attempts: HashMap::new(),
            web_requests: HashMap::new(),
            port_scans: HashMap::new(),
            syn_connections: HashMap::new(),
            last_positions: HashMap::new(),
        }
    }

    pub fn monitor_logs(&mut self) {
        self.monitor_ssh_logs();
        self.monitor_web_logs();
    }

    pub fn monitor_ssh_logs(&mut self) {
        let file_path = CONFIG.file_ssh_log.to_string();

        if let Ok(mut file) = File::open(&file_path) {
            let offset =
                self.last_positions.get(&file_path).copied().unwrap_or(0);

            if offset == 0 {
                if let Ok(end) = file.seek(SeekFrom::End(0)) {
                    self.last_positions.insert(file_path, end);
                }
                return;
            }
            if file.seek(SeekFrom::Start(offset)).is_err() {
                return;
            }
            let mut reader = BufReader::new(file);
            let mut new_offset = offset;
            let mut line = String::new();
            while let Ok(bytes) = reader.read_line(&mut line) {
                if bytes == 0 {
                    break;
                }
                self.analyze_ssh_line(&line);
                new_offset += bytes as u64;
                line.clear();
            }
            self.last_positions.insert(file_path, new_offset);
        }
    }

    pub fn analyze_ssh_line(
        &mut self,
        line: &str,
    ) {
        // Détection des échecs d'authentification SSH
        let failed_auth_patterns = vec![
            r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
            r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)",
            r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
        ];

        for pattern in failed_auth_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(line) {
                    if let Some(ip) = caps.get(1) {
                        let ip = ip.as_str().to_string();
                        self.track_ssh_attempt(&ip);
                    }
                }
            }
        }

        // Détection des scans SSH
        if line.contains("Did not receive identification string")
            || line.contains("Bad protocol version identification")
        {
            if let Some(ip) = Self::extract_ip_from_line(line) {
                self.detect_port_scan(&ip, CONFIG.ssh_port);
            }
        }
    }

    pub fn track_ssh_attempt(
        &mut self,
        ip: &str,
    ) {
        let attempts = self
            .ssh_attempts
            .entry(ip.to_string())
            .or_insert_with(Vec::new);

        let now = Instant::now();
        let window = CONFIG.ssh_window;

        // Nettoyer les anciennes tentatives
        attempts.retain(|&time| now.duration_since(time) < window);
        attempts.push(now);

        if attempts.len() >= CONFIG.ssh_attempts {
            let alert = Alert::new(
                AlertType::SSHBruteForce,
                Risk::Critical,
                ip.to_string(),
                format!(
                    "Brute force SSH détecté: {} tentatives en {} secondes",
                    attempts.len(),
                    window.as_secs()
                ),
                attempts.len(),
            );

            alert.generate_alert();
            attempts.clear();
        }
    }

    pub fn monitor_web_logs(&mut self) {
        let file_path = CONFIG.file_web_log.to_string();
        if let Ok(mut file) = File::open(&file_path) {
            let offset =
                self.last_positions.get(&file_path).copied().unwrap_or(0);
            if offset == 0 {
                if let Ok(end) = file.seek(SeekFrom::End(0)) {
                    self.last_positions.insert(file_path, end);
                }
                return;
            }
            if file.seek(SeekFrom::Start(offset)).is_err() {
                return;
            }

            let mut reader = BufReader::new(file);
            let mut new_offset = offset;
            let mut line = String::new();
            while let Ok(bytes) = reader.read_line(&mut line) {
                if bytes == 0 {
                    break;
                }
                self.analyze_web_line(&line);
                new_offset += bytes as u64;
                line.clear();
            }
            self.last_positions.insert(file_path, new_offset);
        }
    }

    pub fn analyze_web_line(
        &mut self,
        line: &str,
    ) {
        // Extraire l'IP source
        if let Some(ip) = Self::extract_ip_from_line(line) {
            // Suivre les requêtes web
            self.track_web_request(&ip);

            // Détection d'énumération web
            self.detect_web_enumeration(&ip, line);
        }
    }

    pub fn track_web_request(
        &mut self,
        ip: &str,
    ) {
        let requests = self
            .web_requests
            .entry(ip.to_string())
            .or_insert_with(Vec::new);

        let now = Instant::now();
        let window = CONFIG.web_window;

        requests.retain(|&time| now.duration_since(time) < window);
        requests.push(now);
    }

    pub fn detect_web_enumeration(
        &self,
        ip: &str,
        line: &str,
    ) -> bool {
        let enumeration_patterns = vec![
            (r"/admin", "Accès admin"),
            (r"/wp-admin", "WordPress admin"),
            (r"\.git/", "Git directory"),
            (r"/backup", "Backup directory"),
            (r"/phpmyadmin", "phpMyAdmin"),
            (r"/server-status", "Apache status"),
            (r"/cgi-bin/", "CGI scripts"),
            (r"robots\.txt", "Robots file"),
            (r"union.*select", "SQL injection"),
            (r"<script>", "XSS attempt"),
            (r"\.\./", "Directory traversal"),
            (r"\.env", "Environment file"),
            (r"/wp-json", "WordPress API"),
            (r"xmlrpc\.php", "XML-RPC"),
        ];

        let line_lower = line.to_lowercase();
        for (pattern, description) in enumeration_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(&line_lower) {
                    let alert = Alert::new(
                        AlertType::WebEnum,
                        Risk::Medium,
                        ip.to_string(),
                        format!("Énumération web détectée: {}", description),
                        1,
                    );
                    alert.generate_alert();
                    return true;
                }
            }
        }
        return false;
    }

    pub fn analyze_packet(
        &mut self,
        source_ip: &str,
        dest_port: u16,
        protocol: &str,
        flags: u8,
    ) {
        // Détection de scan de ports
        self.detect_port_scan(source_ip, dest_port);

        // Détection SYN Flood
        if protocol == "TCP" && (flags & 0x02) != 0 {
            // SYN flag
            self.detect_syn_flood_ddos(source_ip);
        }
    }

    pub fn detect_port_scan(
        &mut self,
        source_ip: &str,
        dest_port: u16,
    ) {
        let ports = self
            .port_scans
            .entry(source_ip.to_string())
            .or_insert_with(HashSet::new);

        ports.insert(dest_port);

        if ports.len() >= CONFIG.port_scan_threshold {
            let alert = Alert::new(
                AlertType::PortScan,
                Risk::High,
                source_ip.to_string(),
                format!(
                    "Scan de ports détecté: {} ports différents",
                    ports.len()
                ),
                ports.len(),
            );
            alert.generate_alert();
            // Réinitialiser
            ports.clear();
        }
    }

    // Détecte les packets TCP initiés
    pub fn detect_syn_flood_ddos(
        &mut self,
        source_ip: &str,
    ) {
        let syns = self
            .syn_connections
            .entry(source_ip.to_string())
            .or_insert_with(Vec::new);

        let now = Instant::now();
        let window = Duration::from_secs(1);

        syns.retain(|&time| now.duration_since(time) < window);
        syns.push(now);

        if syns.len() > 500 {
            // Seuil SYN flood
            let alert = Alert::new(
                AlertType::DDOS,
                Risk::Critical,
                source_ip.to_string(),
                format!("SYN Flood DDOS détecté: {} SYN/seconde", syns.len()),
                syns.len(),
            );
            alert.generate_alert();
            syns.clear();
        }
    }

    pub fn extract_ip_from_line(line: &str) -> Option<String> {
        if let Ok(re) = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b") {
            re.find(line).map(|m| m.as_str().to_string())
        } else {
            None
        }
    }

    pub fn cleanup_old_entries(&mut self) {
        let now = Instant::now();

        // Nettoyer les tentatives SSH expirées
        for (_, attempts) in self.ssh_attempts.iter_mut() {
            attempts
                .retain(|&time| now.duration_since(time) < CONFIG.ssh_window);
        }

        // Nettoyer les requêtes web expirées
        for (_, requests) in self.web_requests.iter_mut() {
            requests
                .retain(|&time| now.duration_since(time) < CONFIG.web_window);
        }

        // Nettoyer les scans de ports après 5 minutes
        self.port_scans
            .retain(|_, ports: &mut HashSet<u16>| !ports.is_empty());
    }
}
