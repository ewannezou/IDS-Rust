pub mod alert;
pub mod config;
pub mod detector;
pub use alert::{Alert, AlertType, Risk};
pub use detector::Detector;

#[cfg(test)]
mod tests {
    use crate::alert::{Alert, AlertType, Risk};
    use crate::detector::Detector;
    use std::time::{Duration, Instant};

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(
            AlertType::SSHBruteForce,
            Risk::Critical,
            "192.168.1.100".to_string(),
            "Test alert".to_string(),
            5,
        );

        assert_eq!(alert.source_ip, "192.168.1.100");
        assert_eq!(alert.message, "Test alert");
        assert_eq!(alert.count, 5);

        // Vérifier que le timestamp est récent (moins d'1 seconde)
        let now = std::time::SystemTime::now();
        let elapsed = now.duration_since(alert.timestamp).unwrap();
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn test_ssh_brute_force_detection() {
        let mut detector = Detector::new();
        let test_ip = "192.168.1.100";

        // Simuler plusieurs tentatives SSH rapides
        for _i in 0..10 {
            detector.track_ssh_attempt(test_ip);
            // Si c'est la 5ème tentative, une alerte devrait être générée
        }

        // Vérifier que les tentatives sont suivies
        assert!(detector.ssh_attempts.contains_key(test_ip));
        let attempts = detector.ssh_attempts.get(test_ip).unwrap();
        assert!(attempts.len() <= 5); // Doit être nettoyé après seuil
    }

    #[test]
    fn test_port_scan_detection() {
        let mut detector = Detector::new();
        let test_ip = "10.0.0.50";

        // Simuler un scan de ports
        let ports_to_scan =
            vec![22, 80, 443, 8080, 3389, 21, 23, 25, 53, 110];

        for port in ports_to_scan.iter().take(10) {
            detector.detect_port_scan(test_ip, *port);
        }

        // Vérifier que les ports sont suivis
        assert!(detector.port_scans.contains_key(test_ip));
        let ports = detector.port_scans.get(test_ip).unwrap();
        assert_eq!(ports.len(), 10);
    }

    #[test]
    fn test_syn_flood_detection() {
        let mut detector = Detector::new();
        let test_ip = "192.168.1.200";

        // Simuler un SYN flood DDOS
        for _ in 0..600 {
            detector.detect_syn_flood_ddos(test_ip);
        }

        // Vérifier que les SYN sont suivis
        assert!(detector.syn_connections.contains_key(test_ip));
        let syns = detector.syn_connections.get(test_ip).unwrap();
        assert!(syns.len() <= 500);
    }

    #[test]
    fn test_web_enumeration_detection() {
        let detector = Detector::new();
        let test_ip = "10.0.0.100";

        // Test différentes patterns d'énumération web
        let test_cases = vec![
            ("GET /admin/login.php HTTP/1.1", true),
            ("GET /index.html HTTP/1.1", false),
            ("GET /wp-admin/ HTTP/1.1", true),
            ("GET /.git/config HTTP/1.1", true),
            ("GET /backup.zip HTTP/1.1", true),
            ("POST /login.php HTTP/1.1", false),
            ("GET /phpmyadmin/index.php HTTP/1.1", true),
            ("GET /server-status HTTP/1.1", true),
            ("GET /cgi-bin/test.cgi HTTP/1.1", true),
            ("GET /robots.txt HTTP/1.1", true),
        ];

        for (line, should_detect) in test_cases {
            // detect_web_enumeration génère une alerte directement
            detector.detect_web_enumeration(test_ip, line);
        }
    }
    #[test]
    fn test_ip_extraction() {
        use crate::detector::Detector;

        // Test d'extraction d'IP depuis des lignes de log
        let test_cases = vec![
            (
                "Failed password for root from 192.168.1.100",
                Some("192.168.1.100"),
            ),
            ("Invalid user admin from 10.0.0.50", Some("10.0.0.50")),
            ("Connection from 172.16.0.1 port 22", Some("172.16.0.1")),
            ("No IP in this line", None),
            (
                "Multiple IPs 192.168.1.1 and 192.168.1.2",
                Some("192.168.1.1"),
            ),
            ("IPv6: 2001:db8::1", None), // le regex ne gère pas IPv6
            ("", None),
        ];

        for (line, expected) in test_cases {
            let result = Detector::extract_ip_from_line(line);
            assert_eq!(result.as_deref(), expected);
        }
    }

    #[test]
    fn test_cleanup_old_entries() {
        let mut detector = Detector::new();
        let test_ip = "192.168.1.99";

        // Ajouter des entrées anciennes
        let old_time = Instant::now() - Duration::from_secs(100);

        // Pour simuler des anciennes tentatives SSH
        detector
            .ssh_attempts
            .insert(test_ip.to_string(), vec![old_time, old_time, old_time]);

        // Pour simuler d'anciennes requêtes web
        detector
            .web_requests
            .insert(test_ip.to_string(), vec![old_time, old_time]);

        // Pour simuler un vieux scan de ports
        let mut ports = std::collections::HashSet::new();
        ports.insert(22);
        ports.insert(80);
        detector.port_scans.insert(test_ip.to_string(), ports);

        // Exécuter le nettoyage
        detector.cleanup_old_entries();

        // Vérifier que les anciennes entrées sont nettoyées
        let ssh_attempts = detector.ssh_attempts.get(test_ip);
        let web_requests = detector.web_requests.get(test_ip);

        // Les entrées devraient être vides après nettoyage
        assert!(ssh_attempts.map_or(true, |v| v.is_empty()));
        assert!(web_requests.map_or(true, |v| v.is_empty()));

        // Les scans de ports devraient persister (pas de timeout dans notre implémentation)
        assert!(detector.port_scans.contains_key(test_ip));
    }

    #[test]
    fn test_detector_initialization() {
        let detector = Detector::new();

        // Vérifier que tous les HashMaps sont vides à l'initialisation
        assert!(detector.ssh_attempts.is_empty());
        assert!(detector.web_requests.is_empty());
        assert!(detector.port_scans.is_empty());
        assert!(detector.syn_connections.is_empty());
        assert!(detector.last_positions.is_empty());
    }

    #[test]
    fn test_packet_analysis_integration() {
        let mut detector = Detector::new();

        // Simuler l'analyse de différents types de paquets
        let test_cases = vec![
            ("192.168.1.10", 22, "TCP", 0x02), // SYN sur SSH
            ("192.168.1.10", 80, "TCP", 0x02), // SYN sur HTTP
            ("192.168.1.10", 443, "TCP", 0x02), // SYN sur HTTPS
            ("192.168.1.10", 3389, "TCP", 0x02), // SYN sur RDP
            ("192.168.1.10", 21, "TCP", 0x02), // SYN sur FTP
        ];

        for (ip, port, proto, flags) in test_cases {
            detector.analyze_packet(ip, port, proto, flags);
        }

        // Vérifier que le scan de ports est détecté (5 ports différents)
        assert!(detector.port_scans.contains_key("192.168.1.10"));
        let ports = detector.port_scans.get("192.168.1.10").unwrap();
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn test_alert_type_variants() {
        // Test que tous les types d'alerte sont définis
        let types = vec![
            AlertType::SSHBruteForce,
            AlertType::DDOS,
            AlertType::PortScan,
            AlertType::WebEnum,
        ];

        for alert_type in types {
            let alert = Alert::new(
                alert_type,
                Risk::Medium,
                "192.168.1.1".to_string(),
                "Test".to_string(),
                1,
            );
            assert!(!alert.source_ip.is_empty());
        }
    }

    #[test]
    fn test_risk_levels() {
        // Test des différents niveaux de risque
        let risks = vec![Risk::Low, Risk::Medium, Risk::High, Risk::Critical];

        for risk in risks {
            let alert = Alert::new(
                AlertType::PortScan,
                risk,
                "192.168.1.1".to_string(),
                "Test".to_string(),
                1,
            );

            // Vérifier que l'alerte est générée
            alert.generate_alert();
        }
    }
}

#[cfg(test)]
mod config_tests {
    use crate::config::CONFIG;
    use std::time::Duration;

    #[test]
    fn test_config_values() {
        // Vérifier que la configuration a des valeurs raisonnables
        assert!(!CONFIG.file_ssh_log.is_empty());
        assert!(!CONFIG.file_web_log.is_empty());
        assert!(!CONFIG.file_alert.is_empty());

        // Vérifier les valeurs SSH
        assert!(CONFIG.ssh_port > 0 && CONFIG.ssh_port <= 65535);
        assert!(CONFIG.ssh_attempts > 0);
        assert!(CONFIG.ssh_window > Duration::from_secs(0));

        // Vérifier les valeurs Web
        //assert!(CONFIG.web_attempts > 0);
        assert!(CONFIG.web_window > Duration::from_secs(0));

        // Vérifier les valeurs de scan de ports
        assert!(CONFIG.port_scan_threshold > 0);
    }

    #[test]
    fn test_config_paths() {
        // Vérifier que les chemins semblent valides
        assert!(CONFIG.file_ssh_log.contains(".log"));
        assert!(CONFIG.file_web_log.contains(".log"));
        assert!(CONFIG.file_alert.contains(".log"));
    }
}
