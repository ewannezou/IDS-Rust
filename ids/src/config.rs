use std::time::Duration;

pub struct Config {
    pub file_ssh_log: &'static str,
    pub file_web_log: &'static str,
    pub ssh_port: u16,
    pub ssh_attempts: usize,
    pub ssh_window: Duration,
    pub web_window: Duration,
    //pub web_attempts: usize,
    pub port_scan_threshold: usize,
    //pub port_scan_window: Duration,
    pub file_alert: &'static str,
}

pub static CONFIG: Config = Config {
    file_ssh_log: "/var/log/auth.log",
    file_web_log: "/var/log/apache2/access.log",
    ssh_port: 22,
    ssh_attempts: 5,
    ssh_window: Duration::from_secs(60),
    web_window: Duration::from_secs(5),
    //web_attempts: 10,
    port_scan_threshold: 100,
    //port_scan_window: Duration::from_secs(60),
    file_alert: "/opt/log/ids/ids_alert.log",
};
