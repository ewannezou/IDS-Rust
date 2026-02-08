mod alert;
mod config;
mod detector;

use detector::Detector;
use etherparse::{IpNumber, NetHeaders, TransportHeader};
use pcap::{Capture, Device};
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Démarrage du système IDS Rust...");
    println!("Fichier d'alertes: {}", config::CONFIG.file_alert);
    println!("Surveillance SSH: {}", config::CONFIG.file_ssh_log);
    println!("Surveillance Web: {}", config::CONFIG.file_web_log);

    // Créer le répertoire de logs si nécessaire
    std::fs::create_dir_all("/var/log/ids").unwrap_or_default();

    let detector = Detector::new();
    let detector = Arc::new(Mutex::new(detector));

    // Démarrer la surveillance des logs
    let detector_for_logs = Arc::clone(&detector);

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let mut detector = detector_for_logs.lock().await;
            detector.monitor_logs();
            detector.cleanup_old_entries();
        }
    });

    // Démarrer la capture réseau
    start_network_capture(detector).await?;

    Ok(())
}

async fn start_network_capture(
    detector: Arc<Mutex<Detector>>
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Démarrage de la capture réseau...");

    let devices = Device::list()?;
    let device = devices
        .first()
        .ok_or("Aucun périphérique réseau trouvé")?
        .clone();

    println!("Interface réseau: {}", device.name);

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .open()?;

    // Appliquer un filtre pour capturer seulement ce qui nous intéresse
    let filter = "tcp or udp";
    cap.filter(filter, true)?;

    println!("Capture réseau démarrée. Filtre: {}", filter);

    while let Ok(packet) = cap.next_packet() {
        if let Some((src_ip, dst_port, protocol, flags)) =
            parse_packet(&packet)
        {
            let detector = Arc::clone(&detector);
            tokio::spawn(async move {
                let mut detector = detector.lock().await;
                detector.analyze_packet(&src_ip, dst_port, &protocol, flags);
            });
        }
    }

    Ok(())
}

fn parse_packet(packet: &pcap::Packet) -> Option<(String, u16, String, u8)> {
    use etherparse::PacketHeaders;

    let headers = match PacketHeaders::from_ethernet_slice(packet.data) {
        Ok(h) => h,
        Err(_) => return None,
    };

    // Extraire l'IP source et le protocole
    let (source_ip, protocol) = match headers.net {
        Some(NetHeaders::Ipv4(ipv4, _)) => {
            let proto = match ipv4.protocol {
                IpNumber::TCP => "TCP",
                IpNumber::UDP => "UDP",
                IpNumber::ICMP => "ICMP",
                _ => return None,
            };
            // Convertir [u8; 4] en String format IP
            let mut ip_str = String::new();
            for (i, octet) in ipv4.source.iter().enumerate() {
                if i > 0 {
                    write!(ip_str, ".").unwrap();
                }
                write!(ip_str, "{}", octet).unwrap();
            }
            if ip_str == "192.168.56.101" {
                return None;
            }
            (ip_str, proto.to_string())
        }
        Some(NetHeaders::Ipv6(ipv6, _)) => {
            let proto = match ipv6.next_header {
                IpNumber::TCP => "TCP",
                IpNumber::UDP => "UDP",
                IpNumber::ICMP => "ICMP",
                _ => return None,
            };
            // Convertir [u8; 16] en String format IPv6
            let ip_str = format_ipv6(&ipv6.source);
            (ip_str, proto.to_string())
        }
        _ => return None,
    };

    // Extraire le port destination et les flags
    let (dest_port, flags) = match headers.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let dest_port = tcp.destination_port;

            // Extraire les flags TCP
            let flags_u8 = {
                let mut flags = 0u8;
                if tcp.fin {
                    flags |= 0x01;
                }
                if tcp.syn {
                    flags |= 0x02;
                }
                if tcp.rst {
                    flags |= 0x04;
                }
                if tcp.psh {
                    flags |= 0x08;
                }
                if tcp.ack {
                    flags |= 0x10;
                }
                if tcp.urg {
                    flags |= 0x20;
                }
                if tcp.ece {
                    flags |= 0x40;
                }
                if tcp.cwr {
                    flags |= 0x80;
                }
                flags
            };
            (dest_port, flags_u8)
        }
        Some(TransportHeader::Udp(udp)) => (udp.destination_port, 0),
        _ => (0, 0),
    };

    Some((source_ip, dest_port, protocol, flags))
}

// Fonction pour formater une adresse IPv6
fn format_ipv6(addr: &[u8; 16]) -> String {
    let mut result = String::new();
    for i in (0..16).step_by(2) {
        if i > 0 {
            result.push(':');
        }
        write!(&mut result, "{:02x}{:02x}", addr[i], addr[i + 1]).unwrap();
    }

    result
}
