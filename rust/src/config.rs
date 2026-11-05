//! The part of a Python Reticulum config file this replica uses: `enable_transport` and the
//! TCP and UDP interfaces, so one config directory serves either replica.

use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub enum Iface {
    TcpServer(String),
    TcpClient(String),
    Udp { listen: String, forward: Option<String> },
}

#[derive(Debug, Default, PartialEq)]
pub struct Config {
    pub transport: bool,
    pub ifaces: Vec<Iface>,
}

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

pub fn parse(text: &str) -> Config {
    let mut c = Config::default();
    let mut section = String::new();
    let mut sub: Vec<HashMap<String, String>> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.starts_with("[[") {
            sub.push(HashMap::from([("name".into(), line.trim_matches(['[', ']']).into())]));
        } else if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).to_string();
        } else if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if section == "interfaces" {
                if let Some(s) = sub.last_mut() {
                    s.insert(k, v);
                }
            } else if section == "reticulum" && k == "enable_transport" {
                c.transport = truthy(&v);
            }
        }
    }
    for s in sub {
        let get = |k: &str| s.get(k).map(String::as_str).unwrap_or("");
        let enabled = s.get("enabled").or(s.get("interface_enabled")).is_none_or(|v| truthy(v));
        if !enabled {
            continue;
        }
        let addr = |h: &str, p: &str| format!("{}:{}", get(h), get(p));
        match get("type") {
            "TCPServerInterface" => {
                let ip = if get("listen_ip").is_empty() { "0.0.0.0" } else { get("listen_ip") };
                c.ifaces.push(Iface::TcpServer(format!("{ip}:{}", get("listen_port"))))
            }
            "TCPClientInterface" => c.ifaces.push(Iface::TcpClient(addr("target_host", "target_port"))),
            "UDPInterface" => c.ifaces.push(Iface::Udp {
                listen: addr("listen_ip", "listen_port"),
                forward: s.contains_key("forward_ip").then(|| addr("forward_ip", "forward_port")),
            }),
            t => log::warn!("pigeonhole: interface {} of type {t} is not supported, skipped", get("name")),
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_e2e_configs() {
        let c = parse(
            "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n[logging]\n  loglevel = 3\n\
             [interfaces]\n  [[Listen]]\n    type = TCPServerInterface\n    enabled = yes\n    \
             listen_ip = 127.0.0.1\n    listen_port = 47400\n  [[To0]]\n    type = TCPClientInterface\n    \
             enabled = yes\n    target_host = 127.0.0.1\n    target_port = 47401\n  [[Off]]\n    \
             type = TCPClientInterface\n    enabled = no\n  [[Auto]]\n    type = AutoInterface\n",
        );
        assert_eq!(
            c,
            Config {
                transport: true,
                ifaces: vec![Iface::TcpServer("127.0.0.1:47400".into()), Iface::TcpClient("127.0.0.1:47401".into())]
            }
        );
    }
}
