mod conf;

use conf::{IpAddr, IpAddrOrHostname, MacAddr, Protocol};
use serde::{Deserialize, Serialize};

use std::{
    io::{Read, Seek, Write},
    time::SystemTime,
};

use pnet::{
    datalink,
    packet::{Packet, PrimitiveValues},
};

fn main() {
    let config = conf::get_conf();

    // if we have to load from a file, do that in a seperate loop and then return
    if config.load_from_file.is_some() {
        // first, load all the packets from the file
        let fname = config.clone().load_from_file.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(fname)
            .unwrap();

        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();

        let logs: PacketLog = serde_json::from_str(&data).unwrap();

        let start_time = logs.start_time;

        // if real time playback is enabled, then we need to play back the packets in real time, by sleeping for the difference between the current time and the time of the packet
        if config.real_time_playback {
            let mut amount_slept = 0.0;
            for packet in logs.packets.iter() {
                let time_diff = packet
                    .timestamp
                    .duration_since(start_time)
                    .unwrap()
                    .as_secs_f32();
                let time_diff = time_diff - amount_slept;

                std::thread::sleep(std::time::Duration::from_secs_f32(time_diff));

                print_request(packet.clone(), config.clone(), start_time);

                amount_slept += time_diff;
            }
        } else {
            for packet in logs.packets.iter() {
                print_request(packet.clone(), config.clone(), start_time);
            }
        }

        return;
    }

    // now the main loop
    // Get the list of available network interfaces
    let interfaces = datalink::interfaces();

    // Select the network interface to capture packets from
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("Failed to find a suitable network interface");

    // Create a channel to receive packets on the selected interface
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    let mut current_requests: Vec<ProcessedPacket> = Vec::new();

    let start_time = SystemTime::now();

    loop {
        match rx.next() {
            Ok(packet) => {
                // first, check if the origin ip and the dest ip are the same as the last packet

                // if so, append to the current_requests and continue
                // if not, process the current_requests and then clear it

                let ether = pnet::packet::ethernet::EthernetPacket::new(&packet).unwrap();

                let packet = ProcessedPacket {
                    orig_mac: MacAddr::from(ether.get_source().to_primitive_values()),
                    dest_mac: MacAddr::from(ether.get_destination().to_primitive_values()),
                    protocol: Protocol::from(ether.payload()[9]),
                    payload: ether.payload().to_vec(),
                };

                let orig_ip = if ether.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                    let ip = pnet::packet::ipv4::Ipv4Packet::new(ether.payload()).unwrap();
                    IpAddr::V4(ip.get_source().to_primitive_values().into())
                } else {
                    let ip = pnet::packet::ipv6::Ipv6Packet::new(ether.payload());

                    if ip.is_none() {
                        continue;
                    }
                    IpAddr::V6(ip.unwrap().get_source().to_primitive_values().into())
                };

                let dest_ip = if ether.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                    let ip = pnet::packet::ipv4::Ipv4Packet::new(ether.payload()).unwrap();
                    IpAddr::V4(ip.get_destination().to_primitive_values().into())
                } else {
                    let ip = pnet::packet::ipv6::Ipv6Packet::new(ether.payload()).unwrap();
                    IpAddr::V6(ip.get_destination().to_primitive_values().into())
                };

                if current_requests.len() == 0 {
                    current_requests.push(packet);
                    continue;
                } else {
                    let last_packet = current_requests.last().unwrap();

                    if last_packet.orig_mac == packet.orig_mac
                        && last_packet.dest_mac == packet.dest_mac
                    {
                        current_requests.push(packet);
                        continue;
                    } else {
                        // process the current_requests
                        let mut total_bytes = 0;
                        let mut total_packets = 0;

                        for req in current_requests.iter() {
                            total_bytes += req.payload.len();
                            total_packets += 1;
                        }

                        let stats = RequestStats {
                            protocol: current_requests[0].protocol,
                            orig_ip: orig_ip,
                            orig_mac: current_requests[0].orig_mac,
                            dest_ip: dest_ip,
                            dest_mac: current_requests[0].dest_mac,
                            bytes: total_bytes as u64,
                            packets: total_packets as u64,
                            timestamp: SystemTime::now(),
                            raw: current_requests
                                .iter()
                                .map(|x| x.payload.clone())
                                .flatten()
                                .collect(),
                        };

                        print_request(stats, config.clone(), start_time);

                        current_requests.clear();
                        current_requests.push(packet);
                    }
                }
            }
            Err(e) => panic!("Failed to receive packet: {}", e),
        }
    }
}

#[derive(Clone)]
struct ProcessedPacket {
    orig_mac: MacAddr,
    dest_mac: MacAddr,
    protocol: Protocol,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct RequestStats {
    protocol: Protocol,
    orig_ip: IpAddr,
    orig_mac: MacAddr,
    dest_ip: IpAddr,
    dest_mac: MacAddr,

    bytes: u64,
    packets: u64,

    timestamp: SystemTime,

    raw: Vec<u8>, // the raw packet data, but with the headers stripped, leaving just the payload
}

fn print_request(stats: RequestStats, config: conf::Config, start_time: SystemTime) {

    if config.protocol.is_some() {
        let protocol = config.clone().protocol.unwrap();
        if stats.protocol != protocol {
            return;
        }
    }

    // start time is when the program started (ie. when the user pressed enter)

    let mut orig_ip: String;

    if config.hostnames {
        orig_ip = {
            let ip: std::net::IpAddr = match stats.clone().orig_ip {
                IpAddr::V4(ip) => std::net::IpAddr::from(ip.octets),
                IpAddr::V6(ip) => std::net::IpAddr::from(ip.octets),
            };
            dns_lookup::lookup_addr(&ip).unwrap_or(ip.to_string())
        };
    } else {
        orig_ip = stats.orig_ip.to_string();
    }

    let mut dest_ip: String;

    if config.hostnames {
        dest_ip = {
            let ip: std::net::IpAddr = match stats.clone().dest_ip {
                IpAddr::V4(ip) => std::net::IpAddr::from(ip.octets),
                IpAddr::V6(ip) => std::net::IpAddr::from(ip.octets),
            };

            dns_lookup::lookup_addr(&ip).unwrap_or(ip.to_string())
        };
    } else {
        dest_ip = stats.dest_ip.to_string();
    }


    // now, remove all but the TLD from the hostname (the last two parts of the domain)
    if stats.orig_ip.to_string() != orig_ip {
        let orig_ip_splitted = orig_ip.split('.').collect::<Vec<&str>>();
        orig_ip = match orig_ip_splitted.len() {
            0 => stats.orig_ip.to_string(), // IPv6
            1 => orig_ip_splitted[0].to_string(),
            2 => orig_ip_splitted.join("."),
            _ => orig_ip_splitted[orig_ip_splitted.len() - 2..].join("."),
        };    
    }
    
    if stats.dest_ip.to_string() != dest_ip {
        let dest_ip_splitted = dest_ip.split('.').collect::<Vec<&str>>();
        dest_ip = match dest_ip_splitted.len() {
            0 => stats.dest_ip.to_string(), // IPv6
            1 => dest_ip_splitted[0].to_string(),
            2 => dest_ip_splitted.join("."),
            _ => dest_ip_splitted[dest_ip_splitted.len() - 2..].join("."),
        };
    }



    if config.clone().log_file.is_some() {
        log_to_file(stats.clone(), config.clone().log_file.unwrap(), start_time);
    }


    // first, check if we should be printing this request: check exclude/include filters
    if config.exclude_ips.is_some() {
        let exclude_ips = config.clone().exclude_ips.unwrap();
        if exclude_ips.contains(&IpAddrOrHostname::Hostname(orig_ip.clone())) || exclude_ips.contains(&IpAddrOrHostname::Hostname(dest_ip.clone())) {
            return;
        }
    }
    if config.exclude_macs.is_some() {
        let exclude_macs = config.clone().exclude_macs.unwrap();
        if exclude_macs.contains(&stats.orig_mac) || exclude_macs.contains(&stats.dest_mac) {
            return;
        }
    }

    if config.filter_ips.is_some() {
        let include_ips = config.clone().filter_ips.unwrap();
        if !include_ips.contains(&IpAddrOrHostname::Hostname(orig_ip.clone())) && !include_ips.contains(&IpAddrOrHostname::Hostname(dest_ip.clone())) {
            return;
        }
    }

    if config.filter_macs.is_some() {
        let include_macs = config.clone().filter_macs.unwrap();
        if !include_macs.contains(&stats.orig_mac) && !include_macs.contains(&stats.dest_mac) {
            return;
        }
    }


    if config.highlight_macs.is_some() {
        let highlight_macs = config.clone().highlight_macs.unwrap();
        if highlight_macs.contains(&stats.orig_mac) || highlight_macs.contains(&stats.dest_mac) {
            print!("\x1b[1;31m"); // red
        } else {
            print!("\x1b[0m");
        }
    } else if config.highlight_ips.is_some() {
        let highlight_ips = config.clone().highlight_ips.unwrap();
        if highlight_ips.contains(&IpAddrOrHostname::Hostname(orig_ip.clone())) || highlight_ips.contains(&IpAddrOrHostname::Hostname(dest_ip.clone())) {
            print!("\x1b[1;31m"); // red
        } else {
            print!("\x1b[0m");
        }
    } else {
        print!("\x1b[0m");
    }



    // print the stats
    if config.verbose {
        println!(
            "{} ({} packet{}) at {:02}s: {} ({}) -> {} ({}) {}B",
            stats.protocol,
            stats.packets,
            if stats.packets == 1 { "" } else { "s" },
            stats
                .timestamp
                .duration_since(start_time)
                .unwrap()
                .as_secs_f32(),
            orig_ip,
            stats.orig_mac,
            dest_ip,
            stats.dest_mac,
            stats.bytes,
        );
    } else {
        println!(
            "{} at {:.2}s: {} -> {}: {} bytes",
            stats.protocol,
            stats
                .timestamp
                .duration_since(start_time)
                .unwrap()
                .as_secs_f32(),
            orig_ip,
            dest_ip,
            stats.bytes,
        );
    }
}

#[derive(Serialize, Deserialize)]
struct PacketLog {
    packets: Vec<RequestStats>,
    start_time: SystemTime,
}

fn log_to_file(stats: RequestStats, fname: String, start_time: SystemTime) {
    // first, load any existing data from the file
    // then, append the new data
    // then, write the new data to the file

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(fname)
        .unwrap();

    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let mut logs: PacketLog = serde_json::from_str(&data).unwrap_or(PacketLog {
        packets: Vec::new(),
        start_time: start_time,
    });

    logs.packets.push(stats);

    let new_data = serde_json::to_string(&logs).unwrap();

    // seek to the beginning of the file
    file.seek(std::io::SeekFrom::Start(0)).unwrap();

    // write the new data
    file.write_all(new_data.as_bytes()).unwrap();
}
