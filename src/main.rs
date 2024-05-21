use std::io::{Read, Seek, Write};
use std::thread::current;
use std::time::{SystemTime, UNIX_EPOCH};

use pnet::datalink;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::{Packet, PrimitiveValues};

use clap::{self, Parser};

use serde::{Deserialize, Serialize};

// subcommands
#[derive(Parser, Debug)]
enum SubCommand {
    /// Monitor only TCP packets
    #[clap(name = "tcp")]
    Tcp(Tcp),

    /// Monitor only UDP packets
    #[clap(name = "udp")]
    Udp(Udp),

    /// Monitor only ICMP packets
    #[clap(name = "icmp")]
    Icmp(Icmp),

    /// Monitor packets from a previously written log file
    #[clap(name = "file")]
    FromFile(FromFile),
}

// tcp subcommand
#[derive(Parser, Debug)]
struct Tcp {
    #[clap(short, long)]
    port: u16,
}

// udp subcommand
#[derive(Parser, Debug)]
struct Udp {
    #[clap(short, long)]
    port: u16,
}

// icmp subcommand
#[derive(Parser, Debug)]
struct Icmp {
    #[clap(short, long)]
    message: String,
}

#[derive(Parser, Debug)]
struct FromFile {
    #[clap(short, long)]
    file: String,

    #[clap(short, long, default_value = "false")]
    real_time_playback: bool,
}

// main command
#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    subcmd: Option<SubCommand>,

    /// log to a file, off by default. Warning: this creates a HUGE amount of data in seconds
    #[clap(short, long, default_value = "false")]
    log: bool,

    /// verbose output (eg MAC addresses, number of collated packets), off by default
    #[clap(short, long, default_value = "false")]
    verbose: bool,
}

// capture subcommand
fn main() {
    // Parse the command line arguments
    let args: Args = Args::parse();

    let protocol = match args.subcmd {
        Some(SubCommand::Tcp(_)) => 6,
        Some(SubCommand::Udp(_)) => 17,
        Some(SubCommand::Icmp(_)) => 1,
        Some(SubCommand::FromFile(options)) => {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .open(options.file.clone())
                .unwrap();

            let mut contents = String::new();

            file.read_to_string(&mut contents).unwrap();

            let data: LogFile = serde_json::from_str(&contents).unwrap();

            let mut last_time = 0.0;

            if options.real_time_playback {
                let start_time = data.start_time;
                for stats in data.data.iter() {
                    let elapsed_time = stats.time.duration_since(start_time).unwrap();
                    std::thread::sleep(
                        elapsed_time - std::time::Duration::from_secs_f64(last_time as f64),
                    );

                    last_time = elapsed_time.as_secs_f64();

                    print_stats(stats.clone(), Some(start_time), args.verbose);
                }
            } else {
                for stats in data.data.iter() {
                    print_stats(stats.clone(), Some(data.start_time), args.verbose);
                }
            }

            return;
        }
        None => 0,
    };

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

    // Start capturing and decoding packets
    let mut current_request = Vec::<IPv4Packet>::new();

    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let time = std::time::SystemTime::now();

    // create file log-<unix_time>.json
    if args.log {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(format!("log-{}.json", unix_time))
            .unwrap();

        file.write_all("[]".as_bytes()).unwrap();
    }

    loop {
        match rx.next() {
            Ok(packet) => {
                // Decode the Ethernet packet
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    // Check if the packet is an IP packet
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if ethernet.payload()[9] != protocol && protocol != 0 {
                            continue;
                        }

                        // check that from and to are the same - if they are, append and continue, if not, print the data for the current_request and then clear it
                        if (current_request.len() != 0
                            && current_request.last().unwrap().origin
                                == ethernet.get_source().to_primitive_values()
                            && current_request.last().unwrap().dest
                                == ethernet.get_destination().to_primitive_values())
                            || current_request.len() == 0
                        {
                            let ip_packet = ethernet.payload();
                            let dest = ip_packet[16..20].to_vec();
                            let origin = ip_packet[12..16].to_vec();
                            let protocol = ip_packet[9];
                            let data = ip_packet[20..].to_vec();

                            current_request.push(IPv4Packet {
                                dest_ip: dest,
                                orig_ip: origin,
                                protocol: protocol,
                                data: data,
                                origin: ethernet.get_source().to_primitive_values(),
                                dest: ethernet.get_destination().to_primitive_values(),
                            });
                        } else {
                            if current_request.len() != 0 {
                                let mut total_size = 0;
                                for packet in current_request.iter() {
                                    total_size += packet.data.len();
                                }

                                let stats = RequestStats {
                                    packets: current_request.clone(),
                                    time: SystemTime::now(),
                                    total_size: total_size,
                                };

                                print_stats(stats.clone(), Some(time), args.verbose);

                                if args.log {
                                    write_log(stats, Some(format!("log-{}.json", unix_time)), time);
                                }

                                current_request.clear();
                            }
                            let ip_packet = ethernet.payload();
                            let dest = ip_packet[16..20].to_vec();
                            let origin = ip_packet[12..16].to_vec();
                            let protocol = ip_packet[9];
                            let data = ip_packet[20..].to_vec();

                            current_request.push(IPv4Packet {
                                dest_ip: dest,
                                orig_ip: origin,
                                protocol: protocol,
                                data: data,
                                origin: ethernet.get_source().to_primitive_values(),
                                dest: ethernet.get_destination().to_primitive_values(),
                            });
                        }
                    }
                }
            }
            Err(e) => panic!("Failed to receive packet: {}", e),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct IPv4Packet {
    dest: (u8, u8, u8, u8, u8, u8),
    origin: (u8, u8, u8, u8, u8, u8),
    protocol: u8,
    data: Vec<u8>,

    orig_ip: Vec<u8>,
    dest_ip: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct RequestStats {
    packets: Vec<IPv4Packet>,
    time: std::time::SystemTime,
    total_size: usize,
}

#[derive(Serialize, Deserialize, Clone)]
struct LogFile {
    data: Vec<RequestStats>,
    start_time: std::time::SystemTime,
}

fn fmt_mac(mac: (u8, u8, u8, u8, u8, u8)) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}

fn write_log(stats: RequestStats, fname: Option<String>, s_time: std::time::SystemTime) {
    // read the current file's list, append the new data, and write it back

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fname.unwrap())
        .unwrap();

    let mut contents = String::new();

    file.read_to_string(&mut contents).unwrap();

    let mut data: LogFile = serde_json::from_str(&contents).unwrap_or(LogFile {
        data: Vec::new(),
        start_time: s_time,
    });

    data.data.push(stats);

    let to_write = LogFile {
        data: data.data,
        start_time: s_time,
    };

    file.seek(std::io::SeekFrom::Start(0)).unwrap();

    file.write_all(serde_json::to_string(&to_write).unwrap().as_bytes())
        .unwrap();

    file.set_len(serde_json::to_string(&to_write).unwrap().len() as u64)
        .unwrap();

    file.flush().unwrap();
}

fn print_stats(stats: RequestStats, s_time: Option<std::time::SystemTime>, verbose: bool) {
    if verbose {
        println!(
            "{} IPv4 {} packet{} at {:.2}s: {} ({}) -> {} ({}) : {} bytes",
            stats.packets.len(),
            match stats.packets.last().unwrap().protocol {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "Unknown",
            },
            if stats.packets.len() > 1 { "s" } else { "" },
            match s_time {
                Some(time) => stats.time.duration_since(time).unwrap().as_secs_f64(),
                None => stats.time.elapsed().unwrap().as_secs_f64(),
            },
            stats
                .packets
                .last()
                .unwrap()
                .orig_ip
                .iter()
                .map(|x| format!("{}", x))
                .collect::<Vec<String>>()
                .join("."),
            fmt_mac(stats.packets.last().unwrap().origin),
            stats
                .packets
                .last()
                .unwrap()
                .dest_ip
                .iter()
                .map(|x| format!("{}", x))
                .collect::<Vec<String>>()
                .join("."),
            fmt_mac(stats.packets.last().unwrap().dest),
            stats.total_size,
        );
    } else {
        println!(
            "{} at {:.2}s: {} -> {} : {} bytes",
            match stats.packets.last().unwrap().protocol {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "Unknown",
            },
            match s_time {
                Some(time) => stats.time.duration_since(time).unwrap().as_secs_f64(),
                None => stats.time.elapsed().unwrap().as_secs_f64(),
            },
            stats.packets.last().unwrap().orig_ip.iter().map(|x| format!("{}", x)).collect::<Vec<String>>().join("."),
            stats.packets.last().unwrap().dest_ip.iter().map(|x| format!("{}", x)).collect::<Vec<String>>().join("."),
            
            stats.total_size,
        );
    
    }
}

// next up: ipv6
// this would entail creating a more unified interface for packets, seperating the payload into IP address and similar metadata, and then a seperate payload for the actual data, which wouldn't differ between ipv4 and ipv6
