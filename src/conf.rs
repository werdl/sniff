use anstyle::AnsiColor;
use clap::{builder::Styles, Parser};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::num::ParseIntError;
use std::io::{Error, ErrorKind};

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct IpV4 {
    pub octets: [u8; 4],
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct IpV6 {
    pub octets: [u8; 16],
}

impl From<[u8; 4]> for IpV4 {
    fn from(octets: [u8; 4]) -> Self {
        IpV4 { octets }
    }
}

impl From<(u8, u8, u8, u8)> for IpV4 {
    fn from(octets: (u8, u8, u8, u8)) -> Self {
        IpV4 {
            octets: [octets.0, octets.1, octets.2, octets.3],
        }
    }
}

impl From<Vec<u8>> for IpV4 {
    fn from(octets: Vec<u8>) -> Self {
        IpV4 {
            octets: [octets[0], octets[1], octets[2], octets[3]],
        }
    }
}

impl From<Vec<u16>> for IpV6 {
    fn from(octets: Vec<u16>) -> Self {
        // remember, we have 8 16-bit octets, so we need to convert them into 16 8-bit octets
        let mut new_octets: [u8; 16] = [0; 16];

        for i in 0..8 {
            new_octets[i * 2] = (octets[i] >> 8) as u8;
            new_octets[i * 2 + 1] = (octets[i] & 0xFF) as u8;
        }

        IpV6 {
            octets: [
                new_octets[0],
                new_octets[1],
                new_octets[2],
                new_octets[3],
                new_octets[4],
                new_octets[5],
                new_octets[6],
                new_octets[7],
                new_octets[8],
                new_octets[9],
                new_octets[10],
                new_octets[11],
                new_octets[12],
                new_octets[13],
                new_octets[14],
                new_octets[15],
            ],
        }
    }
}

impl From<(u16, u16, u16, u16, u16, u16, u16, u16)> for IpV6 {
    fn from(octets: (u16, u16, u16, u16, u16, u16, u16, u16)) -> Self {
        IpV6 {
            octets: [
                (octets.0 >> 8) as u8,
                (octets.0 & 0xFF) as u8,
                (octets.1 >> 8) as u8,
                (octets.1 & 0xFF) as u8,
                (octets.2 >> 8) as u8,
                (octets.2 & 0xFF) as u8,
                (octets.3 >> 8) as u8,
                (octets.3 & 0xFF) as u8,
                (octets.4 >> 8) as u8,
                (octets.4 & 0xFF) as u8,
                (octets.5 >> 8) as u8,
                (octets.5 & 0xFF) as u8,
                (octets.6 >> 8) as u8,
                (octets.6 & 0xFF) as u8,
                (octets.7 >> 8) as u8,
                (octets.7 & 0xFF) as u8,
            ],
        }
    }
}

impl FromStr for IpV4 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let str_octets: Vec<&str> = s.split('.').collect();

        if str_octets.len() != 4 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Invalid IP address",
            ));
        }

        let mut octets: [u8; 4] = [0; 4];

        for (i, octet) in str_octets.iter().enumerate() {
            let num: Result<u8, ParseIntError> = octet.parse();
            if let Ok(value) = num {
                octets[i] = value;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid IP address",
                ));
            }
        }

        Ok(IpV4 { octets })
    }
}

impl FromStr for IpV6 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let str_octets: Vec<&str> = s.split(':').collect();

        if str_octets.len() != 8 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Invalid IP address",
            ));
        }

        let mut octets: [u16; 8] = [0; 8];

        for (i, octet) in str_octets.iter().enumerate() {
            let num: Result<u16, ParseIntError> = u16::from_str_radix(octet, 16);
            if let Ok(value) = num {
                octets[i] = value;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid IP address",
                ));
            }
        }

        // now, we need to convert the 8 8-bit octets into 16 4-bit octets
        let mut new_octets: [u8; 16] = [0; 16];

        for i in 0..8 {
            new_octets[i * 2] = (octets[i] >> 8) as u8;
            new_octets[i * 2 + 1] = (octets[i] & 0xFF) as u8;
        }

        Ok(IpV6 {
            octets: [
                new_octets[0],
                new_octets[1],
                new_octets[2],
                new_octets[3],
                new_octets[4],
                new_octets[5],
                new_octets[6],
                new_octets[7],
                new_octets[8],
                new_octets[9],
                new_octets[10],
                new_octets[11],
                new_octets[12],
                new_octets[13],
                new_octets[14],
                new_octets[15],
            ],
        })
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4(IpV4),
    V6(IpV6),
}

impl FromStr for IpAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            Ok(IpAddr::V6(s.parse()?))
        } else {
            Ok(IpAddr::V4(s.parse()?))
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Copy)]
pub struct MacAddr {
    octets: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr { octets }
    }
}

impl From<Vec<u8>> for MacAddr {
    fn from(octets: Vec<u8>) -> Self {
        MacAddr {
            octets: [
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
            ],
        }
    }
}

impl From<(u8, u8, u8, u8, u8, u8)> for MacAddr {
    fn from(octets: (u8, u8, u8, u8, u8, u8)) -> Self {
        MacAddr {
            octets: [octets.0, octets.1, octets.2, octets.3, octets.4, octets.5],
        }
    }
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|x| u8::from_str_radix(x, 16))
            .collect::<Result<Vec<u8>, ParseIntError>>();

        let octets = match octets {
            Ok(octets) => octets,
            Err(_) => return Err(Error::new(ErrorKind::InvalidInput, "Invalid MAC address")),
        };

        if octets.len() != 6 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Invalid MAC address",
            ));
        }

        Ok(MacAddr {
            octets: [
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
            ],
        })
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl From<u8> for Protocol {
    fn from(num: u8) -> Self {
        match num {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Unknown,
        }
    }
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            _ => Ok(Protocol::Unknown),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub verbose: bool,
    pub log_file: Option<String>,
    pub exclude_ips: Option<Vec<IpAddrOrHostname>>,
    pub exclude_macs: Option<Vec<MacAddr>>,
    pub filter_ips: Option<Vec<IpAddrOrHostname>>,
    pub filter_macs: Option<Vec<MacAddr>>,

    pub highlight_ips: Option<Vec<IpAddrOrHostname>>,
    pub highlight_macs: Option<Vec<MacAddr>>,

    pub protocol: Option<Protocol>,

    pub load_from_file: Option<String>,
    pub real_time_playback: bool,
    pub hostnames: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum IpAddrOrHostname {
    Ip(IpAddr),
    Hostname(String),
}

impl From<&str> for IpAddrOrHostname {
    fn from(s: &str) -> Self {
        if s.contains(':') {
            IpAddrOrHostname::Ip(s.parse().unwrap())
        } else {
            IpAddrOrHostname::Hostname(s.to_string())
        }
    }
}

const STYLES: Styles = Styles::styled()
    .literal(AnsiColor::BrightCyan.on_default().bold())
    .header(AnsiColor::BrightGreen.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().bold())
    .invalid(AnsiColor::Red.on_default().bold());

#[derive(Parser)]
#[command(styles=STYLES)]
struct Args {
    /// Verbose mode - prints MAC addresses
    #[clap(short, long)]
    verbose: bool,

    /// Path to the log file, if not provided, the program will not log
    #[clap(short, long)]
    log_file: Option<String>,

    /// Exclude IP addresses from the output
    #[clap(short = 'X', long, value_delimiter = ',')]
    exclude_ips: Option<Vec<IpAddrOrHostname>>,

    /// Exclude MAC addresses from the output
    #[clap(short = 'x', long, value_delimiter = ',')]
    exclude_macs: Option<Vec<MacAddr>>,

    /// Filter IP addresses
    #[clap(short = 'F', long, value_delimiter = ',')]
    filter_ips: Option<Vec<IpAddrOrHostname>>,

    /// Filter MAC addresses
    #[clap(short, long, value_delimiter = ',')]
    filter_macs: Option<Vec<MacAddr>>,

    /// Highlight IP addresses
    #[clap(short = 'I', long, value_delimiter = ',')]
    highlight_ips: Option<Vec<IpAddrOrHostname>>,

    /// Highlight MAC addresses
    #[clap(short = 'i', long, value_delimiter = ',')]
    highlight_macs: Option<Vec<MacAddr>>,

    /// Protocol to filter, omit for no filter (note that this is either TCP, UDP, or ICMP, not application layer protocols)
    protocol: Option<Protocol>,
    
    /// Load from a previously saved log file
    #[clap(short = 'L', long)]
    load_from_file: Option<String>,

    /// Real-time playback from the log file
    #[clap(short, long)]
    real_time_playback: bool,

    /// Print hostnames instead of IP addresses
    #[clap(short = 'H', long)]
    hostnames: bool,
}

pub fn get_conf() -> Config {
    let args: Args = Args::parse();

    Config {
        verbose: args.verbose,
        log_file: args.log_file,
        exclude_ips: args.exclude_ips,
        exclude_macs: args.exclude_macs,
        filter_ips: args.filter_ips,
        filter_macs: args.filter_macs,
        highlight_ips: args.highlight_ips,
        highlight_macs: args.highlight_macs,
        protocol: match args.protocol {
            Some(Protocol::Unknown) => None,
            _ => args.protocol,
        },
        load_from_file: args.load_from_file,
        real_time_playback: args.real_time_playback,
        hostnames: args.hostnames,
    }
}

impl std::fmt::Display for IpV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.octets[0], self.octets[1], self.octets[2], self.octets[3])
    }
}

impl std::fmt::Display for IpV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // first convert the 16 8-bit octets into 8 16-bit octets
        let mut new_octets: [u16; 8] = [0; 8];

        for i in 0..8 {
            new_octets[i] = (self.octets[i * 2] as u16) << 8 | self.octets[i * 2 + 1] as u16;
        }

        write!(f, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", new_octets[0], new_octets[1], new_octets[2], new_octets[3], new_octets[4], new_octets[5], new_octets[6], new_octets[7])

    }
}

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpAddr::V4(ip) => write!(f, "{}", ip),
            IpAddr::V6(ip) => write!(f, "{}", ip),
        }
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", self.octets[0], self.octets[1], self.octets[2], self.octets[3], self.octets[4], self.octets[5])
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Unknown => write!(f, "???"),
        }
    }
}