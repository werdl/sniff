# sniff
> A packet-collating, logging and simple packet sniffer, written in Rust
## Usage
```bash
Usage: sniff [OPTIONS] [COMMAND]

Commands:
  tcp   Monitor only TCP packets
  udp   Monitor only UDP packets
  icmp  Monitor only ICMP packets
  file  Monitor packets from a previously written log file
  help  Print this message or the help of the given subcommand(s)
(will default to monitoring all packets if no command is given)

Options:
  -l, --log      log to a file, off by default. Warning: this creates a HUGE amount of data in seconds
  -v, --verbose  verbose output (eg MAC addresses, number of collated packets), off by default
  -h, --help     Print
```

Note: The program must be run as root to access the network interface.

## Notes
- `sniff` only supports IPv4 packets, but should be OS-agnostic.