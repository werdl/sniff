# sniff
> A packet-collating, logging and simple packet sniffer, written in Rust
## Usage
```bash
Usage: sniff [OPTIONS] <PROTOCOL>

Arguments:
  <PROTOCOL>  Protocol to filter (note that this is either TCP, UDP, or ICMP, not application layer protocols)

Options:
  -v, --verbose
          Verbose mode - prints MAC addresses
  -l, --log-file <LOG_FILE>
          Path to the log file, if not provided, the program will not log
  -X, --exclude-ips <EXCLUDE_IPS>
          Exclude IP addresses from the output
  -x, --exclude-macs <EXCLUDE_MACS>
          Exclude MAC addresses from the output
  -F, --filter-ips <FILTER_IPS>
          Filter IP addresses
  -f, --filter-macs <FILTER_MACS>
          Filter MAC addresses
  -I, --highlight-ips <HIGHLIGHT_IPS>
          Highlight IP addresses
  -i, --highlight-macs <HIGHLIGHT_MACS>
          Highlight MAC addresses
  -L, --load-from-file <LOAD_FROM_FILE>
          Load from a previously saved log file
  -r, --real-time-playback
          Real-time playback from the log file
  -h, --help
          Print help
```

Note: The program must be run as root to access the network interface.

## Notes
- `sniff` only supports IPv4 packets, but should be OS-agnostic.
- `libpnet` should be installed to run a pre-compiled executable, along with `libpnet-dev` for compiling said executable.
