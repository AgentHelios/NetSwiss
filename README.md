# Network Swiss Army Knife

A comprehensive network analysis toolkit that combines multiple networking utilities into a single, modular Python application.

## Features

- **Network Scanning**: Discover hosts on a network using various scanning techniques
- **Port Scanning**: Scan for open ports on target hosts
- **Service Detection**: Identify services running on open ports
- **OS Fingerprinting**: Determine operating systems of target hosts
- **Vulnerability Scanning**: Basic vulnerability assessment
- **DNS Reconnaissance**: Gather DNS information about domains
- **Network Mapping**: Visualize network topology

## Installation

### Prerequisites

- Python 3.6+
- Required packages:
  - scapy
  - python-nmap
  - dnspython
  - netifaces
  - networkx
  - matplotlib
  - colorama
  - requests
  - pyyaml

### Install from Source

```bash
# Clone the repository
git clone https://github.com/AgentHelios/NetSwiss.git
cd NetSwiss

# Install the package
pip install -e .
```

## Usage

### Command Line Interface

```bash
netswiss [global options] <module> [module options] <target>
```

### Global Options

- `--version`: Show version information
- `--verbose`, `-v`: Increase output verbosity
- `--quiet`, `-q`: Suppress non-essential output
- `--output`, `-o`: Output file for results
- `--format`, `-f`: Output format (text, json, yaml)

### Available Modules

#### Network Scanner

Discover hosts on a network using various scanning techniques.

```bash
netswiss network_scanner [options] <target>

# Examples:
netswiss network_scanner 192.168.1.0/24
netswiss network_scanner --method ping 10.0.0.0/24
```

#### Port Scanner

Scan for open ports on target hosts.

```bash
netswiss port_scanner [options] <target>

# Examples:
netswiss port_scanner 192.168.1.10
netswiss port_scanner --ports 22,80,443 10.0.0.5
```

#### Service Detector

Identify services running on open ports.

```bash
netswiss service_detector [options] <target>

# Examples:
netswiss service_detector 192.168.1.10
netswiss service_detector --intensity aggressive 192.168.1.1
```

#### OS Fingerprinter

Determine operating systems of target hosts.

```bash
netswiss os_fingerprinter [options] <target>

# Examples:
netswiss os_fingerprinter 192.168.1.10
netswiss os_fingerprinter --method ttl 10.0.0.5
```

#### Vulnerability Scanner

Perform basic vulnerability scanning on target hosts.

```bash
netswiss vulnerability_scanner [options] <target>

# Examples:
netswiss vulnerability_scanner 192.168.1.10
netswiss vulnerability_scanner --level aggressive 192.168.1.1
```

#### DNS Reconnaissance

Gather DNS information about domains.

```bash
netswiss dns_recon [options] <target>

# Examples:
netswiss dns_recon example.com
netswiss dns_recon --type mx example.com
```

#### Network Mapper

Map and visualize network topology.

```bash
netswiss network_mapper [options] <target>

# Examples:
netswiss network_mapper 192.168.1.0/24
netswiss network_mapper --output map.png 10.0.0.0/24
```

## Security Considerations

- This tool should only be used on networks and systems you own or have explicit permission to test
- Some features require root/administrator privileges
- Aggressive scanning may trigger security alerts or cause service disruptions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate network administration purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using this software.
