# BasicFirewall

A simple Python-based firewall for monitoring and filtering network traffic.

## Features

- Rule-based packet filtering
- Support for IP, port, and protocol filtering
- Traffic monitoring and statistics
- Configurable logging
- Easy to extend and customize

## Requirements

- Python 3.6 or higher
- Scapy library for packet capture and analysis

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/BasicFirewall.git
   cd BasicFirewall
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Configuration

The firewall is configured using a JSON file (`firewall_config.json`). Here's an example configuration:

```json
{
    "rules": [
        {
            "name": "Block Telnet",
            "action": "block",
            "dst_port": 23,
            "protocol": "tcp",
            "priority": 10
        },
        {
            "name": "Allow HTTP/HTTPS",
            "action": "allow",
            "dst_port": [80, 443],
            "protocol": "tcp",
            "priority": 30
        }
    ],
    "settings": {
        "default_action": "block",
        "log_level": "info"
    }
}
```

### Rule Configuration

Each rule can contain the following parameters:

- `name`: A descriptive name for the rule
- `action`: Either "allow" or "block"
- `priority`: Rules with lower priority numbers are evaluated first
- `src_ip`: Source IP address or network in CIDR notation
- `dst_ip`: Destination IP address or network in CIDR notation
- `src_port`: Source port (integer, range as string like "1000-2000", or list)
- `dst_port`: Destination port (integer, range as string like "1000-2000", or list)
- `protocol`: Protocol name ("tcp", "udp", "icmp") or protocol number

## Usage

Run the firewall with:

```
python src/main.py
```

Command line options:

```
-c, --config    Path to firewall configuration file (default: firewall_config.json)
-i, --interface Network interface to monitor
-l, --log       Path to log file (default: firewall.log)
-v, --verbose   Enable verbose output
```

## Note

This firewall requires administrator/root privileges to capture network packets.

On Windows:
- Run Command Prompt or PowerShell as Administrator
- Then run the firewall script

On Linux/macOS:
- Use sudo to run the firewall script
  ```
  sudo python src/main.py
  ```

## Testing

There are several ways to test the BasicFirewall:

### Unit Tests

Run the unit tests to verify the core functionality:

```
python -m unittest discover -s tests
```

### Simulation Tests

Run the simulation tests that test the firewall rules against simulated packets:

```
python -m tests.test_simulation
```

### Real-World Testing

To test the firewall with real network traffic:

1. Start the firewall with admin/root privileges:
   ```
   # On Windows (in Admin PowerShell)
   python src/main.py --verbose
   
   # On Linux/macOS
   sudo python src/main.py --verbose
   ```

2. Generate different types of network traffic:
   - HTTP/HTTPS (allowed): Open a web browser and visit websites
   - Telnet/FTP (blocked): Try connecting to a server using these protocols

The firewall log file (default: `firewall.log`) will show which packets were blocked or allowed.

## Warning

This is a basic firewall implementation intended for educational purposes. It is not recommended for production use without further enhancements and security testing.

## License

This project is licensed under the MIT License - see the LICENSE file for details.