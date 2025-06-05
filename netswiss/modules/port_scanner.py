"""
Network Swiss Army Knife - Port Scanner Module
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Union, Tuple

import scapy.all as scapy

from .. import modules

@modules.register_module("port_scanner", modules.NetworkModule)
class PortScanner(modules.NetworkModule):
    """Port scanning functionality."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 1.0)
        self.max_threads = config.get('max_threads', 100)
    
    def get_description(self):
        return "Scan for open ports on target hosts"
    
    def get_help(self):
        return """
        Port Scanner Module
        
        Usage: netswiss port_scanner [options] <target>
        
        Options:
          --ports PORTS      Port range to scan (e.g., 1-1024, 22,80,443) [default: 1-1024]
          --method METHOD    Scanning method (connect, syn, udp) [default: connect]
          --timeout SECONDS  Timeout for responses [default: 1.0]
          --threads NUM      Maximum number of threads [default: 100]
          
        Examples:
          netswiss port_scanner 192.168.1.10
          netswiss port_scanner --ports 22,80,443 10.0.0.5
          netswiss port_scanner --method syn --ports 1-65535 192.168.1.1
        """
    
    def run(self, target: str, ports: str = '1-1024', method: str = 'connect', **kwargs) -> Dict[str, Any]:
        """
        Scan ports on target host.
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (e.g., 1-1024, 22,80,443)
            method: Scanning method (connect, syn, udp)
            
        Returns:
            Dictionary containing scan results
        """
        # Override instance config with run parameters
        self.timeout = kwargs.get('timeout', self.timeout)
        self.max_threads = kwargs.get('threads', self.max_threads)
        
        # Parse port range
        port_list = self._parse_port_range(ports)
        
        # Resolve hostname if needed
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname: {target}")
        
        # Select scanning method
        if method == 'connect':
            open_ports = self._tcp_connect_scan(ip, port_list)
        elif method == 'syn':
            open_ports = self._tcp_syn_scan(ip, port_list)
        elif method == 'udp':
            open_ports = self._udp_scan(ip, port_list)
        else:
            raise ValueError(f"Unknown scanning method: {method}")
        
        # Get service names for open ports
        port_info = []
        for port in open_ports:
            service = self._get_service_name(port)
            port_info.append({
                'port': port,
                'service': service,
                'state': 'open'
            })
        
        return {
            'target': target,
            'ip': ip,
            'method': method,
            'ports_scanned': len(port_list),
            'open_ports': len(port_info),
            'port_details': port_info
        }
    
    def _parse_port_range(self, ports_str: str) -> List[int]:
        """Parse port range string into list of ports."""
        ports = []
        
        for part in ports_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        
        return sorted(list(set(ports)))
    
    def _tcp_connect_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Perform TCP connect scan."""
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for port in ports:
                futures.append(executor.submit(self._tcp_connect_port, ip, port))
            
            for i, future in enumerate(futures):
                if future.result():
                    open_ports.append(ports[i])
        
        return open_ports
    
    def _tcp_connect_port(self, ip: str, port: int) -> bool:
        """Attempt TCP connection to a port and return True if open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _tcp_syn_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Perform TCP SYN scan (requires root)."""
        open_ports = []
        
        for port in ports:
            # Create SYN packet
            syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = scapy.sr1(syn_packet, timeout=self.timeout, verbose=False)
            
            if response and response.haslayer(scapy.TCP):
                # Check if SYN-ACK received (flags 0x12)
                if response[scapy.TCP].flags == 0x12:
                    # Send RST to close connection
                    rst_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="R")
                    scapy.send(rst_packet, verbose=False)
                    open_ports.append(port)
        
        return open_ports
    
    def _udp_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Perform UDP scan."""
        open_ports = []
        
        for port in ports:
            # Create UDP packet
            udp_packet = scapy.IP(dst=ip)/scapy.UDP(dport=port)
            
            # Send packet and wait for response
            response = scapy.sr1(udp_packet, timeout=self.timeout, verbose=False)
            
            # If no response, port might be open
            if response is None:
                open_ports.append(port)
            # If ICMP error received, port is closed
            elif response.haslayer(scapy.ICMP):
                if response[scapy.ICMP].type == 3 and response[scapy.ICMP].code == 3:
                    # Port unreachable - closed
                    pass
                else:
                    # Other ICMP error - might be filtered
                    pass
            # If UDP response received, port is open
            elif response.haslayer(scapy.UDP):
                open_ports.append(port)
        
        return open_ports
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port number."""
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
