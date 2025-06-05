"""
Network Swiss Army Knife - Network Scanner Module
"""

import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

import scapy.all as scapy
import netifaces

from .. import modules

@modules.register_module("network_scanner", modules.NetworkModule)
class NetworkScanner(modules.NetworkModule):
    """Network scanning functionality."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 2.0)
        self.max_threads = config.get('max_threads', 100)
    
    def get_description(self):
        return "Discover hosts on a network using various scanning techniques"
    
    def get_help(self):
        return """
        Network Scanner Module
        
        Usage: netswiss network_scanner [options] <target>
        
        Options:
          --method METHOD    Scanning method (arp, ping, tcp) [default: arp]
          --timeout SECONDS  Timeout for responses [default: 2.0]
          --interface IFACE  Network interface to use
          --port PORT        TCP port to scan when using tcp method [default: 80]
          
        Examples:
          netswiss network_scanner 192.168.1.0/24
          netswiss network_scanner --method ping 10.0.0.0/24
          netswiss network_scanner --method tcp --port 443 192.168.1.0/24
        """
    
    def run(self, target: str, method: str = 'arp', interface: Optional[str] = None, 
            port: int = 80, **kwargs) -> List[Dict[str, Any]]:
        """
        Scan network for active hosts.
        
        Args:
            target: IP address or network in CIDR notation
            method: Scanning method (arp, ping, tcp)
            interface: Network interface to use
            port: TCP port to scan when using tcp method
            
        Returns:
            List of dictionaries containing information about discovered hosts
        """
        # Override instance config with run parameters
        self.timeout = kwargs.get('timeout', self.timeout)
        
        # Determine network range
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ValueError(f"Invalid target: {target}. Use IP address or CIDR notation.")
        
        # Select scanning method
        if method == 'arp':
            return self._arp_scan(network, interface)
        elif method == 'ping':
            return self._ping_scan(network)
        elif method == 'tcp':
            return self._tcp_scan(network, port)
        else:
            raise ValueError(f"Unknown scanning method: {method}")
    
    def _arp_scan(self, network: ipaddress.IPv4Network, interface: Optional[str] = None) -> List[Dict[str, Any]]:
        """Perform ARP scan to discover hosts."""
        if interface is None:
            # Get default interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                interface = gateways['default'][netifaces.AF_INET][1]
            else:
                # Just use the first non-loopback interface
                for iface in netifaces.interfaces():
                    if iface != 'lo':
                        interface = iface
                        break
        
        if not interface:
            raise ValueError("Could not determine network interface")
        
        results = []
        
        # Create ARP request packets for all hosts in the network
        for ip in network.hosts():
            ip_str = str(ip)
            
            # Send ARP request and wait for response
            arp_request = scapy.ARP(pdst=ip_str)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            
            # Send packet and get response
            answered, _ = scapy.srp(packet, timeout=self.timeout, verbose=False, iface=interface)
            
            for _, response in answered:
                results.append({
                    'ip': response.psrc,
                    'mac': response.hwsrc,
                    'hostname': self._get_hostname(response.psrc),
                    'method': 'arp'
                })
        
        return results
    
    def _ping_scan(self, network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
        """Perform ICMP ping scan to discover hosts."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for ip in network.hosts():
                ip_str = str(ip)
                futures.append(executor.submit(self._ping_host, ip_str))
            
            for future in futures:
                result = future.result()
                if result:
                    results.append(result)
        
        return results
    
    def _ping_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Ping a single host and return result if alive."""
        try:
            # Create ICMP packet
            icmp = scapy.IP(dst=ip)/scapy.ICMP()
            
            # Send packet and wait for response
            response = scapy.sr1(icmp, timeout=self.timeout, verbose=False)
            
            if response:
                # Try to get MAC address
                mac = None
                try:
                    arp_request = scapy.ARP(pdst=ip)
                    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast/arp_request
                    answered, _ = scapy.srp(packet, timeout=1, verbose=False)
                    if answered:
                        mac = answered[0][1].hwsrc
                except:
                    pass
                
                return {
                    'ip': ip,
                    'mac': mac,
                    'hostname': self._get_hostname(ip),
                    'method': 'ping',
                    'ttl': response.ttl if hasattr(response, 'ttl') else None
                }
        except:
            pass
        
        return None
    
    def _tcp_scan(self, network: ipaddress.IPv4Network, port: int) -> List[Dict[str, Any]]:
        """Perform TCP scan to discover hosts."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for ip in network.hosts():
                ip_str = str(ip)
                futures.append(executor.submit(self._tcp_connect, ip_str, port))
            
            for future in futures:
                result = future.result()
                if result:
                    results.append(result)
        
        return results
    
    def _tcp_connect(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Attempt TCP connection to a host and return result if successful."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Try to get MAC address
                mac = None
                try:
                    arp_request = scapy.ARP(pdst=ip)
                    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast/arp_request
                    answered, _ = scapy.srp(packet, timeout=1, verbose=False)
                    if answered:
                        mac = answered[0][1].hwsrc
                except:
                    pass
                
                return {
                    'ip': ip,
                    'mac': mac,
                    'hostname': self._get_hostname(ip),
                    'method': 'tcp',
                    'port': port
                }
        except:
            pass
        
        return None
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Attempt to resolve hostname from IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None
