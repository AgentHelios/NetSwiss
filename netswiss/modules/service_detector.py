"""
Network Swiss Army Knife - Service Detection Module
"""

import socket
import time
from typing import Dict, Any, Optional, List, Tuple

import nmap

from .. import modules

@modules.register_module("service_detector", modules.NetworkModule)
class ServiceDetector(modules.NetworkModule):
    """Service detection functionality."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 5.0)
        self.nmapper = nmap.PortScanner()
    
    def get_description(self):
        return "Detect services running on open ports"
    
    def get_help(self):
        return """
        Service Detection Module
        
        Usage: netswiss service_detector [options] <target>
        
        Options:
          --ports PORTS      Port range to scan (e.g., 1-1024, 22,80,443) [default: common]
          --timeout SECONDS  Timeout for responses [default: 5.0]
          --intensity LEVEL  Scan intensity (light, normal, aggressive) [default: normal]
          
        Examples:
          netswiss service_detector 192.168.1.10
          netswiss service_detector --ports 22,80,443 10.0.0.5
          netswiss service_detector --intensity aggressive 192.168.1.1
        """
    
    def run(self, target: str, ports: str = 'common', intensity: str = 'normal', **kwargs) -> Dict[str, Any]:
        """
        Detect services on target host.
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (e.g., 1-1024, 22,80,443, or 'common')
            intensity: Scan intensity (light, normal, aggressive)
            
        Returns:
            Dictionary containing service detection results
        """
        # Override instance config with run parameters
        self.timeout = kwargs.get('timeout', self.timeout)
        
        # Determine port range
        if ports == 'common':
            ports_arg = '-F'  # Fast mode - common ports
        else:
            ports_arg = f'-p {ports}'
        
        # Determine scan intensity
        if intensity == 'light':
            version_arg = '-sV --version-light'
        elif intensity == 'normal':
            version_arg = '-sV'
        elif intensity == 'aggressive':
            version_arg = '-sV --version-all'
        else:
            raise ValueError(f"Unknown intensity level: {intensity}")
        
        # Build arguments for nmap
        args = f"{ports_arg} {version_arg} --host-timeout {int(self.timeout)}s"
        
        try:
            # Run nmap scan
            self.nmapper.scan(hosts=target, arguments=args)
            
            # Process results
            results = {
                'target': target,
                'services': []
            }
            
            # Check if target was scanned
            if target not in self.nmapper.all_hosts():
                return results
            
            # Get all services
            for proto in self.nmapper[target].all_protocols():
                for port in self.nmapper[target][proto].keys():
                    port_info = self.nmapper[target][proto][port]
                    
                    service = {
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }
                    
                    results['services'].append(service)
            
            # Add banner grabbing for common protocols
            for service in results['services']:
                if service['state'] == 'open':
                    banner = self._grab_banner(target, service['port'], service['service'])
                    if banner:
                        service['banner'] = banner
            
            return results
            
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap scan failed: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Service detection failed: {str(e)}")
    
    def _grab_banner(self, ip: str, port: int, service_name: str) -> Optional[str]:
        """Attempt to grab banner from service."""
        if service_name in ['http', 'https']:
            return self._http_banner(ip, port, service_name == 'https')
        elif service_name in ['ssh', 'ftp', 'smtp', 'pop3', 'imap']:
            return self._socket_banner(ip, port)
        
        return None
    
    def _socket_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner using raw socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((ip, port))
            
            # Some services don't send banner until they receive something
            sock.send(b'\r\n')
            
            # Receive banner
            banner = sock.recv(1024)
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        except:
            pass
        
        return None
    
    def _http_banner(self, ip: str, port: int, is_https: bool = False) -> Optional[str]:
        """Grab HTTP server header."""
        try:
            import http.client
            
            if is_https:
                conn = http.client.HTTPSConnection(ip, port, timeout=2.0, context=ssl._create_unverified_context())
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=2.0)
            
            conn.request('HEAD', '/')
            response = conn.getresponse()
            
            server = response.getheader('Server')
            conn.close()
            
            return server
        except:
            pass
        
        return None
