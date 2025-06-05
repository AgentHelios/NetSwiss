"""
Network Swiss Army Knife - OS Fingerprinting Module
"""

import re
from typing import Dict, Any, Optional, List

import nmap
import scapy.all as scapy

from .. import modules

@modules.register_module("os_fingerprinter", modules.NetworkModule)
class OSFingerprinter(modules.NetworkModule):
    """OS fingerprinting functionality."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 5.0)
        self.nmapper = nmap.PortScanner()
    
    def get_description(self):
        return "Identify operating systems of target hosts"
    
    def get_help(self):
        return """
        OS Fingerprinting Module
        
        Usage: netswiss os_fingerprinter [options] <target>
        
        Options:
          --method METHOD    Fingerprinting method (nmap, ttl) [default: nmap]
          --timeout SECONDS  Timeout for responses [default: 5.0]
          --ports PORTS      Ports to use for OS detection [default: common]
          
        Examples:
          netswiss os_fingerprinter 192.168.1.10
          netswiss os_fingerprinter --method ttl 10.0.0.5
          netswiss os_fingerprinter --ports 22,80,443 192.168.1.1
        """
    
    def run(self, target: str, method: str = 'nmap', ports: str = 'common', **kwargs) -> Dict[str, Any]:
        """
        Identify operating system of target host.
        
        Args:
            target: IP address or hostname to scan
            method: Fingerprinting method (nmap, ttl)
            ports: Ports to use for OS detection
            
        Returns:
            Dictionary containing OS detection results
        """
        # Override instance config with run parameters
        self.timeout = kwargs.get('timeout', self.timeout)
        
        # Select fingerprinting method
        if method == 'nmap':
            return self._nmap_fingerprint(target, ports)
        elif method == 'ttl':
            return self._ttl_fingerprint(target)
        else:
            raise ValueError(f"Unknown fingerprinting method: {method}")
    
    def _nmap_fingerprint(self, target: str, ports: str) -> Dict[str, Any]:
        """Perform OS fingerprinting using nmap."""
        # Determine port range
        if ports == 'common':
            ports_arg = '-F'  # Fast mode - common ports
        else:
            ports_arg = f'-p {ports}'
        
        # Build arguments for nmap
        args = f"{ports_arg} -O --osscan-guess --host-timeout {int(self.timeout)}s"
        
        try:
            # Run nmap scan
            self.nmapper.scan(hosts=target, arguments=args)
            
            # Process results
            results = {
                'target': target,
                'method': 'nmap',
                'os_matches': []
            }
            
            # Check if target was scanned
            if target not in self.nmapper.all_hosts():
                return results
            
            # Get OS matches
            if 'osmatch' in self.nmapper[target]:
                for match in self.nmapper[target]['osmatch']:
                    os_match = {
                        'name': match['name'],
                        'accuracy': match['accuracy'],
                        'line': match.get('line', ''),
                        'osclass': []
                    }
                    
                    # Add OS classes
                    if 'osclass' in match:
                        for osclass in match['osclass']:
                            os_match['osclass'].append({
                                'type': osclass.get('type', ''),
                                'vendor': osclass.get('vendor', ''),
                                'osfamily': osclass.get('osfamily', ''),
                                'osgen': osclass.get('osgen', ''),
                                'accuracy': osclass.get('accuracy', '')
                            })
                    
                    results['os_matches'].append(os_match)
            
            # Add best guess
            if results['os_matches']:
                best_match = max(results['os_matches'], key=lambda x: int(x['accuracy']))
                results['best_os_match'] = best_match['name']
                results['best_os_accuracy'] = best_match['accuracy']
            
            return results
            
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap OS scan failed: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"OS fingerprinting failed: {str(e)}")
    
    def _ttl_fingerprint(self, target: str) -> Dict[str, Any]:
        """Perform OS fingerprinting using TTL values."""
        results = {
            'target': target,
            'method': 'ttl',
            'os_matches': []
        }
        
        # TTL reference values
        ttl_references = {
            64: ['Linux', 'Unix', 'macOS'],
            128: ['Windows'],
            255: ['Cisco', 'Network Equipment']
        }
        
        try:
            # Send ICMP echo request
            icmp = scapy.IP(dst=target)/scapy.ICMP()
            response = scapy.sr1(icmp, timeout=self.timeout, verbose=False)
            
            if response and hasattr(response, 'ttl'):
                ttl = response.ttl
                results['ttl'] = ttl
                
                # Find closest TTL reference
                closest_ttl = min(ttl_references.keys(), key=lambda x: abs(x - ttl))
                
                # If TTL is within 5 of a reference value, consider it a match
                if abs(closest_ttl - ttl) <= 5:
                    for os in ttl_references[closest_ttl]:
                        results['os_matches'].append({
                            'name': os,
                            'accuracy': '75',
                            'method': 'TTL analysis'
                        })
                
                # Add best guess
                if results['os_matches']:
                    results['best_os_match'] = results['os_matches'][0]['name']
                    results['best_os_accuracy'] = results['os_matches'][0]['accuracy']
            
            # Try TCP SYN as well
            syn_packet = scapy.IP(dst=target)/scapy.TCP(dport=80, flags="S")
            syn_response = scapy.sr1(syn_packet, timeout=self.timeout, verbose=False)
            
            if syn_response and hasattr(syn_response, 'ttl'):
                results['tcp_ttl'] = syn_response.ttl
            
            return results
            
        except Exception as e:
            raise RuntimeError(f"TTL fingerprinting failed: {str(e)}")
