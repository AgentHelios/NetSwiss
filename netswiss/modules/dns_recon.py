"""
Network Swiss Army Knife - DNS Reconnaissance Module
"""

import socket
import time
from typing import Dict, Any, List, Optional, Union

import dns.resolver
import dns.zone
import dns.query
import dns.reversename

from .. import modules

@modules.register_module("dns_recon", modules.NetworkModule)
class DNSRecon(modules.NetworkModule):
    """DNS reconnaissance functionality."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 5.0)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
    
    def get_description(self):
        return "Perform DNS reconnaissance on target domains"
    
    def get_help(self):
        return """
        DNS Reconnaissance Module
        
        Usage: netswiss dns_recon [options] <target>
        
        Options:
          --type TYPE        Type of DNS query (all, a, mx, ns, txt, soa, ptr, zone) [default: all]
          --timeout SECONDS  Timeout for responses [default: 5.0]
          --nameserver NS    Custom nameserver to use
          --wordlist FILE    Wordlist for subdomain enumeration
          
        Examples:
          netswiss dns_recon example.com
          netswiss dns_recon --type mx example.com
          netswiss dns_recon --nameserver 8.8.8.8 example.com
        """
    
    def run(self, target: str, query_type: str = 'all', nameserver: Optional[str] = None, 
            wordlist: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Perform DNS reconnaissance on target domain.
        
        Args:
            target: Domain name or IP address to query
            query_type: Type of DNS query (all, a, mx, ns, txt, soa, ptr, zone)
            nameserver: Custom nameserver to use
            wordlist: Path to wordlist file for subdomain enumeration
            
        Returns:
            Dictionary containing DNS reconnaissance results
        """
        # Override instance config with run parameters
        self.timeout = kwargs.get('timeout', self.timeout)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        # Set custom nameserver if provided
        if nameserver:
            self.resolver.nameservers = [nameserver]
        
        # Initialize results
        results = {
            'target': target,
            'query_type': query_type,
            'nameserver': nameserver or ', '.join(self.resolver.nameservers),
            'records': {}
        }
        
        # Check if target is an IP address for reverse lookup
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
        
        # Perform DNS queries based on type
        if is_ip and (query_type == 'all' or query_type == 'ptr'):
            # Reverse DNS lookup
            results['records']['ptr'] = self._ptr_lookup(target)
        else:
            # Forward DNS lookups
            if query_type == 'all' or query_type == 'a':
                results['records']['a'] = self._query_records(target, 'A')
                results['records']['aaaa'] = self._query_records(target, 'AAAA')
            
            if query_type == 'all' or query_type == 'mx':
                results['records']['mx'] = self._query_records(target, 'MX')
            
            if query_type == 'all' or query_type == 'ns':
                results['records']['ns'] = self._query_records(target, 'NS')
            
            if query_type == 'all' or query_type == 'txt':
                results['records']['txt'] = self._query_records(target, 'TXT')
            
            if query_type == 'all' or query_type == 'soa':
                results['records']['soa'] = self._query_records(target, 'SOA')
            
            if query_type == 'all' or query_type == 'cname':
                results['records']['cname'] = self._query_records(target, 'CNAME')
            
            if query_type == 'all':
                # Additional record types
                results['records']['spf'] = self._query_records(target, 'SPF')
                results['records']['dkim'] = self._query_dkim(target)
                results['records']['dmarc'] = self._query_records(f'_dmarc.{target}', 'TXT')
            
            if query_type == 'zone' or query_type == 'all':
                # Try zone transfer
                results['zone_transfer'] = self._zone_transfer(target)
            
            # Subdomain enumeration if wordlist provided
            if wordlist:
                results['subdomains'] = self._enumerate_subdomains(target, wordlist)
        
        return results
    
    def _query_records(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """Query DNS records of specified type."""
        results = []
        
        try:
            answers = self.resolver.resolve(domain, record_type)
            
            for rdata in answers:
                record = {'value': str(rdata)}
                
                # Add specific fields based on record type
                if record_type == 'MX':
                    record['preference'] = rdata.preference
                    record['exchange'] = str(rdata.exchange)
                elif record_type == 'SOA':
                    record['mname'] = str(rdata.mname)
                    record['rname'] = str(rdata.rname)
                    record['serial'] = rdata.serial
                    record['refresh'] = rdata.refresh
                    record['retry'] = rdata.retry
                    record['expire'] = rdata.expire
                    record['minimum'] = rdata.minimum
                
                results.append(record)
        except dns.resolver.NXDOMAIN:
            pass  # Domain does not exist
        except dns.resolver.NoAnswer:
            pass  # No records of this type
        except Exception as e:
            results.append({'error': str(e)})
        
        return results
    
    def _ptr_lookup(self, ip: str) -> List[Dict[str, Any]]:
        """Perform reverse DNS lookup."""
        results = []
        
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            
            for rdata in answers:
                results.append({'value': str(rdata)})
        except Exception as e:
            results.append({'error': str(e)})
        
        return results
    
    def _zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt zone transfer."""
        results = {
            'success': False,
            'nameservers': [],
            'records': []
        }
        
        try:
            # Get nameservers
            ns_records = self._query_records(domain, 'NS')
            nameservers = [record['value'] for record in ns_records]
            results['nameservers'] = nameservers
            
            # Try zone transfer with each nameserver
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=self.timeout))
                    
                    results['success'] = True
                    
                    # Extract records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                results['records'].append({
                                    'name': str(name),
                                    'ttl': rdataset.ttl,
                                    'class': dns.rdataclass.to_text(rdataset.rdclass),
                                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                                    'value': str(rdata)
                                })
                    
                    # If successful with one nameserver, break
                    break
                except:
                    continue
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _query_dkim(self, domain: str) -> List[Dict[str, Any]]:
        """Query DKIM records."""
        results = []
        
        # Common DKIM selectors
        selectors = ['default', 'dkim', 'mail', 'email', 'selector1', 'selector2', 'k1']
        
        for selector in selectors:
            dkim_domain = f'{selector}._domainkey.{domain}'
            dkim_records = self._query_records(dkim_domain, 'TXT')
            
            if dkim_records and not any('error' in record for record in dkim_records):
                for record in dkim_records:
                    record['selector'] = selector
                    results.append(record)
        
        return results
    
    def _enumerate_subdomains(self, domain: str, wordlist_path: str) -> List[Dict[str, Any]]:
        """Enumerate subdomains using wordlist."""
        results = []
        
        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            for subdomain in subdomains:
                fqdn = f'{subdomain}.{domain}'
                
                try:
                    answers = self.resolver.resolve(fqdn, 'A')
                    
                    # If we get here, subdomain exists
                    result = {
                        'subdomain': fqdn,
                        'ips': [str(rdata) for rdata in answers]
                    }
                    
                    # Try to get CNAME
                    try:
                        cname_answers = self.resolver.resolve(fqdn, 'CNAME')
                        result['cname'] = str(cname_answers[0])
                    except:
                        pass
                    
                    results.append(result)
                except:
                    continue
        except Exception as e:
            results.append({'error': str(e)})
        
        return results
