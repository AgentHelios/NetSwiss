"""
Network Swiss Army Knife - Network Mapper Module
"""

import ipaddress
import socket
import time
from typing import Dict, Any, List, Optional, Tuple, Set

import networkx as nx
import matplotlib.pyplot as plt
import scapy.all as scapy

from .. import modules

@modules.register_module("network_mapper", modules.NetworkModule)
class NetworkMapper(modules.NetworkModule):
    """Network mapping and visualization functionality."""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 5.0)
        self.max_hops = config.get('max_hops', 30)
        self.max_threads = config.get('max_threads', 50)
    
    def get_description(self):
        return "Map and visualize network topology"
    
    def get_help(self):
        return """
        Network Mapper Module
        
        Usage: netswiss network_mapper [options] <target>
        
        Options:
          --method METHOD    Mapping method (traceroute, scan, combined) [default: combined]
          --timeout SECONDS  Timeout for responses [default: 5.0]
          --max-hops NUM     Maximum number of hops for traceroute [default: 30]
          --output FILE      Output file for network map image [default: network_map.png]
          --format FORMAT    Output format (png, pdf, svg) [default: png]
          
        Examples:
          netswiss network_mapper 192.168.1.0/24
          netswiss network_mapper --method traceroute example.com
          netswiss network_mapper --output network_map.pdf --format pdf 10.0.0.0/24
        """
    
    def run(self, target: str, method: str = 'combined', output: str = 'network_map.png', 
            format: str = 'png', **kwargs) -> Dict[str, Any]:
        """
        Map and visualize network topology.
        
        Args:
            target: IP address, hostname, or network in CIDR notation
            method: Mapping method (traceroute, scan, combined)
            output: Output file for network map image
            format: Output format (png, pdf, svg)
            
        Returns:
            Dictionary containing network mapping results and path to visualization
        """
        # Override instance config with run parameters
        self.timeout = kwargs.get('timeout', self.timeout)
        self.max_hops = kwargs.get('max_hops', self.max_hops)
        
        # Initialize graph
        G = nx.Graph()
        
        # Initialize results
        results = {
            'target': target,
            'method': method,
            'nodes': [],
            'edges': [],
            'visualization': output
        }
        
        # Determine if target is a network or single host
        try:
            network = ipaddress.ip_network(target, strict=False)
            is_network = True
        except ValueError:
            is_network = False
            # Try to resolve hostname
            try:
                ip = socket.gethostbyname(target)
                target_ip = ip
            except socket.gaierror:
                raise ValueError(f"Could not resolve hostname: {target}")
        
        # Perform mapping based on method
        if method == 'traceroute' or method == 'combined':
            if is_network:
                # For networks, trace route to a few key hosts
                sample_hosts = self._sample_network(network)
                for host in sample_hosts:
                    trace_results = self._traceroute(str(host))
                    self._add_trace_to_graph(G, trace_results)
                    results['nodes'].extend([node for node in trace_results if node not in results['nodes']])
            else:
                # For single host, trace route to it
                trace_results = self._traceroute(target_ip)
                self._add_trace_to_graph(G, trace_results)
                results['nodes'].extend(trace_results)
        
        if method == 'scan' or method == 'combined':
            if is_network:
                # For networks, scan the network
                scan_results = self._scan_network(network)
                self._add_scan_to_graph(G, scan_results)
                
                # Add nodes and edges to results
                for host, neighbors in scan_results.items():
                    if host not in results['nodes']:
                        results['nodes'].append(host)
                    
                    for neighbor in neighbors:
                        if neighbor not in results['nodes']:
                            results['nodes'].append(neighbor)
            else:
                # For single host, scan local network
                try:
                    # Get local network from target IP
                    ip_obj = ipaddress.ip_address(target_ip)
                    if ip_obj.is_private:
                        # Assume /24 network for private IP
                        network_str = f"{target_ip.rsplit('.', 1)[0]}.0/24"
                        local_network = ipaddress.ip_network(network_str, strict=False)
                        
                        scan_results = self._scan_network(local_network)
                        self._add_scan_to_graph(G, scan_results)
                        
                        # Add nodes and edges to results
                        for host, neighbors in scan_results.items():
                            if host not in results['nodes']:
                                results['nodes'].append(host)
                            
                            for neighbor in neighbors:
                                if neighbor not in results['nodes']:
                                    results['nodes'].append(neighbor)
                except:
                    # If we can't determine local network, skip scan
                    pass
        
        # Extract edges from graph
        for u, v in G.edges():
            results['edges'].append((u, v))
        
        # Generate visualization
        self._visualize_network(G, output, format)
        
        return results
    
    def _traceroute(self, target: str) -> List[str]:
        """Perform traceroute to target."""
        hops = []
        
        for ttl in range(1, self.max_hops + 1):
            # Create packet with specific TTL
            packet = scapy.IP(dst=target, ttl=ttl) / scapy.ICMP()
            
            # Send packet and wait for response
            reply = scapy.sr1(packet, timeout=self.timeout, verbose=False)
            
            if reply is None:
                # No response
                hops.append(f"*")
            else:
                # Got response
                hops.append(reply.src)
                
                # If we reached the target, stop
                if reply.src == target:
                    break
        
        # Filter out unknown hops
        return [hop for hop in hops if hop != "*"]
    
    def _scan_network(self, network: ipaddress.IPv4Network) -> Dict[str, List[str]]:
        """Scan network to discover hosts and connections."""
        hosts = {}
        
        # First, discover hosts on the network
        discovered_hosts = self._discover_hosts(network)
        
        # Then, for each host, try to determine connections
        for host in discovered_hosts:
            neighbors = self._discover_neighbors(host)
            hosts[host] = neighbors
        
        return hosts
    
    def _discover_hosts(self, network: ipaddress.IPv4Network) -> List[str]:
        """Discover hosts on network using ARP scan."""
        discovered_hosts = []
        
        # Create ARP request packets for all hosts in the network
        for ip in network.hosts():
            ip_str = str(ip)
            
            # Send ARP request and wait for response
            arp_request = scapy.ARP(pdst=ip_str)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            
            # Send packet and get response
            answered, _ = scapy.srp(packet, timeout=self.timeout, verbose=False)
            
            for _, response in answered:
                discovered_hosts.append(response.psrc)
        
        return discovered_hosts
    
    def _discover_neighbors(self, host: str) -> List[str]:
        """Discover network neighbors of a host."""
        neighbors = []
        
        # Common ports to check for connections
        ports = [22, 23, 80, 443, 445, 3389]
        
        for port in ports:
            # Create SYN packet
            syn_packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = scapy.sr1(syn_packet, timeout=self.timeout, verbose=False)
            
            if response and response.haslayer(scapy.TCP):
                # Check if SYN-ACK received (flags 0x12)
                if response[scapy.TCP].flags == 0x12:
                    # Send RST to close connection
                    rst_packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="R")
                    scapy.send(rst_packet, verbose=False)
                    
                    # Try to get source route
                    route_trace = self._traceroute(host)
                    if len(route_trace) > 1:
                        # Add intermediate hops as neighbors
                        for hop in route_trace[:-1]:
                            if hop not in neighbors and hop != host:
                                neighbors.append(hop)
        
        return neighbors
    
    def _sample_network(self, network: ipaddress.IPv4Network) -> List[ipaddress.IPv4Address]:
        """Sample a few key hosts from network for traceroute."""
        samples = []
        
        # Always include network address (first address)
        samples.append(network.network_address + 1)
        
        # Include broadcast address (last address)
        samples.append(network.broadcast_address - 1)
        
        # Include a few addresses in between
        network_size = network.num_addresses
        if network_size > 4:
            step = network_size // 4
            for i in range(1, 4):
                samples.append(network.network_address + (i * step))
        
        return samples
    
    def _add_trace_to_graph(self, G: nx.Graph, trace: List[str]) -> None:
        """Add traceroute results to graph."""
        for i in range(len(trace) - 1):
            G.add_edge(trace[i], trace[i + 1])
    
    def _add_scan_to_graph(self, G: nx.Graph, scan_results: Dict[str, List[str]]) -> None:
        """Add network scan results to graph."""
        for host, neighbors in scan_results.items():
            for neighbor in neighbors:
                G.add_edge(host, neighbor)
    
    def _visualize_network(self, G: nx.Graph, output: str, format: str) -> None:
        """Generate network visualization."""
        plt.figure(figsize=(12, 8))
        
        # Use spring layout for graph
        pos = nx.spring_layout(G)
        
        # Draw nodes and edges
        nx.draw(G, pos, with_labels=True, node_color='skyblue', 
                node_size=1500, edge_color='gray', linewidths=1, 
                font_size=10, font_weight='bold')
        
        # Add title
        plt.title("Network Topology Map", fontsize=15)
        
        # Save figure
        plt.tight_layout()
        plt.savefig(output, format=format)
        plt.close()
