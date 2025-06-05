"""
Network Swiss Army Knife - Main CLI
"""

import argparse
import json
import sys
import os
import textwrap
from typing import Dict, Any, List, Optional

from . import modules

class NetSwissCLI:
    """Main command-line interface for Network Swiss Army Knife."""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Network Swiss Army Knife - A comprehensive network analysis toolkit',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent('''
                Examples:
                  netswiss network_scanner 192.168.1.0/24
                  netswiss port_scanner --ports 22,80,443 10.0.0.5
                  netswiss service_detector example.com
                  netswiss os_fingerprinter --method ttl 192.168.1.1
                  netswiss vulnerability_scanner --level aggressive 192.168.1.10
                  netswiss dns_recon --type mx example.com
                  netswiss network_mapper --output map.png 192.168.1.0/24
            ''')
        )
        
        # Global arguments
        self.parser.add_argument('--version', action='version', version='Network Swiss Army Knife v1.0.0')
        self.parser.add_argument('--verbose', '-v', action='count', default=0, help='Increase output verbosity')
        self.parser.add_argument('--quiet', '-q', action='store_true', help='Suppress non-essential output')
        self.parser.add_argument('--output', '-o', help='Output file for results (default: stdout)')
        self.parser.add_argument('--format', '-f', choices=['text', 'json', 'yaml'], default='text',
                                help='Output format (default: text)')
        
        # Create subparsers for each module
        self.subparsers = self.parser.add_subparsers(dest='module', help='Module to run')
        
        # Load modules
        self._load_modules()
    
    def _load_modules(self):
        """Load all available modules and create subparsers for them."""
        # Import modules to trigger registration
        from .modules import network_scanner
        from .modules import port_scanner
        from .modules import service_detector
        from .modules import os_fingerprinter
        from .modules import vulnerability_scanner
        from .modules import dns_recon
        from .modules import network_mapper
        
        # Get all registered modules
        all_modules = modules.get_all_modules()
        
        # Create subparser for each module
        for name, module_class in all_modules.items():
            # Create instance to get help text
            instance = module_class()
            
            # Create subparser
            subparser = self.subparsers.add_parser(
                name, 
                help=instance.get_description(),
                formatter_class=argparse.RawDescriptionHelpFormatter,
                description=instance.get_help()
            )
            
            # Add target argument (common to all modules)
            subparser.add_argument('target', help='Target IP, hostname, or network')
            
            # Add module-specific arguments based on module's run method
            self._add_module_arguments(subparser, module_class)
    
    def _add_module_arguments(self, subparser, module_class):
        """Add module-specific arguments to subparser based on module's run method."""
        import inspect
        
        # Get run method signature
        signature = inspect.signature(module_class.run)
        
        # Add arguments for each parameter (except self and target)
        for param_name, param in signature.parameters.items():
            if param_name in ('self', 'target'):
                continue
            
            # Get default value and annotation
            default = param.default if param.default is not inspect.Parameter.empty else None
            annotation = param.annotation if param.annotation is not inspect.Parameter.empty else Any
            
            # Determine argument type
            arg_type = str
            if annotation in (int, float, bool):
                arg_type = annotation
            
            # Create argument
            if param.default is inspect.Parameter.empty:
                # Required argument
                subparser.add_argument(f'--{param_name.replace("_", "-")}', 
                                      dest=param_name,
                                      type=arg_type,
                                      required=True,
                                      help=f'Required: {param_name}')
            else:
                # Optional argument with default
                if isinstance(default, bool):
                    # Boolean flag
                    subparser.add_argument(f'--{param_name.replace("_", "-")}',
                                          dest=param_name,
                                          action='store_true' if not default else 'store_false',
                                          help=f'Flag: {param_name} (default: {default})')
                else:
                    # Regular argument with default
                    subparser.add_argument(f'--{param_name.replace("_", "-")}',
                                          dest=param_name,
                                          type=arg_type,
                                          default=default,
                                          help=f'{param_name} (default: {default})')
    
    def parse_args(self, args=None):
        """Parse command-line arguments."""
        return self.parser.parse_args(args)
    
    def run(self, args=None):
        """Run the CLI with the given arguments."""
        # Parse arguments
        args = self.parse_args(args)
        
        # Check if a module was specified
        if not args.module:
            self.parser.print_help()
            return 1
        
        try:
            # Get module class
            module_class = modules.get_module(args.module)
            
            # Create module instance
            module_instance = module_class()
            
            # Convert args to dict and remove module and target
            kwargs = vars(args)
            module_name = kwargs.pop('module')
            target = kwargs.pop('target')
            
            # Remove global arguments
            for arg in ('verbose', 'quiet', 'output', 'format'):
                kwargs.pop(arg, None)
            
            # Run module
            if args.verbose > 0 and not args.quiet:
                print(f"Running {module_name} on {target}...", file=sys.stderr)
            
            result = module_instance.run(target, **kwargs)
            
            # Format and output result
            self._output_result(result, args.format, args.output, args.verbose, args.quiet)
            
            return 0
            
        except Exception as e:
            if not args.quiet:
                print(f"Error: {str(e)}", file=sys.stderr)
            return 1
    
    def _output_result(self, result, format_type, output_file, verbose, quiet):
        """Format and output result."""
        # Format result
        if format_type == 'json':
            formatted_result = json.dumps(result, indent=2)
        elif format_type == 'yaml':
            import yaml
            formatted_result = yaml.dump(result, default_flow_style=False)
        else:  # text
            formatted_result = self._format_text(result, verbose)
        
        # Output result
        if output_file:
            with open(output_file, 'w') as f:
                f.write(formatted_result)
            
            if not quiet:
                print(f"Results written to {output_file}", file=sys.stderr)
        else:
            print(formatted_result)
    
    def _format_text(self, result, verbose):
        """Format result as text."""
        lines = []
        
        # Add title
        if 'target' in result:
            lines.append(f"Results for {result['target']}")
            lines.append("=" * len(lines[-1]))
        
        # Format based on module type
        if 'ports_scanned' in result:  # Port scanner
            lines.append(f"Scanned {result['ports_scanned']} ports, found {result['open_ports']} open")
            
            if 'port_details' in result:
                lines.append("\nOpen ports:")
                for port in result['port_details']:
                    lines.append(f"  {port['port']}/{port.get('protocol', 'tcp')}: {port.get('service', 'unknown')}")
        
        elif 'services' in result:  # Service detector
            lines.append(f"Detected {len(result['services'])} services")
            
            if result['services']:
                lines.append("\nServices:")
                for service in result['services']:
                    service_info = f"{service['port']}/{service.get('protocol', 'tcp')}: {service['service']}"
                    if service.get('product'):
                        service_info += f" - {service['product']}"
                        if service.get('version'):
                            service_info += f" {service['version']}"
                    lines.append(f"  {service_info}")
        
        elif 'os_matches' in result:  # OS fingerprinter
            if result['os_matches']:
                lines.append(f"OS detection results ({result.get('method', 'unknown')} method):")
                
                if 'best_os_match' in result:
                    lines.append(f"\nBest match: {result['best_os_match']} (accuracy: {result.get('best_os_accuracy', 'unknown')})")
                
                if verbose > 0:
                    lines.append("\nAll matches:")
                    for match in result['os_matches']:
                        lines.append(f"  {match['name']} (accuracy: {match.get('accuracy', 'unknown')})")
            else:
                lines.append("No OS matches found")
        
        elif 'vulnerabilities' in result:  # Vulnerability scanner
            vuln_count = len(result['vulnerabilities'])
            lines.append(f"Found {vuln_count} potential vulnerabilities")
            
            if 'severity_summary' in result:
                summary = result['severity_summary']
                lines.append("\nSeverity summary:")
                for sev, count in summary.items():
                    if count > 0:
                        lines.append(f"  {sev.capitalize()}: {count}")
            
            if vuln_count > 0:
                lines.append("\nVulnerabilities:")
                for vuln in result['vulnerabilities']:
                    vuln_info = f"{vuln.get('id', 'Unknown')}"
                    if 'severity' in vuln:
                        vuln_info += f" ({vuln['severity'].upper()})"
                    if 'port' in vuln:
                        vuln_info += f" - Port {vuln['port']}"
                    lines.append(f"  {vuln_info}")
                    
                    if verbose > 0 and 'description' in vuln:
                        desc = vuln['description']
                        wrapped = textwrap.fill(desc, width=80, initial_indent="    ", subsequent_indent="    ")
                        lines.append(wrapped)
        
        elif 'records' in result:  # DNS recon
            lines.append(f"DNS reconnaissance results for {result['target']}")
            
            for record_type, records in result['records'].items():
                if records:
                    lines.append(f"\n{record_type.upper()} records:")
                    for record in records:
                        if 'error' in record:
                            lines.append(f"  Error: {record['error']}")
                        else:
                            lines.append(f"  {record.get('value', '')}")
            
            if 'zone_transfer' in result and result['zone_transfer'].get('success'):
                lines.append("\nZone transfer successful!")
                if verbose > 0:
                    lines.append("Zone records:")
                    for record in result['zone_transfer']['records']:
                        lines.append(f"  {record['name']} {record['ttl']} {record['class']} {record['type']} {record['value']}")
            
            if 'subdomains' in result and result['subdomains']:
                lines.append(f"\nDiscovered {len(result['subdomains'])} subdomains:")
                for subdomain in result['subdomains']:
                    if 'error' in subdomain:
                        continue
                    subdomain_info = f"{subdomain['subdomain']}"
                    if 'ips' in subdomain:
                        subdomain_info += f" ({', '.join(subdomain['ips'])})"
                    lines.append(f"  {subdomain_info}")
        
        elif 'nodes' in result and 'edges' in result:  # Network mapper
            lines.append(f"Network mapping results for {result['target']}")
            lines.append(f"Method: {result.get('method', 'unknown')}")
            lines.append(f"Nodes: {len(result['nodes'])}")
            lines.append(f"Edges: {len(result['edges'])}")
            
            if 'visualization' in result:
                lines.append(f"\nVisualization saved to: {result['visualization']}")
            
            if verbose > 0:
                lines.append("\nNodes:")
                for node in result['nodes']:
                    lines.append(f"  {node}")
                
                lines.append("\nConnections:")
                for edge in result['edges']:
                    lines.append(f"  {edge[0]} <-> {edge[1]}")
        
        else:  # Generic or network scanner
            # For network scanner or unknown module type
            if 'ip' in result:
                lines.append(f"IP: {result['ip']}")
            
            if isinstance(result, list):
                # Network scanner returns list of hosts
                lines.append(f"Discovered {len(result)} hosts:")
                for host in result:
                    host_info = f"{host['ip']}"
                    if 'mac' in host and host['mac']:
                        host_info += f" ({host['mac']})"
                    if 'hostname' in host and host['hostname']:
                        host_info += f" - {host['hostname']}"
                    lines.append(f"  {host_info}")
        
        return "\n".join(lines)


def main():
    """Entry point for the CLI."""
    cli = NetSwissCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
