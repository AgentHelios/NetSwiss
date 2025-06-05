"""
Network Swiss Army Knife - Module Registration
"""

from importlib import import_module
from typing import Dict, Type

# Base module class
class NetworkModule:
    """Base class for all network modules."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.name = self.__class__.__name__
        
    def run(self, *args, **kwargs):
        """Execute the module's primary function."""
        raise NotImplementedError
        
    def get_description(self):
        """Return module description."""
        raise NotImplementedError
        
    def get_help(self):
        """Return module help text."""
        raise NotImplementedError

# Module registry
_modules: Dict[str, Type[NetworkModule]] = {}

def register_module(name, module_class):
    """Register a module with the system."""
    if not issubclass(module_class, NetworkModule):
        raise TypeError(f"Module {name} must inherit from NetworkModule")
    _modules[name] = module_class
    return module_class

def get_module(name):
    """Get a module by name."""
    if name not in _modules:
        raise ValueError(f"Module {name} not found")
    return _modules[name]

def get_all_modules():
    """Get all registered modules."""
    return _modules.copy()

def load_modules():
    """Load all modules."""
    # Import modules to trigger registration
    from . import network_scanner
    from . import port_scanner
    from . import service_detector
    from . import os_fingerprinter
    from . import vulnerability_scanner
    from . import dns_recon
    from . import network_mapper
