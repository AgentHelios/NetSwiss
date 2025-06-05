"""
Network Swiss Army Knife - Setup Script
"""

from setuptools import setup, find_packages

setup(
    name="netswiss",
    version="1.0.0",
    description="Network Swiss Army Knife - A comprehensive network analysis toolkit",
    author="Manus AI",
    packages=find_packages(),
    install_requires=[
        "scapy",
        "python-nmap",
        "dnspython",
        "netifaces",
        "networkx",
        "matplotlib",
        "colorama",
        "requests",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "netswiss=netswiss.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.6",
)
