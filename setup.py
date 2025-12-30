"""Setup script for Network Packet Investigator."""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='network-packet-investigator',
    version='1.0.0',
    author='Security Analyst',
    description='Advanced PCAP analysis tool for detecting suspicious network activities',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'python-whois>=0.8.0',
        'tldextract>=5.0.0',
    ],
    entry_points={
        'console_scripts': [
            'npi=main:main',  # Updated to point to main.py
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.8',
)
