"""Detectors package for identifying specific threat patterns."""

from .exfiltration import ExfiltrationDetector
from .phishing import PhishingDetector

__all__ = ['ExfiltrationDetector', 'PhishingDetector']

