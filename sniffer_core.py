import queue
import threading
import logging
from datetime import datetime, timezone
from typing import Optional, Callable

logger=logging.getLogger(__name__)

try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.warning("Scapy not installed. Run: pip install scapy")

