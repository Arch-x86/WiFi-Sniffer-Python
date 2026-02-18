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

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}

TCP_FLAGS = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}


