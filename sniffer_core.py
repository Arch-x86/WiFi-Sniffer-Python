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

def parse_packet(pkt) -> dict:
    """Convert a raw Scapy packet into a plain dict."""
    now = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    rec = {
        "time": now,
        "protocol": "OTHER",
        "src": "",
        "dst": "",
        "sport": None,
        "dport": None,
        "length": len(pkt),
        "flags": "",
        "service": "",
        "info": "",
    }

    try:
        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            rec["protocol"] = "ARP"
            rec["src"] = arp.psrc
            rec["dst"] = arp.pdst
            rec["info"] = f"{'Request' if arp.op == 1 else 'Reply'}: {arp.psrc} → {arp.pdst}"
            return rec
        
        if pkt.haslayer(IP):
            ip = pkt[IP]
            rec["src"] = ip.src
            rec["dst"] = ip.dst

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                rec["protocol"] = "TCP"
                rec["sport"] = tcp.sport
                rec["dport"] = tcp.dport
                flags = "+".join(v for k, v in TCP_FLAGS.items() if k in str(tcp.flags))
                rec["flags"] = flags

                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)[:256]
                    text = payload.decode("utf-8", errors="replace")
                    if any(text.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                        rec["protocol"] = "HTTP"
                        rec["info"] = text.split("\r\n")[0]

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                rec["sport"] = udp.sport
                rec["dport"] = udp.dport

                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    rec["protocol"] = "DNS"
                    qname = ""
                    if dns.qd:
                        try:
                            qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                        except Exception:
                            pass
                    direction = "Response" if dns.qr else "Query"
                    rec["info"] = f"DNS {direction}: {qname}"
                else:
                    rec["protocol"] = "UDP"

            elif pkt.haslayer(ICMP):
                rec["protocol"] = "ICMP"
                icmp_type = {0: "Echo Reply", 8: "Echo Request", 3: "Unreachable", 11: "Time Exceeded"}
                rec["info"] = icmp_type.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")

            else:
                rec["protocol"] = "IPv4"

        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            rec["src"] = ip6.src
            rec["dst"] = ip6.dst
            rec["protocol"] = "IPv6"

        for port in (rec["dport"], rec["sport"]):
            if port in SERVICES:
                rec["service"] = SERVICES[port]
                break

        if not rec["info"]:
            sp = f":{rec['sport']}" if rec["sport"] else ""
            dp = f":{rec['dport']}" if rec["dport"] else ""
            svc = f" [{rec['service']}]" if rec["service"] else ""
            fl = f" [{rec['flags']}]" if rec["flags"] else ""
            rec["info"] = f"{rec['src']}{sp} → {rec['dst']}{dp}{svc}{fl}"

    except Exception as e:
        rec["info"] = f"[parse error: {e}]"

    return rec


