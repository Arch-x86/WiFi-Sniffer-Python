import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import csv
import os
import logging
from typing import Optional

from sniffer_core import Sniffer, get_interfaces

logger = logging.getLogger(__name__)

PROTO_COLORS = {
    "TCP":  "#e8f4fd",
    "HTTP": "#fff3cd",
    "UDP":  "#f3e5f5",
    "DNS":  "#e8f5e9",
    "ICMP": "#fce4ec",
    "ARP":  "#fff8e1",
}

COLUMNS = [
    ("time",     "Time",        90),
    ("protocol", "Protocol",    72),
    ("src",      "Source",     170),
    ("dst",      "Destination",170),
    ("length",   "Len",         52),
    ("info",     "Info",       380),
]

class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("🔍 Packet Sniffer")
        self.root.geometry("1100x700")
        self.root.minsize(800, 500)

        self._sniffer: Optional[Sniffer] = None
        self._packets: list[dict] = []   # master list of all captured packets
        self._autoscroll = True

        self._apply_theme()
        self._build_toolbar()
        self._build_filter_bar()
        self._build_packet_list()
        self._build_detail_panel()
        self._build_statusbar()

        self._refresh_interfaces()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
    def _apply_theme(self) -> None:
        style = ttk.Style(self.root)
        for name in ("clam", "alt", "default"):
            if name in style.theme_names():
                style.theme_use(name)
                break
        style.configure("Treeview", rowheight=22, font=("Courier", 9))
        style.configure("Treeview.Heading", font=("Helvetica", 9, "bold"))
