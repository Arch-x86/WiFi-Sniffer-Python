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