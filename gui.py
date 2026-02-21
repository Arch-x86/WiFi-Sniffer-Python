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

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(6, 4))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="🔍 Packet Sniffer", font=("Helvetica", 11, "bold")).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)

        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT, padx=(0, 4))
        self._iface_var = tk.StringVar()
        self._iface_combo = ttk.Combobox(bar, textvariable=self._iface_var, width=16, state="readonly")
        self._iface_combo.pack(side=tk.LEFT, padx=(0, 10))

        self._btn_start = ttk.Button(bar, text="▶ Start", command=self._start, width=9)
        self._btn_start.pack(side=tk.LEFT, padx=2)

        self._btn_stop = ttk.Button(bar, text="⏹ Stop", command=self._stop, width=9, state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=2)

        ttk.Button(bar, text="🗑 Clear", command=self._clear, width=9).pack(side=tk.LEFT, padx=2)
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Button(bar, text="💾 Export", command=self._export, width=9).pack(side=tk.LEFT, padx=2)
    
    def _build_filter_bar(self) -> None:
        bar = ttk.LabelFrame(self.root, text="Filter", padding=(6, 3))
        bar.pack(fill=tk.X, padx=6, pady=(0, 2))

        ttk.Label(bar, text="BPF:").pack(side=tk.LEFT)
        self._bpf_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self._bpf_var, width=22).pack(side=tk.LEFT, padx=(2, 12))

        ttk.Label(bar, text="Protocol:").pack(side=tk.LEFT)
        self._proto_var = tk.StringVar()
        ttk.Combobox(bar, textvariable=self._proto_var, width=10, state="readonly",
                     values=["", "TCP", "UDP", "HTTP", "DNS", "ICMP", "ARP", "IPv4", "IPv6"]
                     ).pack(side=tk.LEFT, padx=(2, 12))

        ttk.Label(bar, text="Search:").pack(side=tk.LEFT)
        self._search_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self._search_var, width=18)
        entry.pack(side=tk.LEFT, padx=(2, 8))
        entry.bind("<Return>", lambda _: self._apply_display_filter())

        ttk.Button(bar, text="Apply", command=self._apply_display_filter, width=7).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Clear", command=self._clear_display_filter, width=7).pack(side=tk.LEFT, padx=2)

    def _build_packet_list(self) -> None:
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=2)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        cols = [c[0] for c in COLUMNS]
        self._tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")

        for col_id, heading, width in COLUMNS:
            self._tree.heading(col_id, text=heading)
            self._tree.column(col_id, width=width, minwidth=40, stretch=(col_id == "info"))

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._tree.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Row colour tags
        for proto, colour in PROTO_COLORS.items():
            self._tree.tag_configure(proto, background=colour)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
    
        menu = tk.Menu(self._tree, tearoff=False)
        menu.add_command(label="Copy row", command=self._copy_selected)
        menu.add_separator()
        self._scroll_var = tk.BooleanVar(value=True)
        menu.add_checkbutton(label="Auto-scroll", variable=self._scroll_var,
                             command=lambda: setattr(self, "_autoscroll", self._scroll_var.get()))
        self._tree.bind("<Button-3>", lambda e: menu.post(e.x_root, e.y_root))

    def _build_detail_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Packet Detail", padding=(4, 4))
        frame.pack(fill=tk.X, padx=6, pady=(0, 2))

        self._detail = tk.Text(frame, height=6, wrap=tk.WORD,
                                font=("Courier", 9), state=tk.DISABLED,
                                bg="#1e1e1e", fg="#d4d4d4", relief=tk.FLAT)
        self._detail.pack(fill=tk.X)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, relief=tk.SUNKEN, padding=(6, 2))
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_var = tk.StringVar(value="● Idle")
        self._count_var = tk.StringVar(value="Captured: 0")
        self._shown_var = tk.StringVar(value="Shown: 0")

        ttk.Label(bar, textvariable=self._status_var, width=14).pack(side=tk.LEFT)
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Label(bar, textvariable=self._count_var, width=14).pack(side=tk.LEFT)
        ttk.Label(bar, textvariable=self._shown_var, width=14).pack(side=tk.LEFT)
    
    def _refresh_interfaces(self) -> None:
        ifaces = get_interfaces()
        self._iface_combo["values"] = ifaces
        if ifaces:
            self._iface_var.set(ifaces[0])
    
    def _start(self) -> None:
        iface = self._iface_var.get() or None
        bpf = self._bpf_var.get().strip()

        try:
            self._sniffer = Sniffer(iface=iface, bpf=bpf)
            self._sniffer.start()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
            return

        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._iface_combo.config(state=tk.DISABLED)
        self._status_var.set("🟢 Running")
        self._poll()

    def _stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._iface_combo.config(state="readonly")
        self._status_var.set("🔴 Stopped")

    def _clear(self) -> None:
        self._stop()
        self._packets.clear()
        self._tree.delete(*self._tree.get_children())
        self._set_detail("")
        self._update_counts()

    def _on_close(self) -> None:
        self._stop()
        self.root.destroy()

    def _poll(self) -> None:
        if not self._sniffer:
            return

        for _ in range(50):   # drain up to 50 packets per tick
            try:
                pkt = self._sniffer.queue.get_nowait()
            except Exception:
                break
            self._packets.append(pkt)
            if self._matches_display_filter(pkt):
                self._insert_row(pkt)

        self._update_counts()

        if self._sniffer.is_running():
            self.root.after(100, self._poll)

    def _matches_display_filter(self, pkt: dict) -> bool:
        proto = self._proto_var.get()
        keyword = self._search_var.get().strip().lower()

        if proto and pkt.get("protocol", "") != proto:
            return False
        if keyword:
            haystack = " ".join(str(v) for v in pkt.values()).lower()
            if keyword not in haystack:
                return False
        return True

    def _apply_display_filter(self) -> None:
        self._tree.delete(*self._tree.get_children())
        for pkt in self._packets:
            if self._matches_display_filter(pkt):
                self._insert_row(pkt)
        self._update_counts()

    def _clear_display_filter(self) -> None:
        self._proto_var.set("")
        self._search_var.set("")
        self._apply_display_filter()

    # ------------------------------------------------------------------
    # Treeview helpers
    # ------------------------------------------------------------------

    def _insert_row(self, pkt: dict) -> None:
        tag = pkt.get("protocol", "OTHER")
        iid = self._tree.insert("", tk.END, tags=(tag,), values=(
            pkt["time"], pkt["protocol"],
            pkt["src"], pkt["dst"],
            pkt["length"], pkt["info"],
        ))
        if self._autoscroll:
            self._tree.see(iid)

    def _on_select(self, _=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        row_idx = self._tree.index(sel[0])  # position in visible tree
        # Find the matching packet in filtered list
        visible = [p for p in self._packets if self._matches_display_filter(p)]
        if row_idx < len(visible):
            self._show_detail(visible[row_idx])

    def _show_detail(self, pkt: dict) -> None:
        lines = [f"  {k:<10}: {v}" for k, v in pkt.items() if v not in (None, "")]
        self._set_detail("\n".join(lines))

    def _set_detail(self, text: str) -> None:
        self._detail.config(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        self._detail.insert(tk.END, text)
        self._detail.config(state=tk.DISABLED)

    def _copy_selected(self) -> None:
        sel = self._tree.selection()
        if sel:
            vals = self._tree.item(sel[0])["values"]
            self.root.clipboard_clear()
            self.root.clipboard_append("\t".join(str(v) for v in vals))

    def _update_counts(self) -> None:
        total = len(self._packets)
        shown = len(self._tree.get_children())
        self._count_var.set(f"Captured: {total:,}")
        self._shown_var.set(f"Shown: {shown:,}")
        


