import argparse
import logging
import sys

def main():
    parser = argparse.ArgumentParser(description="WiFi / Packet Sniffer")
    parser.add_argument("--no-gui", action="store_true", help="CLI mode")
    parser.add_argument("--iface", "-i", default=None, help="Network interface")
    parser.add_argument("--bpf", "-f", default="", help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

     # ── Run tests ──────────────────────────────────────────────────────────
    if args.test:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName("tests")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

       # ── Privilege warning ──────────────────────────────────────────────────
    import os
    is_root = (os.name == "nt") or (os.geteuid() == 0)
    if not is_root:
        print("⚠  Not running as root/admin. Capture may fail.")
        print("   Linux/macOS: sudo python main.py")
        print("   Windows: run terminal as Administrator\n")

    # ── CLI mode ───────────────────────────────────────────────────────────
    if args.no_gui:
        import signal
        from sniffer_core import Sniffer, parse_packet

        sniffer = Sniffer(iface=args.iface, bpf=args.bpf)

        def _on_signal(sig, frame):
            print(f"\nStopping... {sniffer.total} packets captured.")
            sniffer.stop()

        signal.signal(signal.SIGINT, _on_signal)

        print(f"Sniffing on {args.iface or 'default'!r}  BPF: {args.bpf or '(none)'}")
        print("Press Ctrl+C to stop.\n")
        sniffer.start()

        try:
            while sniffer.is_running():
                try:
                    pkt = sniffer.queue.get(timeout=0.2)
                    print(f"[{pkt['time']}] {pkt['protocol']:6s}  {pkt['info']}")
                except Exception:
                    pass
        except KeyboardInterrupt:
            sniffer.stop()

        return
    
      # ── GUI mode ───────────────────────────────────────────────────────────
    try:
        import tkinter as tk
    except ImportError:
        print("tkinter not available. Install it (e.g. sudo apt install python3-tk)")
        sys.exit(1)

    from gui import App
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
