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