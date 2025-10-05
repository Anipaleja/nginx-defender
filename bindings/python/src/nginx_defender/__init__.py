"""nginx-defender Python package."""
__version__ = "2.0.0"
__author__ = "nginx-defender team"
__email__ = "support@nginx-defender.com"

from .core import NginxDefender, ThreatEvent, BlockEvent

__all__ = ["NginxDefender", "ThreatEvent", "BlockEvent"]


def main():
    """CLI entry point."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="nginx-defender Python CLI")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--start", action="store_true", help="Start the defender")
    
    args = parser.parse_args()
    
    if args.start:
        defender = NginxDefender(config_file=args.config)
        defender.start()
    else:
        parser.print_help()
