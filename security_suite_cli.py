#!/usr/bin/env python3
"""
Security Testing Suite v4.0 - Interactive CLI
Application Traceroute as primary entry point with integrated bypass validation.
SmartCrawler for additional vulnerability discovery.
"""

import sys
import os
import asyncio
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any

# Add paths for all modules
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR / 'Application_tracereout_3.5'))
sys.path.insert(0, str(SCRIPT_DIR / 'SmartCrawler'))

# Try Rich for beautiful CLI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None


def clear_screen():
    """Clear terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗             ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝             ║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝              ║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝               ║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║                ║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝                ║
║                                                                               ║
║                    ████████╗███████╗███████╗████████╗                         ║
║                    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝                         ║
║                       ██║   █████╗  ███████╗   ██║                            ║
║                       ██║   ██╔══╝  ╚════██║   ██║                            ║
║                       ██║   ███████╗███████║   ██║                            ║
║                       ╚═╝   ╚══════╝╚══════╝   ╚═╝                            ║
║                                                                               ║
║              ███████╗██╗   ██╗██╗████████╗███████╗    ██╗   ██╗██╗  ██╗       ║
║              ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝    ██║   ██║██║  ██║       ║
║              ███████╗██║   ██║██║   ██║   █████╗      ██║   ██║███████║       ║
║              ╚════██║██║   ██║██║   ██║   ██╔══╝      ╚██╗ ██╔╝╚════██║       ║
║              ███████║╚██████╔╝██║   ██║   ███████╗     ╚████╔╝     ██║        ║
║              ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝      ╚═══╝      ╚═╝        ║
║                                                                               ║
║         Application Traceroute + SmartCrawler Security Testing Suite         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    if console:
        console.print(Panel(banner, style="bold blue"))
    else:
        print(banner)


def print_menu(has_target: bool = False, target_url: str = None):
    """Print main menu."""
    if console:
        table = Table(title="Main Menu", show_header=False, box=None)
        table.add_column("Option", style="cyan", width=6)
        table.add_column("Description", style="white")

        table.add_row("", "")
        table.add_row("[1]", "Application Traceroute - Stack Analysis & Bypass Discovery")

        if has_target:
            table.add_row("[2]", f"SmartCrawler - Vulnerability Discovery (target: {target_url})")
        else:
            table.add_row("[2]", "SmartCrawler - Vulnerability Discovery")

        table.add_row("", "")
        table.add_row("[3]", "View Results")
        table.add_row("[4]", "Settings")
        table.add_row("[0]", "Exit")

        console.print(table)
    else:
        print("""
┌─────────────────────────────────────────────────────────────┐
│                        MAIN MENU                            │
├─────────────────────────────────────────────────────────────┤
│  [1] Application Traceroute - Stack Analysis & Bypass       │
│  [2] SmartCrawler - Vulnerability Discovery                 │
│                                                             │
│  [3] View Results                                           │
│  [4] Settings                                               │
│  [0] Exit                                                   │
└─────────────────────────────────────────────────────────────┘
        """)


class SecuritySuite:
    """Interactive Security Testing Suite."""

    def __init__(self):
        self.target_url: Optional[str] = None
        self.forbidden_endpoint: Optional[str] = None
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)
        self.last_traceroute_completed: bool = False
        self.settings = {
            'rate_limit': 3.0,
            'timeout': 30,
            'verbose': True,
            'save_results': True,
            'wordlist_base': '/usr/share/wordlists',
            'auto_find_forbidden': True
        }

    def prompt(self, message: str, default: str = "") -> str:
        """Get user input with optional default."""
        if console:
            return Prompt.ask(f"[cyan]{message}[/cyan]", default=default)
        else:
            result = input(f"{message} [{default}]: ").strip()
            return result if result else default

    def confirm(self, message: str, default: bool = True) -> bool:
        """Get yes/no confirmation."""
        if console:
            return Confirm.ask(message, default=default)
        else:
            default_str = "Y/n" if default else "y/N"
            result = input(f"{message} [{default_str}]: ").strip().lower()
            if not result:
                return default
            return result in ('y', 'yes', 's', 'si')

    def set_target(self) -> bool:
        """Set target URL."""
        url = self.prompt("\nEnter target URL", self.target_url or "")

        if not url:
            print("No URL provided")
            return False

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        self.target_url = url
        print(f"Target set to: {self.target_url}")
        return True

    def set_forbidden_endpoint(self):
        """Set forbidden endpoint for bypass testing."""
        endpoint = self.prompt(
            "\nEnter forbidden endpoint for bypass testing (optional, press Enter to skip)",
            self.forbidden_endpoint or ""
        )

        if endpoint:
            self.forbidden_endpoint = endpoint
            print(f"Forbidden endpoint set to: {self.forbidden_endpoint}")
        else:
            self.forbidden_endpoint = None
            print("Skipping forbidden endpoint testing")

    def run_application_traceroute(self):
        """Run Application Traceroute analysis with integrated bypass validation."""
        if not self.set_target():
            return

        self.set_forbidden_endpoint()

        print("\n" + "=" * 60)
        print("RUNNING APPLICATION TRACEROUTE")
        print("Stack Analysis + Bypass Discovery")
        print("=" * 60)

        try:
            # Import module using importlib (file has dot in name)
            import importlib.util
            script_path = SCRIPT_DIR / 'Application_tracereout_3.5' / 'application_traceroute_v3.5.py'

            spec = importlib.util.spec_from_file_location("application_traceroute", str(script_path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            ApplicationTraceroute = module.ApplicationTraceroute

            # Se auto_find_forbidden è True e l'utente non ha specificato un endpoint,
            # NON skippiamo i test - lasciamo che ForbiddenEndpointFinder cerchi automaticamente
            skip_tests = not self.settings['auto_find_forbidden'] and not self.forbidden_endpoint

            tracer = ApplicationTraceroute(
                self.target_url,
                forbidden_endpoint=self.forbidden_endpoint,
                skip_forbidden_tests=skip_tests
            )

            # Run analysis
            asyncio.run(tracer.run_full_analysis())

            self.last_traceroute_completed = True
            print("\nApplication Traceroute completed successfully!")

        except Exception as e:
            print(f"Error: {e}")
            print("Trying to run script directly...")
            self._run_traceroute_subprocess()

    def _run_traceroute_subprocess(self):
        """Run traceroute by executing the script directly."""
        import subprocess

        script_path = SCRIPT_DIR / 'Application_tracereout_3.5' / 'application_traceroute_v3.5.py'

        if not script_path.exists():
            print(f"Error: Script not found at {script_path}")
            return

        cmd = [sys.executable, str(script_path), self.target_url]
        if self.forbidden_endpoint:
            cmd.extend(['--forbidden-endpoint', self.forbidden_endpoint])

        print(f"Running: {' '.join(cmd)}\n")

        result = subprocess.run(cmd, cwd=str(SCRIPT_DIR))

        if result.returncode == 0:
            self.last_traceroute_completed = True
            print("\nApplication Traceroute completed successfully!")

    def run_smart_crawler(self, use_existing_target: bool = False):
        """Run Smart Crawler for vulnerability discovery."""
        if not use_existing_target or not self.target_url:
            if not self.set_target():
                return

        print("\n" + "=" * 60)
        print("RUNNING SMART CRAWLER")
        print(f"Target: {self.target_url}")
        print("=" * 60)

        try:
            import subprocess

            script_path = SCRIPT_DIR / 'SmartCrawler' / 'smart_vuln_crawler2.py'

            if not script_path.exists():
                print(f"Error: Script not found at {script_path}")
                return

            output_file = self.results_dir / f"crawler_{int(time.time())}.json"

            cmd = [
                sys.executable, str(script_path),
                self.target_url,
                '--output', str(output_file),
                '--max-pages', '50',
                '--wordlist-base', self.settings['wordlist_base']
            ]

            print(f"Running: {' '.join(cmd)}\n")

            result = subprocess.run(cmd, cwd=str(SCRIPT_DIR))

            if result.returncode == 0:
                print(f"\nSmartCrawler completed!")
                if output_file.exists():
                    print(f"Results saved to: {output_file}")

        except Exception as e:
            print(f"Error running crawler: {e}")
            import traceback
            traceback.print_exc()

    def show_settings(self):
        """Show and modify settings."""
        while True:
            clear_screen()
            print("\n" + "=" * 50)
            print("SETTINGS")
            print("=" * 50)

            print(f"\n  [1] Rate Limit: {self.settings['rate_limit']} req/s")
            print(f"  [2] Timeout: {self.settings['timeout']}s")
            print(f"  [3] Verbose: {self.settings['verbose']}")
            print(f"  [4] Save Results: {self.settings['save_results']}")
            print(f"  [5] Results Dir: {self.results_dir}")
            print(f"\n  --- SmartCrawler ---")
            print(f"  [6] Wordlist Base Path: {self.settings['wordlist_base']}")
            print(f"\n  --- Application Traceroute ---")
            print(f"  [7] Auto-find Forbidden Endpoint: {self.settings['auto_find_forbidden']}")
            print(f"\n  [0] Back to Main Menu")

            choice = self.prompt("\nSelect option", "0")

            if choice == "0":
                break
            elif choice == "1":
                val = self.prompt(f"New rate limit", str(self.settings['rate_limit']))
                if val:
                    try:
                        self.settings['rate_limit'] = float(val)
                    except ValueError:
                        print("Invalid value")
            elif choice == "2":
                val = self.prompt(f"New timeout", str(self.settings['timeout']))
                if val:
                    try:
                        self.settings['timeout'] = int(val)
                    except ValueError:
                        print("Invalid value")
            elif choice == "3":
                self.settings['verbose'] = not self.settings['verbose']
                print(f"Verbose: {self.settings['verbose']}")
            elif choice == "4":
                self.settings['save_results'] = not self.settings['save_results']
                print(f"Save Results: {self.settings['save_results']}")
            elif choice == "5":
                val = self.prompt(f"New results dir", str(self.results_dir))
                if val:
                    self.results_dir = Path(val)
                    self.results_dir.mkdir(exist_ok=True)
            elif choice == "6":
                print("\n  Common paths:")
                print("    /usr/share/wordlists")
                print("    ~/wordlists")
                print("    /opt/wordlists")
                val = self.prompt(f"New wordlist base path", self.settings['wordlist_base'])
                if val:
                    if os.path.isdir(val):
                        self.settings['wordlist_base'] = val
                        print(f"  Wordlist path set to: {val}")
                    else:
                        print(f"  Warning: Directory '{val}' doesn't exist, setting anyway")
                        self.settings['wordlist_base'] = val
            elif choice == "7":
                self.settings['auto_find_forbidden'] = not self.settings['auto_find_forbidden']
                status = "enabled" if self.settings['auto_find_forbidden'] else "disabled"
                print(f"  Auto-find forbidden endpoint: {status}")

    def view_results(self):
        """View saved results."""
        clear_screen()
        print("\n" + "=" * 40)
        print("SAVED RESULTS")
        print("=" * 40)

        result_files = sorted(self.results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)

        if not result_files:
            print("\n  No results found.")
            input("\nPress Enter to continue...")
            return

        for i, f in enumerate(result_files[:20], 1):  # Show last 20
            size = f.stat().st_size / 1024
            mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(f.stat().st_mtime))
            print(f"\n  [{i}] {f.name}")
            print(f"      Size: {size:.1f} KB | Modified: {mtime}")

        choice = self.prompt("\nView file (0 to go back)", "0")

        if choice != "0":
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(result_files):
                    selected = result_files[idx]
                    with open(selected) as f:
                        data = json.load(f)

                    clear_screen()
                    print(f"\n=== {selected.name} ===\n")

                    output = json.dumps(data, indent=2)
                    if len(output) > 5000:
                        print(output[:5000])
                        print("\n... (truncated, file is larger)")
                    else:
                        print(output)
                else:
                    print("Invalid selection")

            except Exception as e:
                print(f"Error reading file: {e}")

        input("\nPress Enter to continue...")

    def offer_smart_crawler_after_traceroute(self):
        """Offer to run SmartCrawler after Traceroute completes."""
        if self.target_url and self.last_traceroute_completed:
            print("\n" + "-" * 40)
            if self.confirm(f"Run SmartCrawler on {self.target_url}?", default=False):
                self.run_smart_crawler(use_existing_target=True)
            self.last_traceroute_completed = False

    def run(self):
        """Main interactive loop."""
        while True:
            clear_screen()
            print_banner()

            if self.target_url:
                print(f"\nCurrent Target: {self.target_url}")
                if self.forbidden_endpoint:
                    print(f"Forbidden Endpoint: {self.forbidden_endpoint}")

            print_menu(has_target=bool(self.target_url), target_url=self.target_url)

            choice = self.prompt("\nSelect option", "0")

            if choice == "0":
                print("\nGoodbye!")
                break
            elif choice == "1":
                self.run_application_traceroute()
                self.offer_smart_crawler_after_traceroute()
                input("\nPress Enter to continue...")
            elif choice == "2":
                # If we have a target from traceroute, offer to use it
                if self.target_url:
                    if self.confirm(f"Use existing target ({self.target_url})?", default=True):
                        self.run_smart_crawler(use_existing_target=True)
                    else:
                        self.run_smart_crawler(use_existing_target=False)
                else:
                    self.run_smart_crawler(use_existing_target=False)
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.view_results()
            elif choice == "4":
                self.show_settings()
            else:
                print("Invalid option")
                time.sleep(1)


def main():
    """Entry point - Interactive mode only."""
    suite = SecuritySuite()
    suite.run()


if __name__ == '__main__':
    main()
