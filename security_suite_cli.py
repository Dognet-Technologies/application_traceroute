#!/usr/bin/env python3
"""
Security Testing Suite v4.0 - Integrated CLI
Orchestrates Application_traceroute, BypassValidator, SmartCrawler + Causal Inference

Interactive menu-driven interface for comprehensive security testing.
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
sys.path.insert(0, str(SCRIPT_DIR / 'BypassValidator'))

# Try Rich for beautiful CLI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Install 'rich' for a better experience (pip install rich)")

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
║                  Causal Inference Security Testing Framework                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    if console:
        console.print(Panel(banner, style="bold blue"))
    else:
        print(banner)


def print_menu():
    """Print main menu."""
    if console:
        table = Table(title="Main Menu", show_header=False, box=None)
        table.add_column("Option", style="cyan", width=6)
        table.add_column("Description", style="white")

        table.add_row("", "")
        table.add_row("[1]", "🔍 Application Traceroute - Stack Analysis & Bypass Discovery")
        table.add_row("[2]", "🕷️  Smart Crawler - Vulnerability Discovery & Prediction")
        table.add_row("[3]", "🛡️  Bypass Validator - Intelligent Bypass Validation")
        table.add_row("[4]", "📊 Causal Analysis Suite - Advanced Causal Inference")
        table.add_row("[5]", "🚀 Full Analysis - Run Complete Pipeline")
        table.add_row("", "")
        table.add_row("[6]", "⚙️  Settings")
        table.add_row("[7]", "📁 View Results")
        table.add_row("[0]", "❌ Exit")

        console.print(table)
    else:
        print("""
┌─────────────────────────────────────────────────────────────┐
│                        MAIN MENU                            │
├─────────────────────────────────────────────────────────────┤
│  [1] Application Traceroute - Stack Analysis & Bypass       │
│  [2] Smart Crawler - Vulnerability Discovery                │
│  [3] Bypass Validator - Intelligent Validation              │
│  [4] Causal Analysis Suite - Advanced Analysis              │
│  [5] Full Analysis - Run Complete Pipeline                  │
│                                                             │
│  [6] Settings                                               │
│  [7] View Results                                           │
│  [0] Exit                                                   │
└─────────────────────────────────────────────────────────────┘
        """)


class SecuritySuiteIntegrated:
    """Integrated Security Testing Suite."""

    def __init__(self):
        self.target_url: Optional[str] = None
        self.forbidden_endpoint: Optional[str] = None
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)
        self.current_results: Dict[str, Any] = {}
        self.settings = {
            'rate_limit': 3.0,
            'timeout': 30,
            'verbose': True,
            'save_results': True
        }

    def set_target(self) -> bool:
        """Set target URL."""
        if console:
            self.target_url = Prompt.ask("\n[cyan]Enter target URL[/cyan]", default=self.target_url or "")
        else:
            self.target_url = input("\nEnter target URL: ").strip()

        if not self.target_url:
            print("❌ No URL provided")
            return False

        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'https://' + self.target_url

        print(f"✓ Target set to: {self.target_url}")
        return True

    def set_forbidden_endpoint(self):
        """Set forbidden endpoint for bypass testing."""
        if console:
            self.forbidden_endpoint = Prompt.ask(
                "\n[cyan]Enter forbidden endpoint (403/401)[/cyan]",
                default=self.forbidden_endpoint or ""
            )
        else:
            self.forbidden_endpoint = input("\nEnter forbidden endpoint (403/401): ").strip()

        if self.forbidden_endpoint:
            print(f"✓ Forbidden endpoint set to: {self.forbidden_endpoint}")

    def run_application_traceroute(self):
        """Run Application Traceroute analysis."""
        if not self.target_url:
            if not self.set_target():
                return

        print("\n" + "="*60)
        print("🔍 RUNNING APPLICATION TRACEROUTE")
        print("="*60)

        try:
            # Import and run
            from application_traceroute_v3_5 import ApplicationTraceroute

            tracer = ApplicationTraceroute(
                self.target_url,
                forbidden_endpoint=self.forbidden_endpoint,
                skip_forbidden_tests=not self.forbidden_endpoint
            )

            # Run analysis
            asyncio.run(tracer.run_full_analysis())

            self.current_results['traceroute'] = {
                'timestamp': time.time(),
                'target': self.target_url,
                'status': 'completed'
            }

        except ImportError as e:
            print(f"⚠️  Import error: {e}")
            print("Trying alternative import...")
            self._run_traceroute_direct()
        except Exception as e:
            print(f"❌ Error running traceroute: {e}")
            import traceback
            traceback.print_exc()

    def _run_traceroute_direct(self):
        """Run traceroute by executing the script directly."""
        import subprocess

        script_path = SCRIPT_DIR / 'Application_tracereout_3.5' / 'application_traceroute_v3.5.py'

        cmd = [sys.executable, str(script_path), self.target_url]
        if self.forbidden_endpoint:
            cmd.extend(['--forbidden-endpoint', self.forbidden_endpoint])

        print(f"Running: {' '.join(cmd)}\n")

        result = subprocess.run(cmd, cwd=str(SCRIPT_DIR))

        if result.returncode == 0:
            self.current_results['traceroute'] = {'status': 'completed'}

    def run_smart_crawler(self):
        """Run Smart Crawler."""
        if not self.target_url:
            if not self.set_target():
                return

        print("\n" + "="*60)
        print("🕷️  RUNNING SMART CRAWLER")
        print("="*60)

        try:
            import subprocess

            script_path = SCRIPT_DIR / 'SmartCrawler' / 'smart_vuln_crawler2.py'
            output_file = self.results_dir / f"crawler_{int(time.time())}.json"

            cmd = [
                sys.executable, str(script_path),
                self.target_url,
                '--output', str(output_file),
                '--max-pages', '50'
            ]

            print(f"Running: {' '.join(cmd)}\n")

            result = subprocess.run(cmd, cwd=str(SCRIPT_DIR))

            if result.returncode == 0:
                self.current_results['crawler'] = {
                    'status': 'completed',
                    'output': str(output_file)
                }
                print(f"\n✓ Results saved to: {output_file}")

        except Exception as e:
            print(f"❌ Error running crawler: {e}")

    def run_bypass_validator(self):
        """Run Bypass Validator."""
        print("\n" + "="*60)
        print("🛡️  RUNNING BYPASS VALIDATOR")
        print("="*60)

        # Check for traceroute results to validate
        json_files = list(self.results_dir.glob("*bypass*.json")) + \
                     list(self.results_dir.glob("*traceroute*.json"))

        if not json_files:
            print("⚠️  No bypass files found. Run Application Traceroute first.")
            if console:
                if Confirm.ask("Run Application Traceroute now?"):
                    self.run_application_traceroute()
                    return self.run_bypass_validator()
            return

        print("\nAvailable bypass files:")
        for i, f in enumerate(json_files, 1):
            print(f"  [{i}] {f.name}")

        if console:
            choice = Prompt.ask("Select file", default="1")
        else:
            choice = input("Select file [1]: ").strip() or "1"

        try:
            selected_file = json_files[int(choice) - 1]

            import subprocess
            script_path = SCRIPT_DIR / 'BypassValidator' / 'intelligent_bypass_validator.py'

            cmd = [sys.executable, str(script_path), str(selected_file)]
            print(f"\nRunning: {' '.join(cmd)}\n")

            subprocess.run(cmd, cwd=str(SCRIPT_DIR))

        except Exception as e:
            print(f"❌ Error: {e}")

    def run_causal_analysis(self):
        """Run Causal Analysis Suite."""
        if not self.target_url:
            if not self.set_target():
                return

        print("\n" + "="*60)
        print("📊 RUNNING CAUSAL ANALYSIS SUITE")
        print("="*60)

        try:
            from Suite.cli.orchestrator import SecuritySuiteOrchestrator, AnalysisConfig

            config = AnalysisConfig(
                target_url=self.target_url,
                results_dir=self.results_dir,
                verbose=self.settings['verbose']
            )

            orchestrator = SecuritySuiteOrchestrator(config)
            results = orchestrator.run()

            self.current_results['causal_analysis'] = results

            print(f"\n✓ Analysis complete!")
            print(f"  Phases: {results['summary']['phases_successful']}/{results['summary']['phases_total']}")

        except Exception as e:
            print(f"❌ Error running causal analysis: {e}")
            import traceback
            traceback.print_exc()

    def run_full_pipeline(self):
        """Run complete analysis pipeline."""
        if not self.target_url:
            if not self.set_target():
                return

        self.set_forbidden_endpoint()

        print("\n" + "="*60)
        print("🚀 RUNNING FULL ANALYSIS PIPELINE")
        print("="*60)

        steps = [
            ("Application Traceroute", self.run_application_traceroute),
            ("Smart Crawler", self.run_smart_crawler),
            ("Causal Analysis", self.run_causal_analysis),
        ]

        for i, (name, func) in enumerate(steps, 1):
            print(f"\n{'─'*60}")
            print(f"Step {i}/{len(steps)}: {name}")
            print('─'*60)

            try:
                func()
            except Exception as e:
                print(f"⚠️  Error in {name}: {e}")
                if console:
                    if not Confirm.ask("Continue with next step?"):
                        break

        # Final summary
        print("\n" + "="*60)
        print("📋 ANALYSIS COMPLETE - SUMMARY")
        print("="*60)

        for tool, result in self.current_results.items():
            status = result.get('status', 'unknown')
            print(f"  {tool}: {status}")

        print(f"\n📁 Results saved to: {self.results_dir}")

    def show_settings(self):
        """Show and modify settings."""
        while True:
            print("\n" + "="*40)
            print("⚙️  SETTINGS")
            print("="*40)

            print(f"\n  [1] Rate Limit: {self.settings['rate_limit']} req/s")
            print(f"  [2] Timeout: {self.settings['timeout']}s")
            print(f"  [3] Verbose: {self.settings['verbose']}")
            print(f"  [4] Save Results: {self.settings['save_results']}")
            print(f"  [5] Results Dir: {self.results_dir}")
            print(f"\n  [0] Back to Main Menu")

            if console:
                choice = Prompt.ask("\nSelect option", default="0")
            else:
                choice = input("\nSelect option [0]: ").strip() or "0"

            if choice == "0":
                break
            elif choice == "1":
                val = input(f"New rate limit [{self.settings['rate_limit']}]: ").strip()
                if val:
                    self.settings['rate_limit'] = float(val)
            elif choice == "2":
                val = input(f"New timeout [{self.settings['timeout']}]: ").strip()
                if val:
                    self.settings['timeout'] = int(val)
            elif choice == "3":
                self.settings['verbose'] = not self.settings['verbose']
            elif choice == "4":
                self.settings['save_results'] = not self.settings['save_results']
            elif choice == "5":
                val = input(f"New results dir [{self.results_dir}]: ").strip()
                if val:
                    self.results_dir = Path(val)
                    self.results_dir.mkdir(exist_ok=True)

    def view_results(self):
        """View saved results."""
        print("\n" + "="*40)
        print("📁 SAVED RESULTS")
        print("="*40)

        result_files = list(self.results_dir.glob("*.json"))

        if not result_files:
            print("\n  No results found.")
            return

        for i, f in enumerate(result_files, 1):
            size = f.stat().st_size / 1024
            mtime = time.ctime(f.stat().st_mtime)
            print(f"\n  [{i}] {f.name}")
            print(f"      Size: {size:.1f} KB | Modified: {mtime}")

        if console:
            choice = Prompt.ask("\nView file (0 to go back)", default="0")
        else:
            choice = input("\nView file (0 to go back) [0]: ").strip() or "0"

        if choice != "0":
            try:
                selected = result_files[int(choice) - 1]
                with open(selected) as f:
                    data = json.load(f)

                if console:
                    from rich.syntax import Syntax
                    syntax = Syntax(json.dumps(data, indent=2)[:3000], "json", theme="monokai")
                    console.print(syntax)
                else:
                    print(json.dumps(data, indent=2)[:3000])

                if len(json.dumps(data)) > 3000:
                    print("\n... (truncated)")

            except Exception as e:
                print(f"❌ Error reading file: {e}")

        input("\nPress Enter to continue...")

    def run(self):
        """Main loop."""
        while True:
            clear_screen()
            print_banner()

            if self.target_url:
                print(f"\n🎯 Current Target: {self.target_url}")
                if self.forbidden_endpoint:
                    print(f"🚫 Forbidden Endpoint: {self.forbidden_endpoint}")

            print_menu()

            if console:
                choice = Prompt.ask("\n[cyan]Select option[/cyan]", default="0")
            else:
                choice = input("\nSelect option [0]: ").strip() or "0"

            if choice == "0":
                print("\n👋 Goodbye!")
                break
            elif choice == "1":
                self.set_target()
                self.set_forbidden_endpoint()
                self.run_application_traceroute()
                input("\nPress Enter to continue...")
            elif choice == "2":
                self.run_smart_crawler()
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.run_bypass_validator()
                input("\nPress Enter to continue...")
            elif choice == "4":
                self.run_causal_analysis()
                input("\nPress Enter to continue...")
            elif choice == "5":
                self.run_full_pipeline()
                input("\nPress Enter to continue...")
            elif choice == "6":
                self.show_settings()
            elif choice == "7":
                self.view_results()
            else:
                print("Invalid option")
                time.sleep(1)


def main():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Security Testing Suite v4.0 - Integrated CLI'
    )
    parser.add_argument('--target', '-t', help='Target URL')
    parser.add_argument('--forbidden', '-f', help='Forbidden endpoint')
    parser.add_argument('--tool', choices=['traceroute', 'crawler', 'validator', 'causal', 'full'],
                        help='Run specific tool directly')
    parser.add_argument('--no-interactive', action='store_true', help='Non-interactive mode')

    args = parser.parse_args()

    suite = SecuritySuiteIntegrated()

    if args.target:
        suite.target_url = args.target
    if args.forbidden:
        suite.forbidden_endpoint = args.forbidden

    if args.tool:
        if not suite.target_url:
            print("Error: --target required when using --tool")
            sys.exit(1)

        tool_map = {
            'traceroute': suite.run_application_traceroute,
            'crawler': suite.run_smart_crawler,
            'validator': suite.run_bypass_validator,
            'causal': suite.run_causal_analysis,
            'full': suite.run_full_pipeline
        }
        tool_map[args.tool]()
    else:
        suite.run()


if __name__ == '__main__':
    main()
