#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║       VulnScan Framework - Automated PenTest Suite       ║
║       Open Source | MIT License                          ║
╚══════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.YELLOW}  Automated Penetration Testing & Vulnerability Scanning Framework{Style.RESET_ALL}
{Fore.GREEN}  ML-Powered | Modular | Open Source{Style.RESET_ALL}
{Fore.RED}  ⚠  FOR AUTHORIZED TESTING ONLY — USE RESPONSIBLY{Style.RESET_ALL}
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScan Framework - Automated Penetration Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com --mode full
  python main.py --target 192.168.1.0/24 --mode recon --output json
  python main.py --target example.com --mode web --modules sqli,xss,lfi
  python main.py --target example.com --mode ml-predict --train-data data/vulns.csv
        """
    )

    parser.add_argument("--target", "-t", required=True, help="Target host, IP, or CIDR range")
    parser.add_argument("--mode", "-m", default="full",
                        choices=["full", "recon", "portscan", "web", "auth", "ml-predict", "report-only"],
                        help="Scan mode (default: full)")
    parser.add_argument("--modules", help="Comma-separated list of modules to run (sqli,xss,lfi,rce,ssrf,xxe,csrf)")
    parser.add_argument("--ports", "-p", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("--threads", default=50, type=int, help="Number of concurrent threads (default: 50)")
    parser.add_argument("--timeout", default=10, type=int, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output", "-o", default="html", choices=["html", "json", "pdf", "all"],
                        help="Report output format (default: html)")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist for directory/parameter fuzzing")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)")
    parser.add_argument("--cookies", help="Session cookies for authenticated scans (JSON string)")
    parser.add_argument("--headers", help="Custom HTTP headers (JSON string)")
    parser.add_argument("--train-data", help="Path to training CSV for ML model")
    parser.add_argument("--ml-model", default="models/vuln_predictor.pkl", help="Path to saved ML model")
    parser.add_argument("--depth", "-d", default=3, type=int, help="Crawl depth (default: 3)")
    parser.add_argument("--rate-limit", default=0, type=float, help="Delay between requests in seconds")
    parser.add_argument("--verify-ssl", action="store_true", default=False, help="Verify SSL certificates")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and progress output")
    parser.add_argument("--config", "-c", help="Path to YAML configuration file")

    return parser.parse_args()


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    import yaml
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def run_scan(args):
    """Main scan orchestration function."""
    from core.recon import ReconEngine
    from core.scanner import PortScanner
    from core.web_scanner import WebVulnScanner
    from core.auth_scanner import AuthScanner
    from ml.predictor import VulnPredictor
    from core.reporter import ReportGenerator
    from utils.logger import get_logger

    logger = get_logger(verbose=args.verbose, quiet=args.quiet)
    results = {
        "target": args.target,
        "scan_start": datetime.now().isoformat(),
        "mode": args.mode,
        "recon": {},
        "ports": {},
        "vulnerabilities": [],
        "ml_predictions": [],
        "risk_score": 0,
    }

    logger.info(f"[*] Starting scan against target: {args.target}")
    logger.info(f"[*] Mode: {args.mode} | Threads: {args.threads} | Timeout: {args.timeout}s")

    # ── Phase 1: Reconnaissance ────────────────────────────────────────────────
    if args.mode in ("full", "recon"):
        logger.info(f"\n{Fore.CYAN}[PHASE 1] Web Reconnaissance{Style.RESET_ALL}")
        recon = ReconEngine(
            target=args.target,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            verbose=args.verbose,
        )
        results["recon"] = recon.run_all()
        logger.info(f"[+] Recon complete: {len(results['recon'])} data points collected")

    # ── Phase 2: Port Scanning ─────────────────────────────────────────────────
    if args.mode in ("full", "portscan"):
        logger.info(f"\n{Fore.CYAN}[PHASE 2] Port & Service Scanning{Style.RESET_ALL}")
        scanner = PortScanner(
            target=args.target,
            port_range=args.ports,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        results["ports"] = scanner.scan()
        open_ports = [p for p, d in results["ports"].items() if d.get("state") == "open"]
        logger.info(f"[+] Port scan complete: {len(open_ports)} open ports found")

    # ── Phase 3: Web Vulnerability Scanning ───────────────────────────────────
    if args.mode in ("full", "web"):
        logger.info(f"\n{Fore.CYAN}[PHASE 3] Web Vulnerability Scanning{Style.RESET_ALL}")
        modules = args.modules.split(",") if args.modules else None
        cookies = json.loads(args.cookies) if args.cookies else {}
        headers = json.loads(args.headers) if args.headers else {}

        web_scanner = WebVulnScanner(
            target=args.target,
            timeout=args.timeout,
            threads=args.threads,
            depth=args.depth,
            modules=modules,
            cookies=cookies,
            headers=headers,
            proxy=args.proxy,
            wordlist=args.wordlist,
            rate_limit=args.rate_limit,
            verify_ssl=args.verify_ssl,
            verbose=args.verbose,
        )
        web_vulns = web_scanner.scan()
        results["vulnerabilities"].extend(web_vulns)
        logger.info(f"[+] Web scan complete: {len(web_vulns)} vulnerabilities found")

    # ── Phase 4: Authentication Testing ───────────────────────────────────────
    if args.mode in ("full", "auth"):
        logger.info(f"\n{Fore.CYAN}[PHASE 4] Authentication & Access Control Testing{Style.RESET_ALL}")
        auth_scanner = AuthScanner(
            target=args.target,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        auth_vulns = auth_scanner.scan()
        results["vulnerabilities"].extend(auth_vulns)
        logger.info(f"[+] Auth scan complete: {len(auth_vulns)} issues found")

    # ── Phase 5: ML-Powered Vulnerability Prediction ──────────────────────────
    if args.mode in ("full", "ml-predict"):
        logger.info(f"\n{Fore.CYAN}[PHASE 5] ML Vulnerability Prediction{Style.RESET_ALL}")
        predictor = VulnPredictor(model_path=args.ml_model)

        if args.train_data:
            logger.info(f"[*] Training ML model on: {args.train_data}")
            predictor.train(args.train_data)

        predictions = predictor.predict(results["recon"], results["ports"])
        results["ml_predictions"] = predictions
        logger.info(f"[+] ML prediction complete: {len(predictions)} potential vulnerabilities predicted")

    # ── Phase 6: Risk Scoring & Reporting ─────────────────────────────────────
    logger.info(f"\n{Fore.CYAN}[PHASE 6] Generating Report{Style.RESET_ALL}")
    results["scan_end"] = datetime.now().isoformat()
    results["risk_score"] = calculate_risk_score(results)

    os.makedirs(args.output_dir, exist_ok=True)
    reporter = ReportGenerator(results, output_dir=args.output_dir)

    formats = ["html", "json", "pdf"] if args.output == "all" else [args.output]
    for fmt in formats:
        path = reporter.generate(fmt)
        logger.info(f"[+] Report saved: {path}")

    # ── Summary ────────────────────────────────────────────────────────────────
    print_summary(results, logger)
    return results


def calculate_risk_score(results: dict) -> float:
    """Calculate overall risk score (0-100) based on findings."""
    score = 0.0
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0.5}
    for vuln in results.get("vulnerabilities", []):
        severity = vuln.get("severity", "info").lower()
        score += severity_weights.get(severity, 0)
    for pred in results.get("ml_predictions", []):
        confidence = pred.get("confidence", 0)
        score += confidence * 5
    return min(round(score, 1), 100.0)


def print_summary(results: dict, logger):
    """Print a human-readable scan summary."""
    vulns = results.get("vulnerabilities", [])
    preds = results.get("ml_predictions", [])

    critical = sum(1 for v in vulns if v.get("severity") == "critical")
    high     = sum(1 for v in vulns if v.get("severity") == "high")
    medium   = sum(1 for v in vulns if v.get("severity") == "medium")
    low      = sum(1 for v in vulns if v.get("severity") == "low")

    risk = results.get("risk_score", 0)
    risk_color = Fore.RED if risk >= 70 else (Fore.YELLOW if risk >= 40 else Fore.GREEN)

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════╗
║              SCAN SUMMARY                    ║
╠══════════════════════════════════════════════╣{Style.RESET_ALL}
  Target       : {results['target']}
  Duration     : {results.get('scan_end', 'N/A')}
  Risk Score   : {risk_color}{risk}/100{Style.RESET_ALL}
{Fore.CYAN}╠══════════════════════════════════════════════╣{Style.RESET_ALL}
  {Fore.RED}Critical     : {critical}{Style.RESET_ALL}
  {Fore.YELLOW}High         : {high}{Style.RESET_ALL}
  {Fore.BLUE}Medium       : {medium}{Style.RESET_ALL}
  {Fore.GREEN}Low          : {low}{Style.RESET_ALL}
  ML Predicted : {len(preds)}
{Fore.CYAN}╚══════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def main():
    args = parse_args()

    if not args.quiet:
        print(BANNER)

    if args.config:
        config = load_config(args.config)
        for key, val in config.items():
            if not getattr(args, key, None):
                setattr(args, key, val)

    try:
        run_scan(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
