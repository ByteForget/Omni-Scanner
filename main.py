"""
Vuln_Scanner_AG - Modular Vulnerability Scanner
Main orchestrator script to parse arguments, load modules, and generate reports.
"""
import argparse
import sys

from utils.logger import logger
from scanner_core import run_full_scan

def parse_arguments() -> argparse.Namespace:
    """
    Parse CLI options using argparse.

    Returns:
        argparse.Namespace: Object containing parsed CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Vuln_Scanner_AG: An Extensible and Modular Vulnerability Scanner.",
        epilog="Example: python main.py -t http://example.com -m xss_scanner "
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target URL, IPv4, or host to analyze."
    )
    parser.add_argument(
        "-m", "--modules",
        nargs="+",
        default=["all"],
        help="Names of modules to execute space-separated. Default is 'all'."
    )
    parser.add_argument(
        "-c", "--cookies",
        help="Custom configuration string for session cookies (e.g., 'PHPSESSID=12345; security=low')."
    )
    parser.add_argument(
        "-o", "--output",
        default="scan_report",
        help="Base name for the generated report files (default: 'scan_report')."
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable the Smart Parameter Fuzzer explicitly during the initial Recon sequence."
    )
    parser.add_argument(
        "--dvwa",
        action="store_true",
        help="Automatically authenticate using default DVWA credentials (admin:password)."
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=5,
        help="Number of concurrent threading workers (default: 5)."
    )

    return parser.parse_args()

def main():
    """Application entry point coordinating scan tasks."""
    args = parse_arguments()

    logger.info("=" * 50)
    logger.info(f"Target Acquired: {args.target}")
    logger.info("=" * 50)

    try:
        run_full_scan(
            args.target,
            modules=args.modules,
            cookies=args.cookies,
            deep=getattr(args, "deep", False),
            dvwa=getattr(args, "dvwa", False),
            workers=args.workers,
            write_reports=True,
            output_base=args.output,
            reports_dir="reports",
            generate_html=True,
            generate_pdf=True,
        )
        logger.info("-> Scan complete. Reports written to `reports/`.")
    except (ValueError, RuntimeError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
