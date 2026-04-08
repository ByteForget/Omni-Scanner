import socket
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List

from utils.logger import logger

def execute(target: str, forms: Optional[List[Dict[str, Any]]] = None, session: Optional[Any] = None) -> Dict[str, Any]:
    """
    Execute a basic Port Scan against the target hostname.

    Args:
        target (str): The target URL to scan (protocol is stripped).
        forms (list): Ignored for network scans.
        session (Any): Ignored for network socket connections.

    Returns:
        Dict[str, Any]: A dictionary containing the scan results.
    """
    logger.info(f"Starting Port Scan on target: {target}")

    results: Dict[str, Any] = {
        "vulnerabilities_found": False,
        "details": []
    }


    parsed_url = urlparse(target)
    hostname = parsed_url.hostname or target


    if "://" not in target and "/" in hostname:
        hostname = hostname.split("/")[0]

    ports_to_scan = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Proxy"
    }


    standard_ports = [80, 443, 8080]

    total_open = 0

    for port, service in ports_to_scan.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((hostname, port))

            if result == 0:
                total_open += 1
                is_risky = port not in standard_ports


                if is_risky:
                    logger.warning(f"[!] Risky Open Port found: {port}/{service} on {hostname}")
                    results["vulnerabilities_found"] = True
                    results["details"].append({
                        "type": "Exposed Network Service",
                        "severity": "Medium",
                        "parameter": "Network Port",
                        "payload": f"{port}/{service}",
                        "url": hostname,
                        "evidence": f"Socket successfully connected to {hostname}:{port} indicating the {service} service is publicly accessible.",
                        "remediation": f"Verify if the {service} service needs to be publicly accessible. Restrict access using firewalls, security groups, or VPNs."
                    })
                else:
                    logger.info(f"[+] Standard Open Port found: {port}/{service} on {hostname}")

        except socket.error as e:
            logger.error(f"Socket error when scanning {hostname}:{port} - {e}")
        finally:
            sock.close()

    if total_open > 0:
        logger.info(f"Port scan complete. {total_open} total open ports found.")
    else:
        logger.info("Port scan complete. No targeted open ports found.")

    return results
