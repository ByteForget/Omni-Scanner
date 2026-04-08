"""
Discovery/Crawler Module for Vuln_Scanner_AG.
Crawls the target URL to find all internal links and forms.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Set, Optional

from utils.logger import logger

def get_base_domain(url: str) -> str:
    """Extract the base domain from a URL to ensure we stay in-scope."""
    return urlparse(url).netloc

def execute(target: str, session: Optional[requests.Session] = None, deep_scan: bool = False) -> Dict[str, Any]:
    """
    Crawl the target URL to discover internal links and forms.

    Args:
        target (str): The starting URL for the crawler.
        session (requests.Session): The configured authenticated requests session.

    Returns:
        Dict[str, Any]: A dictionary containing lists of discovered URLs and forms.
    """
    logger.info(f"Starting crawler on target: {target}")
    req_client = session if session else requests

    results: Dict[str, Any] = {
        "urls": [],
        "forms": []
    }

    discovered_urls: Set[str] = set()
    base_domain = get_base_domain(target)

    try:
        response = req_client.get(target, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')


        for link in soup.find_all('a'):
            href = link.get('href')
            if not href:
                continue


            if href.startswith('#') or href.startswith('mailto:'):
                continue


            absolute_url = urljoin(target, href)


            if get_base_domain(absolute_url) == base_domain:
                discovered_urls.add(absolute_url)

        results["urls"] = list(discovered_urls)
        logger.info(f"Crawler discovered {len(results['urls'])} internal URLs.")


        forms = soup.find_all('form')
        for form in forms:
            form_info = {
                "action": urljoin(target, form.get('action', '')),
                "method": form.get('method', 'get').upper(),
                "inputs": []
            }

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    form_info["inputs"].append({
                        "name": input_name,
                        "type": input_type
                    })

            results["forms"].append(form_info)


        logger.info(f"Crawler discovered {len(results['forms'])} forms.")


        if deep_scan:
            logger.info("Initializing Smart Parameter Fuzzer via Deep Scan flag...")
            from urllib.parse import urlencode, parse_qsl, urlunparse

            fuzz_params = ['id', 'page', 'dir', 'file', 'cmd', 'debug', 'admin', 'conf', 'log', 'query']
            fuzzed_urls: Set[str] = set()

            base_urls_to_fuzz = list(results["urls"])
            if target not in base_urls_to_fuzz:
                base_urls_to_fuzz.append(target)

            for u in base_urls_to_fuzz:
                parsed = urlparse(u)
                existing_params = parse_qsl(parsed.query)

                for param in fuzz_params:

                    if not any(k == param for k, v in existing_params):
                        new_params = existing_params.copy()
                        new_params.append((param, 'test_fuzz'))
                        new_query = urlencode(new_params)
                        fuzzed_url = urlunparse(parsed._replace(query=new_query))
                        fuzzed_urls.add(fuzzed_url)

            if fuzzed_urls:
                results["urls"].extend(list(fuzzed_urls))

                results["urls"] = sorted(list(set(results["urls"])))
                logger.info(f"Fuzzer injected {len(fuzzed_urls)} new parameter variants. Total URLs to scan: {len(results['urls'])}")

    except requests.RequestException as e:
        logger.error(f"Crawler Request failed for {target}: {e}")

    return results
