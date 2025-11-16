#!/usr/bin/env python3
"""
GitHub Actions IP Whitelist Script

This script fetches the current GitHub Actions IP ranges from GitHub's API
and configures UFW firewall rules to allow access on a specified TCP port.
"""

import os
import sys
import subprocess
import logging
from datetime import datetime
from typing import List, Set
import requests
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/github-ufw-whitelist.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# GitHub API endpoint for meta information
GITHUB_META_URL = "https://api.github.com/meta"

# UFW rule comment to identify our managed rules
UFW_COMMENT = "GitHub Actions"


def load_config() -> int:
    """Load configuration from .env file."""
    load_dotenv()

    tcp_port = os.getenv('TCP_PORT')
    if not tcp_port:
        logger.error("TCP_PORT not found in .env file")
        sys.exit(1)

    try:
        port = int(tcp_port)
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return port
    except ValueError as e:
        logger.error(f"Invalid TCP_PORT value: {e}")
        sys.exit(1)


def check_root():
    """Verify script is running as root."""
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)


def fetch_github_actions_ips() -> List[str]:
    """Fetch GitHub Actions IP ranges from GitHub API."""
    try:
        logger.info(f"Fetching GitHub Actions IPs from {GITHUB_META_URL}")
        response = requests.get(GITHUB_META_URL, timeout=10)
        response.raise_for_status()

        data = response.json()
        actions_ips = data.get('actions', [])

        if not actions_ips:
            logger.warning("No GitHub Actions IPs found in API response")
            return []

        logger.info(f"Retrieved {len(actions_ips)} IP ranges")
        return actions_ips

    except requests.RequestException as e:
        logger.error(f"Failed to fetch GitHub Actions IPs: {e}")
        sys.exit(1)


def get_existing_rules(port: int) -> Set[str]:
    """Get existing UFW rules for GitHub Actions on the specified port."""
    try:
        result = subprocess.run(
            ['ufw', 'status', 'numbered'],
            capture_output=True,
            text=True,
            check=True
        )

        existing_ips = set()
        for line in result.stdout.split('\n'):
            if UFW_COMMENT in line and str(port) in line:
                # Extract IP from rule line
                # Format: [ X] 22/tcp ALLOW IN 192.30.252.0/22 # GitHub Actions
                parts = line.split()
                for i, part in enumerate(parts):
                    if '/' in part and '.' in part:
                        # Found IP CIDR
                        existing_ips.add(part)

        return existing_ips

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get UFW status: {e}")
        return set()


def remove_stale_rules(port: int, current_ips: Set[str]):
    """Remove UFW rules for IPs that are no longer in GitHub's list."""
    try:
        result = subprocess.run(
            ['ufw', 'status', 'numbered'],
            capture_output=True,
            text=True,
            check=True
        )

        # Collect rule numbers to delete (in reverse order)
        rules_to_delete = []

        for line in result.stdout.split('\n'):
            if UFW_COMMENT in line and str(port) in line:
                # Extract rule number and IP
                if line.strip().startswith('['):
                    try:
                        rule_num = line.split(']')[0].strip('[').strip()

                        # Extract IP from the rule
                        parts = line.split()
                        ip_found = None
                        for part in parts:
                            if '/' in part and '.' in part:
                                ip_found = part
                                break

                        if ip_found and ip_found not in current_ips:
                            rules_to_delete.append((int(rule_num), ip_found))

                    except (IndexError, ValueError):
                        continue

        # Delete rules in reverse order to maintain rule numbers
        for rule_num, ip in sorted(rules_to_delete, reverse=True):
            logger.info(f"Removing stale rule for {ip}")
            subprocess.run(
                ['ufw', 'delete', str(rule_num)],
                input='y\n',
                capture_output=True,
                text=True
            )

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to remove stale rules: {e}")


def add_ufw_rule(ip_range: str, port: int):
    """Add a UFW rule to allow traffic from IP range on specified port."""
    try:
        cmd = [
            'ufw', 'allow', 'from', ip_range,
            'to', 'any', 'port', str(port),
            'proto', 'tcp', 'comment', UFW_COMMENT
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        logger.info(f"Added rule: {ip_range} -> port {port}/tcp")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to add UFW rule for {ip_range}: {e.stderr}")
        return False


def main():
    """Main execution function."""
    logger.info("=" * 60)
    logger.info("GitHub Actions UFW Whitelist Script Starting")
    logger.info("=" * 60)

    # Check if running as root
    check_root()

    # Load configuration
    tcp_port = load_config()
    logger.info(f"Configured TCP port: {tcp_port}")

    # Fetch GitHub Actions IPs
    github_ips = fetch_github_actions_ips()
    current_ips = set(github_ips)

    # Get existing rules
    existing_ips = get_existing_rules(tcp_port)
    logger.info(f"Found {len(existing_ips)} existing rules")

    # Remove stale rules
    stale_ips = existing_ips - current_ips
    if stale_ips:
        logger.info(f"Removing {len(stale_ips)} stale rules")
        remove_stale_rules(tcp_port, current_ips)

    # Add new rules
    new_ips = current_ips - existing_ips
    if new_ips:
        logger.info(f"Adding {len(new_ips)} new rules")
        for ip_range in new_ips:
            add_ufw_rule(ip_range, tcp_port)
    else:
        logger.info("No new IPs to add")

    logger.info("Script completed successfully")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
