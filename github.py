#!/usr/bin/env python3
"""
GitHub Actions IP Whitelist Script

This script fetches the current GitHub Actions IP ranges from GitHub's API
and configures UFW firewall rules using ipset for efficient management of
thousands of IP addresses.

Uses ipset to manage large IP lists efficiently (single rule instead of thousands).
"""

import os
import sys
import subprocess
import logging
import tempfile
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

# ipset names for GitHub Actions IPs (separate for IPv4 and IPv6)
IPSET_NAME_V4 = "github-actions-v4"
IPSET_NAME_V6 = "github-actions-v6"

# UFW rule comment to identify our managed rules
UFW_COMMENT = "GitHub Actions (ipset)"


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


def separate_ip_families(ip_list: List[str]) -> tuple[List[str], List[str]]:
    """Separate IPv4 and IPv6 addresses."""
    ipv4_list = []
    ipv6_list = []

    for ip in ip_list:
        if ':' in ip:
            # IPv6 addresses contain colons
            ipv6_list.append(ip)
        else:
            # IPv4 addresses are dotted decimal
            ipv4_list.append(ip)

    logger.info(f"Separated into {len(ipv4_list)} IPv4 and {len(ipv6_list)} IPv6 ranges")
    return ipv4_list, ipv6_list


def check_ipset_installed():
    """Check if ipset is installed."""
    try:
        subprocess.run(['ipset', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("ipset is not installed. Install it with: apt-get install ipset")
        sys.exit(1)


def ipset_exists(ipset_name: str) -> bool:
    """Check if an ipset exists."""
    try:
        result = subprocess.run(
            ['ipset', 'list', ipset_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False


def create_ipset(ipset_name: str, family: str):
    """Create an ipset for GitHub Actions IPs.

    Args:
        ipset_name: Name of the ipset to create
        family: 'inet' for IPv4 or 'inet6' for IPv6
    """
    try:
        logger.info(f"Creating ipset '{ipset_name}' (family: {family})")
        subprocess.run(
            ['ipset', 'create', ipset_name, 'hash:net', 'family', family, 'hashsize', '4096', 'maxelem', '10000'],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"ipset '{ipset_name}' created successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create ipset '{ipset_name}': {e.stderr}")
        return False


def get_ipset_entries(ipset_name: str) -> Set[str]:
    """Get current entries in an ipset."""
    try:
        result = subprocess.run(
            ['ipset', 'list', ipset_name],
            capture_output=True,
            text=True,
            check=True
        )

        entries = set()
        in_members = False
        for line in result.stdout.split('\n'):
            if line.startswith('Members:'):
                in_members = True
                continue
            if in_members and line.strip():
                entries.add(line.strip())

        return entries
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get ipset entries for '{ipset_name}': {e}")
        return set()


def update_ipset(ipset_name: str, current_ips: List[str]):
    """Update ipset with current GitHub Actions IPs using efficient batch method."""
    if not current_ips:
        logger.info(f"No IPs to update for {ipset_name}")
        return True

    logger.info(f"Updating ipset '{ipset_name}' with {len(current_ips)} IP ranges")

    # Get existing entries
    existing_ips = get_ipset_entries(ipset_name)
    current_ips_set = set(current_ips)

    # Calculate differences
    to_add = current_ips_set - existing_ips
    to_remove = existing_ips - current_ips_set

    logger.info(f"[{ipset_name}] IPs to add: {len(to_add)}, IPs to remove: {len(to_remove)}")

    # Remove stale entries
    if to_remove:
        for ip in to_remove:
            try:
                subprocess.run(
                    ['ipset', 'del', ipset_name, ip],
                    capture_output=True,
                    check=True
                )
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to remove {ip} from {ipset_name}: {e}")

    # Add new entries using restore (batch method - much faster!)
    if to_add:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for ip in to_add:
                f.write(f"add {ipset_name} {ip}\n")
            temp_file = f.name

        try:
            subprocess.run(
                ['ipset', 'restore', '-exist'],
                stdin=open(temp_file, 'r'),
                capture_output=True,
                check=True
            )
            logger.info(f"[{ipset_name}] Successfully added {len(to_add)} new IP ranges")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add IPs to ipset '{ipset_name}': {e.stderr}")
        finally:
            os.unlink(temp_file)

    return True


def ensure_ufw_rule_exists(port: int, ipset_name: str, ip_version: int):
    """Ensure UFW has a rule to allow traffic from our ipset.

    Args:
        port: TCP port to allow
        ipset_name: Name of the ipset
        ip_version: 4 for IPv4, 6 for IPv6
    """
    try:
        iptables_cmd = 'iptables' if ip_version == 4 else 'ip6tables'
        rule_comment = f"{UFW_COMMENT} IPv{ip_version}"

        # Check if rule already exists
        result = subprocess.run(
            [iptables_cmd, '-L', 'ufw-user-input', '-n'],
            capture_output=True,
            text=True,
            check=True
        )

        # Look for our ipset rule
        if ipset_name in result.stdout:
            logger.info(f"IPv{ip_version} rule for ipset '{ipset_name}' already exists")
            return True

        # Rule doesn't exist, create it using iptables directly
        logger.info(f"Creating IPv{ip_version} rule for ipset '{ipset_name}' on port {port}")

        # Add iptables rule directly (UFW-compatible)
        # This creates a rule that allows traffic from IPs in the ipset
        subprocess.run(
            [
                iptables_cmd, '-I', 'ufw-user-input', '1',
                '-p', 'tcp', '--dport', str(port),
                '-m', 'set', '--match-set', ipset_name, 'src',
                '-j', 'ACCEPT',
                '-m', 'comment', '--comment', rule_comment
            ],
            capture_output=True,
            check=True
        )

        logger.info(f"IPv{ip_version} rule created successfully")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create IPv{ip_version} rule: {e.stderr}")
        return False


def make_ipset_persistent():
    """Make ipset persistent across reboots."""
    try:
        # Save current ipset configuration
        logger.info("Making ipset persistent")

        # Create directory if it doesn't exist
        os.makedirs('/etc/ipset', exist_ok=True)

        # Save ipset
        with open('/etc/ipset/ipset.rules', 'w') as f:
            result = subprocess.run(
                ['ipset', 'save'],
                capture_output=True,
                text=True,
                check=True
            )
            f.write(result.stdout)

        logger.info("ipset configuration saved to /etc/ipset/ipset.rules")

        # Check if netfilter-persistent is installed
        try:
            subprocess.run(['which', 'netfilter-persistent'], capture_output=True, check=True)
            subprocess.run(['netfilter-persistent', 'save'], capture_output=True, check=True)
            logger.info("iptables rules saved via netfilter-persistent")
        except subprocess.CalledProcessError:
            logger.warning("netfilter-persistent not found. Install with: apt-get install iptables-persistent")

        return True
    except Exception as e:
        logger.error(f"Failed to make ipset persistent: {e}")
        return False


def main():
    """Main execution function."""
    logger.info("=" * 60)
    logger.info("GitHub Actions UFW Whitelist Script Starting (ipset mode)")
    logger.info("=" * 60)

    # Check if running as root
    check_root()

    # Check if ipset is installed
    check_ipset_installed()

    # Load configuration
    tcp_port = load_config()
    logger.info(f"Configured TCP port: {tcp_port}")

    # Fetch GitHub Actions IPs
    github_ips = fetch_github_actions_ips()
    logger.info(f"Retrieved {len(github_ips)} IP ranges from GitHub")

    # Separate IPv4 and IPv6 addresses
    ipv4_ips, ipv6_ips = separate_ip_families(github_ips)

    # Handle IPv4 addresses
    if ipv4_ips:
        if not ipset_exists(IPSET_NAME_V4):
            logger.info(f"IPv4 ipset does not exist, creating it")
            create_ipset(IPSET_NAME_V4, 'inet')
        else:
            logger.info(f"IPv4 ipset '{IPSET_NAME_V4}' already exists")

        update_ipset(IPSET_NAME_V4, ipv4_ips)
        ensure_ufw_rule_exists(tcp_port, IPSET_NAME_V4, 4)
    else:
        logger.info("No IPv4 addresses to manage")

    # Handle IPv6 addresses
    if ipv6_ips:
        if not ipset_exists(IPSET_NAME_V6):
            logger.info(f"IPv6 ipset does not exist, creating it")
            create_ipset(IPSET_NAME_V6, 'inet6')
        else:
            logger.info(f"IPv6 ipset '{IPSET_NAME_V6}' already exists")

        update_ipset(IPSET_NAME_V6, ipv6_ips)
        ensure_ufw_rule_exists(tcp_port, IPSET_NAME_V6, 6)
    else:
        logger.info("No IPv6 addresses to manage")

    # Make ipset persistent across reboots
    make_ipset_persistent()

    logger.info("Script completed successfully")
    logger.info(f"Total IP ranges managed: {len(github_ips)} (IPv4: {len(ipv4_ips)}, IPv6: {len(ipv6_ips)})")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
