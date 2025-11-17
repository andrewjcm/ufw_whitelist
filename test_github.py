"""
Unit tests for github.py

Tests the GitHub Actions UFW whitelist script functionality.
"""

import pytest
import os
import subprocess
from unittest.mock import Mock, patch, mock_open, MagicMock
import tempfile

# Import functions from github.py
import github


class TestLoadConfig:
    """Tests for load_config function."""

    @patch('github.load_dotenv')
    def test_load_config_valid_port(self, mock_dotenv, monkeypatch):
        """Test loading a valid port configuration."""
        monkeypatch.setenv('TCP_PORT', '22')
        port = github.load_config()
        assert port == 22

    @patch('github.load_dotenv')
    def test_load_config_valid_port_high(self, mock_dotenv, monkeypatch):
        """Test loading a valid high port number."""
        monkeypatch.setenv('TCP_PORT', '65535')
        port = github.load_config()
        assert port == 65535

    @patch('github.load_dotenv')
    def test_load_config_missing_port(self, mock_dotenv, monkeypatch):
        """Test that missing TCP_PORT raises SystemExit."""
        monkeypatch.delenv('TCP_PORT', raising=False)
        with pytest.raises(SystemExit):
            github.load_config()

    @patch('github.load_dotenv')
    def test_load_config_invalid_port_string(self, mock_dotenv, monkeypatch):
        """Test that non-numeric port raises SystemExit."""
        monkeypatch.setenv('TCP_PORT', 'not_a_number')
        with pytest.raises(SystemExit):
            github.load_config()

    @patch('github.load_dotenv')
    def test_load_config_port_out_of_range_low(self, mock_dotenv, monkeypatch):
        """Test that port 0 raises SystemExit."""
        monkeypatch.setenv('TCP_PORT', '0')
        with pytest.raises(SystemExit):
            github.load_config()

    @patch('github.load_dotenv')
    def test_load_config_port_out_of_range_high(self, mock_dotenv, monkeypatch):
        """Test that port > 65535 raises SystemExit."""
        monkeypatch.setenv('TCP_PORT', '65536')
        with pytest.raises(SystemExit):
            github.load_config()


class TestSeparateIPFamilies:
    """Tests for separate_ip_families function."""

    def test_separate_ipv4_only(self):
        """Test separating IPv4 addresses only."""
        ip_list = [
            '192.168.1.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12'
        ]
        ipv4, ipv6 = github.separate_ip_families(ip_list)
        assert len(ipv4) == 3
        assert len(ipv6) == 0
        assert ipv4 == ip_list

    def test_separate_ipv6_only(self):
        """Test separating IPv6 addresses only."""
        ip_list = [
            '2001:db8::/32',
            'fe80::/10',
            '::1/128'
        ]
        ipv4, ipv6 = github.separate_ip_families(ip_list)
        assert len(ipv4) == 0
        assert len(ipv6) == 3
        assert ipv6 == ip_list

    def test_separate_mixed_ips(self):
        """Test separating mixed IPv4 and IPv6 addresses."""
        ip_list = [
            '192.168.1.0/24',
            '2001:db8::/32',
            '10.0.0.0/8',
            'fe80::/10',
            '172.16.0.0/12',
            '::1/128'
        ]
        ipv4, ipv6 = github.separate_ip_families(ip_list)
        assert len(ipv4) == 3
        assert len(ipv6) == 3
        assert '192.168.1.0/24' in ipv4
        assert '2001:db8::/32' in ipv6

    def test_separate_single_ips(self):
        """Test separating single IPs without CIDR notation."""
        ip_list = [
            '192.168.1.1',
            '2001:db8::1'
        ]
        ipv4, ipv6 = github.separate_ip_families(ip_list)
        assert len(ipv4) == 1
        assert len(ipv6) == 1

    def test_separate_invalid_ips(self):
        """Test that invalid IPs are skipped."""
        ip_list = [
            '192.168.1.0/24',
            'invalid_ip',
            '2001:db8::/32',
            'not.an.ip.address'
        ]
        ipv4, ipv6 = github.separate_ip_families(ip_list)
        assert len(ipv4) == 1
        assert len(ipv6) == 1
        # Invalid IPs should be skipped

    def test_separate_empty_list(self):
        """Test separating empty list."""
        ipv4, ipv6 = github.separate_ip_families([])
        assert len(ipv4) == 0
        assert len(ipv6) == 0


class TestFetchGitHubActionsIPs:
    """Tests for fetch_github_actions_ips function."""

    @patch('github.requests.get')
    def test_fetch_success(self, mock_get):
        """Test successful fetching of GitHub Actions IPs."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'actions': [
                '192.30.252.0/22',
                '185.199.108.0/22',
                '2001:db8::/32'
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        ips = github.fetch_github_actions_ips()
        assert len(ips) == 3
        assert '192.30.252.0/22' in ips

    @patch('github.requests.get')
    def test_fetch_empty_actions(self, mock_get):
        """Test fetching when no actions IPs are returned."""
        mock_response = Mock()
        mock_response.json.return_value = {'actions': []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        ips = github.fetch_github_actions_ips()
        assert ips == []

    @patch('github.requests.get')
    def test_fetch_missing_actions_key(self, mock_get):
        """Test fetching when 'actions' key is missing."""
        mock_response = Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        ips = github.fetch_github_actions_ips()
        assert ips == []

    @patch('github.requests.get')
    def test_fetch_network_error(self, mock_get):
        """Test network error handling."""
        import requests
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(SystemExit):
            github.fetch_github_actions_ips()

    @patch('github.requests.get')
    def test_fetch_timeout(self, mock_get):
        """Test timeout handling."""
        import requests
        mock_get.side_effect = requests.Timeout("Request timeout")

        with pytest.raises(SystemExit):
            github.fetch_github_actions_ips()


class TestIPSetExists:
    """Tests for ipset_exists function."""

    @patch('github.subprocess.run')
    def test_ipset_exists_true(self, mock_run):
        """Test when ipset exists."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = github.ipset_exists('test-ipset')
        assert result is True

    @patch('github.subprocess.run')
    def test_ipset_exists_false(self, mock_run):
        """Test when ipset does not exist."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        result = github.ipset_exists('test-ipset')
        assert result is False

    @patch('github.subprocess.run')
    def test_ipset_exists_exception(self, mock_run):
        """Test exception handling."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'ipset')

        result = github.ipset_exists('test-ipset')
        assert result is False


class TestCreateIPSet:
    """Tests for create_ipset function."""

    @patch('github.subprocess.run')
    def test_create_ipset_ipv4_success(self, mock_run):
        """Test successful creation of IPv4 ipset."""
        mock_run.return_value = Mock()

        result = github.create_ipset('test-ipset-v4', 'inet')
        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert 'ipset' in call_args
        assert 'create' in call_args
        assert 'test-ipset-v4' in call_args
        assert 'inet' in call_args

    @patch('github.subprocess.run')
    def test_create_ipset_ipv6_success(self, mock_run):
        """Test successful creation of IPv6 ipset."""
        mock_run.return_value = Mock()

        result = github.create_ipset('test-ipset-v6', 'inet6')
        assert result is True
        call_args = mock_run.call_args[0][0]
        assert 'inet6' in call_args

    @patch('github.subprocess.run')
    def test_create_ipset_failure(self, mock_run):
        """Test failed ipset creation."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, 'ipset', stderr=b'Error creating ipset'
        )

        result = github.create_ipset('test-ipset', 'inet')
        assert result is False


class TestGetIPSetEntries:
    """Tests for get_ipset_entries function."""

    @patch('github.subprocess.run')
    def test_get_entries_success(self, mock_run):
        """Test getting ipset entries successfully."""
        mock_result = Mock()
        mock_result.stdout = """Name: test-ipset
Type: hash:net
Revision: 7
Header: family inet hashsize 1024 maxelem 65536
Size in memory: 1024
References: 1
Number of entries: 3
Members:
192.168.1.0/24
10.0.0.0/8
172.16.0.0/12
"""
        mock_run.return_value = mock_result

        entries = github.get_ipset_entries('test-ipset')
        assert len(entries) == 3
        assert '192.168.1.0/24' in entries
        assert '10.0.0.0/8' in entries

    @patch('github.subprocess.run')
    def test_get_entries_empty(self, mock_run):
        """Test getting entries from empty ipset."""
        mock_result = Mock()
        mock_result.stdout = """Name: test-ipset
Type: hash:net
Members:
"""
        mock_run.return_value = mock_result

        entries = github.get_ipset_entries('test-ipset')
        assert len(entries) == 0

    @patch('github.subprocess.run')
    def test_get_entries_error(self, mock_run):
        """Test error handling when getting entries."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'ipset')

        entries = github.get_ipset_entries('test-ipset')
        assert entries == set()


class TestUpdateIPSet:
    """Tests for update_ipset function."""

    @patch('github.os.unlink')
    @patch('github.open', new_callable=mock_open)
    @patch('github.get_ipset_entries')
    @patch('github.subprocess.run')
    @patch('github.tempfile.NamedTemporaryFile')
    def test_update_ipset_add_new(self, mock_tempfile, mock_run, mock_get_entries, mock_open_file, mock_unlink):
        """Test adding new IPs to ipset."""
        # Mock existing entries (empty)
        mock_get_entries.return_value = set()

        # Mock temporary file
        mock_file = MagicMock()
        mock_file.name = '/tmp/test_file'
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        mock_file.write = MagicMock()
        mock_tempfile.return_value.__enter__.return_value = mock_file

        # Mock subprocess
        mock_run.return_value = Mock()

        current_ips = ['192.168.1.0/24', '10.0.0.0/8']
        result = github.update_ipset('test-ipset', current_ips)

        assert result is True
        # Verify batch restore was called
        assert mock_run.call_count >= 1
        # Verify temp file was deleted
        mock_unlink.assert_called_once()

    @patch('github.get_ipset_entries')
    @patch('github.subprocess.run')
    def test_update_ipset_remove_stale(self, mock_run, mock_get_entries):
        """Test removing stale IPs from ipset."""
        # Mock existing entries
        mock_get_entries.return_value = {'192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12'}

        # Current IPs (missing 172.16.0.0/12)
        current_ips = ['192.168.1.0/24', '10.0.0.0/8']
        result = github.update_ipset('test-ipset', current_ips)

        assert result is True

    @patch('github.get_ipset_entries')
    def test_update_ipset_empty_list(self, mock_get_entries):
        """Test updating with empty IP list."""
        mock_get_entries.return_value = set()

        result = github.update_ipset('test-ipset', [])
        assert result is True

    @patch('github.get_ipset_entries')
    @patch('github.subprocess.run')
    def test_update_ipset_no_changes(self, mock_run, mock_get_entries):
        """Test updating when IPs are already current."""
        existing = {'192.168.1.0/24', '10.0.0.0/8'}
        mock_get_entries.return_value = existing

        current_ips = ['192.168.1.0/24', '10.0.0.0/8']
        result = github.update_ipset('test-ipset', current_ips)

        assert result is True


class TestCheckIPSetInstalled:
    """Tests for check_ipset_installed function."""

    @patch('github.subprocess.run')
    def test_ipset_installed(self, mock_run):
        """Test when ipset is installed."""
        mock_run.return_value = Mock()

        result = github.check_ipset_installed()
        assert result is True

    @patch('github.subprocess.run')
    def test_ipset_not_installed(self, mock_run):
        """Test when ipset is not installed."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(SystemExit):
            github.check_ipset_installed()


class TestEnsureUFWRuleExists:
    """Tests for ensure_ufw_rule_exists function."""

    @patch('github.subprocess.run')
    def test_create_ipv4_rule(self, mock_run):
        """Test creating IPv4 iptables rule."""
        # First call: check if rule exists (not found)
        # Second call: create the rule
        mock_result = Mock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = github.ensure_ufw_rule_exists(22, 'test-ipset-v4', 4)
        assert result is True

    @patch('github.subprocess.run')
    def test_create_ipv6_rule(self, mock_run):
        """Test creating IPv6 ip6tables rule."""
        mock_result = Mock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = github.ensure_ufw_rule_exists(22, 'test-ipset-v6', 6)
        assert result is True
        # Verify ip6tables was called
        call_args = mock_run.call_args_list
        assert any('ip6tables' in str(call) for call in call_args)

    @patch('github.subprocess.run')
    def test_rule_already_exists(self, mock_run):
        """Test when rule already exists."""
        mock_result = Mock()
        mock_result.stdout = "match-set test-ipset-v4"
        mock_run.return_value = mock_result

        result = github.ensure_ufw_rule_exists(22, 'test-ipset-v4', 4)
        assert result is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
