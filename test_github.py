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
    """Tests for update_ipset function (swap-pattern rebuild)."""

    @patch('github.subprocess.run')
    def test_update_ipset_success(self, mock_run):
        """All ipset commands succeed → returns True and issues create/restore/swap/destroy."""
        mock_run.return_value = Mock()

        current_ips = ['192.168.1.0/24', '10.0.0.0/8']
        result = github.update_ipset('test-ipset', 'inet', 200000, current_ips)

        assert result is True
        # Expected calls: pre-cleanup destroy, create tmp, restore, swap, destroy tmp = 5
        assert mock_run.call_count == 5
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert commands[0][:2] == ['ipset', 'destroy']           # pre-cleanup
        assert commands[1][:3] == ['ipset', 'create', 'test-ipset-tmp']
        assert commands[2][:2] == ['ipset', 'restore']
        assert commands[3][:2] == ['ipset', 'swap']
        assert commands[4][:3] == ['ipset', 'destroy', 'test-ipset-tmp']

    @patch('github.subprocess.run')
    def test_update_ipset_restore_payload_contains_all_ips(self, mock_run):
        """The restore step should receive `add <tmp> <ip>` lines for every IP."""
        mock_run.return_value = Mock()
        ips = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']

        github.update_ipset('test-ipset', 'inet', 200000, ips)

        restore_call = mock_run.call_args_list[2]
        payload = restore_call.kwargs['input']
        for ip in ips:
            assert f"add test-ipset-tmp {ip}\n" in payload

    @patch('github.subprocess.run')
    def test_update_ipset_uses_correct_family_and_maxelem(self, mock_run):
        """create-tmp should be invoked with the given family and maxelem."""
        mock_run.return_value = Mock()

        github.update_ipset('test-ipset-v6', 'inet6', 16384, ['2001:db8::/32'])

        create_call = mock_run.call_args_list[1].args[0]
        assert 'inet6' in create_call
        assert '16384' in create_call

    @patch('github.subprocess.run')
    def test_update_ipset_empty_list(self, mock_run):
        """Empty IP list → short-circuit, no subprocess calls."""
        result = github.update_ipset('test-ipset', 'inet', 200000, [])
        assert result is True
        mock_run.assert_not_called()

    @patch('github.subprocess.run')
    def test_update_ipset_create_failure_returns_false(self, mock_run):
        """If creating the tmp set fails, returns False and cleans up tmp."""
        # 1st call: pre-cleanup destroy (succeeds, no check)
        # 2nd call: create tmp → raises
        # 3rd call: except-block cleanup destroy
        mock_run.side_effect = [
            Mock(),
            subprocess.CalledProcessError(1, 'ipset', stderr=b'Hash is full'),
            Mock(),
        ]

        result = github.update_ipset('test-ipset', 'inet', 200000, ['192.168.1.0/24'])

        assert result is False
        assert mock_run.call_count == 3

    @patch('github.subprocess.run')
    def test_update_ipset_swap_failure_returns_false(self, mock_run):
        """Failure during swap returns False; tmp set is destroyed in cleanup."""
        mock_run.side_effect = [
            Mock(),  # pre-cleanup destroy
            Mock(),  # create tmp
            Mock(),  # restore
            subprocess.CalledProcessError(1, 'ipset', stderr=b'swap failed'),  # swap
            Mock(),  # except-block cleanup destroy
        ]

        result = github.update_ipset('test-ipset', 'inet', 200000, ['192.168.1.0/24'])
        assert result is False
        assert mock_run.call_count == 5


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


class TestCheckUFWRulesInConfig:
    """Tests for check_ufw_rules_in_config function."""

    @patch('github.os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='# Some UFW rules\n-A ufw-before-input -j ACCEPT\n')
    def test_rules_not_found(self, mock_file, mock_exists):
        """Test when GitHub Actions rules are not in config."""
        mock_exists.return_value = True

        result = github.check_ufw_rules_in_config('/etc/ufw/before.rules', 'github-actions-v4')
        assert result is False

    @patch('github.os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='# GitHub Actions ipset rules\n-A ufw-before-input -m set --match-set github-actions-v4 src -j ACCEPT\n')
    def test_rules_found(self, mock_file, mock_exists):
        """Test when GitHub Actions rules exist in config."""
        mock_exists.return_value = True

        result = github.check_ufw_rules_in_config('/etc/ufw/before.rules', 'github-actions-v4')
        assert result is True

    @patch('github.os.path.exists')
    def test_config_file_not_exists(self, mock_exists):
        """Test when config file doesn't exist."""
        mock_exists.return_value = False

        result = github.check_ufw_rules_in_config('/etc/ufw/before.rules', 'github-actions-v4')
        assert result is False


class TestAddRulesToUFWConfig:
    """Tests for add_rules_to_ufw_config function."""

    @patch('github.os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='# Existing rules\n-A ufw-before-input -j ACCEPT\nCOMMIT\n')
    def test_add_ipv4_rules(self, mock_file, mock_exists):
        """Test adding IPv4 rules to before.rules."""
        mock_exists.return_value = True

        result = github.add_rules_to_ufw_config('/etc/ufw/before.rules', 'github-actions-v4', 22)
        assert result is True

        # Verify file operations occurred
        assert mock_file.call_count >= 2  # At least read and write

    @patch('github.os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='# Existing rules\n-A ufw6-before-input -j ACCEPT\nCOMMIT\n')
    def test_add_ipv6_rules(self, mock_file, mock_exists):
        """Test adding IPv6 rules to before6.rules."""
        mock_exists.return_value = True

        result = github.add_rules_to_ufw_config('/etc/ufw/before6.rules', 'github-actions-v6', 22)
        assert result is True

    @patch('github.os.path.exists')
    def test_config_file_not_exists(self, mock_exists):
        """Test when config file doesn't exist."""
        mock_exists.return_value = False

        result = github.add_rules_to_ufw_config('/etc/ufw/before.rules', 'github-actions-v4', 22)
        assert result is False

    @patch('github.os.path.exists')
    @patch('builtins.open', side_effect=PermissionError())
    def test_permission_error(self, mock_file, mock_exists):
        """Test handling permission errors."""
        mock_exists.return_value = True

        result = github.add_rules_to_ufw_config('/etc/ufw/before.rules', 'github-actions-v4', 22)
        assert result is False


class TestReloadUFW:
    """Tests for reload_ufw function."""

    @patch('github.subprocess.run')
    def test_reload_success(self, mock_run):
        """Test successful UFW reload."""
        mock_run.return_value = Mock()

        result = github.reload_ufw()
        assert result is True
        mock_run.assert_called_once()

    @patch('github.subprocess.run')
    def test_reload_failure(self, mock_run):
        """Test failed UFW reload."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'ufw')

        result = github.reload_ufw()
        assert result is False


class TestEnsureUFWRuleExistsV2:
    """Tests for updated ensure_ufw_rule_exists using config files."""

    @patch('github.check_ufw_rules_in_config')
    def test_rules_already_exist(self, mock_check):
        """Test when rules already exist in config."""
        mock_check.return_value = True

        result = github.ensure_ufw_rule_exists(22, 'github-actions-v4', 4)
        assert result is True

    @patch('github.reload_ufw')
    @patch('github.add_rules_to_ufw_config')
    @patch('github.check_ufw_rules_in_config')
    def test_add_new_rules_ipv4(self, mock_check, mock_add, mock_reload):
        """Test adding new IPv4 rules."""
        mock_check.return_value = False
        mock_add.return_value = True
        mock_reload.return_value = True

        result = github.ensure_ufw_rule_exists(22, 'github-actions-v4', 4)
        assert result is True
        mock_add.assert_called_with('/etc/ufw/before.rules', 'github-actions-v4', 22)
        mock_reload.assert_called_once()

    @patch('github.reload_ufw')
    @patch('github.add_rules_to_ufw_config')
    @patch('github.check_ufw_rules_in_config')
    def test_add_new_rules_ipv6(self, mock_check, mock_add, mock_reload):
        """Test adding new IPv6 rules."""
        mock_check.return_value = False
        mock_add.return_value = True
        mock_reload.return_value = True

        result = github.ensure_ufw_rule_exists(22, 'github-actions-v6', 6)
        assert result is True
        mock_add.assert_called_with('/etc/ufw/before6.rules', 'github-actions-v6', 22)

    @patch('github.add_rules_to_ufw_config')
    @patch('github.check_ufw_rules_in_config')
    def test_add_rules_fails(self, mock_check, mock_add):
        """Test when adding rules fails."""
        mock_check.return_value = False
        mock_add.return_value = False

        result = github.ensure_ufw_rule_exists(22, 'github-actions-v4', 4)
        assert result is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
