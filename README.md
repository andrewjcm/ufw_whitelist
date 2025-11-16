# GitHub Actions UFW Whitelist

Automatically whitelist GitHub Actions IP ranges in UFW firewall for a specified TCP port using **ipset** for efficient management of thousands of IPs.

## Overview

This script fetches the current GitHub Actions IP ranges from GitHub's public API and automatically configures UFW (Uncomplicated Firewall) rules using **ipset** to allow traffic from these IPs to a specified TCP port.

**Why ipset?** GitHub provides 5000+ IP ranges for Actions. Using individual UFW rules would be extremely slow (hours to update). ipset allows managing all IPs efficiently with a single firewall rule, updating in seconds instead of hours.

## Features

- **High Performance**: Uses ipset to manage 5000+ IPs efficiently (single rule instead of thousands)
- Fetches GitHub Actions IP ranges from GitHub's official API
- Automatically updates ipset with new IP ranges
- Removes stale IPs when no longer in GitHub's list
- Persistent across reboots
- Comprehensive logging to `/var/log/github-ufw-whitelist.log`
- Configurable TCP port via environment variable
- Safe to run multiple times (idempotent)

## Requirements

- Python 3.7 or higher
- UFW (Uncomplicated Firewall)
- **ipset** (for efficient IP set management)
- **iptables-persistent** (recommended, for persistence)
- Root/sudo access
- [uv](https://github.com/astral-sh/uv) package manager

## Installation

### 1. Install System Dependencies

First, install ipset and iptables-persistent:

```bash
sudo apt-get update
sudo apt-get install -y ipset iptables-persistent
```

### 2. Clone the Repository

```bash
cd /opt
sudo git clone https://github.com/andrewjcm/ufw_whitelist.git ufw_whitelist
cd ufw_whitelist
```

### 3. Install uv (if not already installed)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 4. Install Python Dependencies

```bash
uv sync
```

### 5. Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

Edit the `.env` file and set your desired TCP port:

```env
TCP_PORT=22  # Change to your desired port (e.g., 22 for SSH, 443 for HTTPS)
```

### 6. Create Log Directory and File

```bash
sudo touch /var/log/github-ufw-whitelist.log
sudo chmod 640 /var/log/github-ufw-whitelist.log
```

### 7. Test the Script

Run the script manually to ensure it works:

```bash
sudo uv run github.py
```

Check the log file for any errors:

```bash
sudo tail -f /var/log/github-ufw-whitelist.log
```

Verify ipset was created and populated:

```bash
sudo ipset list github-actions | head -n 20
```

Verify UFW/iptables rule was added:

```bash
sudo iptables -L ufw-user-input -n -v | grep github-actions
```

## Crontab Setup

To automatically update the whitelist, set up a crontab job running as root.

### 1. Edit Root Crontab

```bash
sudo crontab -e
```

### 2. Add Crontab Entry

Add one of the following entries based on your preference:

**Run daily at 3:00 AM:**
```cron
0 3 * * * cd /opt/ufw_whitelist && /root/.local/bin/uv run github.py
```

**Run every 6 hours:**
```cron
0 */6 * * * cd /opt/ufw_whitelist && /root/.local/bin/uv run github.py
```

**Run weekly on Sunday at 2:00 AM:**
```cron
0 2 * * 0 cd /opt/ufw_whitelist && /root/.local/bin/uv run github.py
```

**Note:** Adjust the path to `uv` if it's installed in a different location. You can find it with:
```bash
sudo which uv
```

### 3. Verify Crontab

List the root crontab to verify:

```bash
sudo crontab -l
```

## How It Works

The script uses **ipset** for efficient management of thousands of IP addresses:

1. **Fetch IPs**: Fetches the latest GitHub Actions IP ranges from `https://api.github.com/meta` (typically 5000+ IPs)
2. **Create/Update ipset**:
   - Creates an ipset named `github-actions` if it doesn't exist
   - Uses batch operations to efficiently add/remove IPs
3. **Compare & Update**: Compares current IPs with existing ipset entries
4. **Remove Stale IPs**: Removes IPs no longer in GitHub's list
5. **Add New IPs**: Adds new IPs using efficient batch method
6. **Single Firewall Rule**: Creates ONE iptables rule that references the entire ipset
7. **Persist**: Saves ipset and iptables rules to survive reboots
8. **Log**: All actions are logged to `/var/log/github-ufw-whitelist.log`

### Why ipset is Fast

Traditional approach: 5000 individual UFW commands = **hours**

ipset approach: Single ipset with batch updates = **seconds**

## Technical Details

The script creates:

1. **ipset** named `github-actions` containing all GitHub Actions IP ranges
2. **Single iptables rule** that allows traffic from any IP in the ipset:

```bash
iptables -I ufw-user-input -p tcp --dport <PORT> -m set --match-set github-actions src -j ACCEPT
```

This is equivalent to having one rule that matches against 5000+ IPs, but executes in O(1) time.

## Monitoring

### View Logs

```bash
sudo tail -f /var/log/github-ufw-whitelist.log
```

### Check ipset Contents

```bash
# List all IPs in the ipset
sudo ipset list github-actions

# Count total IPs
sudo ipset list github-actions | grep "Number of entries"

# View first 20 entries
sudo ipset list github-actions | head -n 30
```

### Check Firewall Rule

```bash
# Check iptables rule
sudo iptables -L ufw-user-input -n -v | grep github-actions

# Check UFW status
sudo ufw status verbose
```

### Manual Run

```bash
sudo uv run github.py
```

## Troubleshooting

### Script Fails with "ipset is not installed"

Install ipset:

```bash
sudo apt-get install ipset
```

### Script Fails with "Must be run as root"

Ensure you're running the script with sudo or as root user:

```bash
sudo uv run github.py
```

### UFW Not Enabled

If UFW is not enabled, enable it first:

```bash
sudo ufw enable
```

### ipset Not Persisting After Reboot

Ensure iptables-persistent is installed and configured:

```bash
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

The script also saves ipset to `/etc/ipset/ipset.rules`. To restore on boot, create a systemd service:

```bash
sudo nano /etc/systemd/system/ipset-restore.service
```

Add:

```ini
[Unit]
Description=Restore ipset rules
Before=netfilter-persistent.service

[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -f /etc/ipset/ipset.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl enable ipset-restore.service
sudo systemctl start ipset-restore.service
```

### Log Permission Issues

Ensure the log file exists and has proper permissions:

```bash
sudo touch /var/log/github-ufw-whitelist.log
sudo chmod 640 /var/log/github-ufw-whitelist.log
```

### Crontab Not Running

Check cron service status:

```bash
sudo systemctl status cron
```

Check syslog for cron execution:

```bash
grep CRON /var/log/syslog
```

### Check if IPs are Being Matched

Test if traffic from a specific GitHub Actions IP is allowed:

```bash
# Check recent connections
sudo iptables -L ufw-user-input -n -v

# The packet counter should increment when traffic matches
```

## Security Considerations

- The `.env` file is excluded from version control (see `.gitignore`)
- Always review UFW rules after running the script
- Consider restricting the TCP port to only necessary services
- Regularly monitor logs for unexpected behavior
- GitHub's IP ranges can change; ensure crontab runs regularly

## Uninstallation

To completely remove the GitHub Actions whitelist:

### 1. Remove iptables Rule

```bash
# Find the rule
sudo iptables -L ufw-user-input --line-numbers | grep github-actions

# Delete it (replace X with the line number)
sudo iptables -D ufw-user-input X

# Save the change
sudo netfilter-persistent save
```

### 2. Destroy the ipset

```bash
sudo ipset destroy github-actions
```

### 3. Remove Persistent Files

```bash
sudo rm -f /etc/ipset/ipset.rules
```

### 4. Remove Crontab Entry

```bash
sudo crontab -e
# Remove the line containing github.py
```

### 5. Optional: Remove the Project

```bash
sudo rm -rf /opt/ufw_whitelist
```

## License

MIT License - Feel free to use and modify as needed.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.
