# GitHub Actions UFW Whitelist

Automatically whitelist GitHub Actions IP ranges in UFW firewall for a specified TCP port.

## Overview

This script fetches the current GitHub Actions IP ranges from GitHub's public API and automatically configures UFW (Uncomplicated Firewall) rules to allow traffic from these IPs to a specified TCP port. It's designed to run via crontab to keep the whitelist up-to-date as GitHub updates their IP ranges.

## Features

- Fetches GitHub Actions IP ranges from GitHub's official API
- Automatically adds UFW rules for new IP ranges
- Removes stale rules when IPs are no longer in GitHub's list
- Comprehensive logging to `/var/log/github-ufw-whitelist.log`
- Configurable TCP port via environment variable
- Safe to run multiple times (idempotent)

## Requirements

- Python 3.7 or higher
- UFW (Uncomplicated Firewall)
- Root/sudo access
- [uv](https://github.com/astral-sh/uv) package manager

## Installation

### 1. Clone the Repository

```bash
cd /opt
git clone <repository-url> ufw_whitelist
cd ufw_whitelist
```

### 2. Install uv (if not already installed)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 3. Install Dependencies

```bash
uv sync
```

### 4. Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

Edit the `.env` file and set your desired TCP port:

```env
TCP_PORT=22  # Change to your desired port (e.g., 22 for SSH, 443 for HTTPS)
```

### 5. Create Log Directory and File

```bash
sudo touch /var/log/github-ufw-whitelist.log
sudo chmod 640 /var/log/github-ufw-whitelist.log
```

### 6. Test the Script

Run the script manually to ensure it works:

```bash
sudo uv run github.py
```

Check the log file for any errors:

```bash
sudo tail -f /var/log/github-ufw-whitelist.log
```

Verify UFW rules were added:

```bash
sudo ufw status numbered | grep "GitHub Actions"
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

1. **Fetch IPs**: The script fetches the latest GitHub Actions IP ranges from `https://api.github.com/meta`
2. **Compare**: It compares the current IPs with existing UFW rules
3. **Remove Stale Rules**: Any rules for IPs no longer in GitHub's list are removed
4. **Add New Rules**: New IPs are added as UFW rules with the comment "GitHub Actions"
5. **Log**: All actions are logged to `/var/log/github-ufw-whitelist.log`

## UFW Rules Format

The script creates rules in this format:

```
ufw allow from <IP_RANGE> to any port <TCP_PORT> proto tcp comment "GitHub Actions"
```

Example:

```
ufw allow from 192.30.252.0/22 to any port 22 proto tcp comment "GitHub Actions"
```

## Monitoring

### View Logs

```bash
sudo tail -f /var/log/github-ufw-whitelist.log
```

### Check UFW Rules

```bash
sudo ufw status numbered | grep "GitHub Actions"
```

### Manual Run

```bash
sudo uv run github.py
```

## Troubleshooting

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

## Security Considerations

- The `.env` file is excluded from version control (see `.gitignore`)
- Always review UFW rules after running the script
- Consider restricting the TCP port to only necessary services
- Regularly monitor logs for unexpected behavior
- GitHub's IP ranges can change; ensure crontab runs regularly

## Uninstallation

To remove all GitHub Actions UFW rules:

```bash
# Get rule numbers
sudo ufw status numbered | grep "GitHub Actions"

# Delete each rule (replace X with rule number, starting from highest)
sudo ufw delete X
```

Remove crontab entry:

```bash
sudo crontab -e
# Remove the line containing github.py
```

## License

MIT License - Feel free to use and modify as needed.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.
