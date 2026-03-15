#!/bin/bash
# nuke-firewall.sh
# Author: Dylan Harvey
# Description: Interactive firewall hardening script that restores backup if you block yourself
# Dependencies: nftables (nft), systemd (systemctl)
# WARNING: WILL BREAK SERVICES!!!

# === CONFIG ===
ALLOW_IPS="10.2.0.0/24"  # CHANGE, Supports CIDR or individual IPs (comma-separated)
INBOUND_ACTION="drop"  # default drop
OUTBOUND_ACTION="drop"  # default accept (Block super strict, will stop C2+RevShell and probably break more stuff)
BACKUP_PATH="./nftables_backup.rules"
CONF_FILE="/etc/nftables.conf"
RULE_COMMENT="BLUE_TEAM_MGMT"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

echo "Creating backup at $BACKUP_PATH..."
nft list ruleset > "$BACKUP_PATH"

echo "Generating new nftables configuration..."

cat <<EOF > /tmp/new_nftables.rules
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy $INBOUND_ACTION;

        ct state invalid drop
        iif "lo" accept
        ct state established,related accept

        ip saddr { $ALLOW_IPS } accept comment $RULE_COMMENT
        
        log prefix "NFT_INPUT_POLICY: " flags all
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy $OUTBOUND_ACTION;

        oif "lo" accept
        ct state established,related accept

        ip daddr { $ALLOW_IPS } accept comment $RULE_COMMENT

        log prefix "NFT_OUTPUT_POLICY: " flags all
    }
}
EOF

echo "Applying rules..."
nft -f /tmp/new_nftables.rules

echo "\n--- SAFETY REVERT ENABLED ---"
echo "Press 'y' to KEEP these settings. Reverting in 10 seconds..."

read -t 10 -n 1 -p "Confirm (y/n): " confirm

if [[ $confirm == "y" || $confirm == "Y" ]]; then
    echo "\nSettings CONFIRMED."
    cp /tmp/new_nftables.rules "$CONF_FILE"
    systemctl enable --now nftables
    echo "Configuration saved to $CONF_FILE and service enabled."
else
    echo -e "\nNO INPUT OR REJECTED. REVERTING..."
    nft -f "$BACKUP_PATH"
    echo -e "Firewall restored to previous state."
fi
