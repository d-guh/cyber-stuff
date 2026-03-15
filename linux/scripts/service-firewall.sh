# service-firewall.sh
# Author: Dylan Harvey
# Description: Interactive firewall script that adds rules required for AD and common services
# Dependencies: nftables (nft), bash, tr, xargs, systemctl/service
# Note: Designed to be run after nuke-firewall.sh, but technically OK to be run standalone

# === CONFIG ===
SCOREBOARD_IPS="10.3.2.1"    # CHANGE, Supports CIDR and individual IPs (space or comma separated)
DC_IPS="10.3.4.1 10.3.4.2"   # CHANGE, Supports CIDR and individual IPs (space or comma separated)
DM_IPS="10.3.4.0/24"         # CHANGE, Supports CIDR and individual IPs (space or comma separated)
DOMAIN_IPS="$DC_IPS $DM_IPS"
ALL_IPS="$SCOREBOARD_IPS $DOMAIN_IPS"

BACKUP_PATH="/etc/nftables.conf.bak"
CONF_FILE="/etc/nftables.conf"
TMP_RULES="/tmp/nftables_new.conf"

# TODO: Role Detection
IS_DC=false
IS_DM=true

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# === HELPERS ===
backup_rules() {
    if [[ -f "$CONF_FILE" ]]; then
        cp "$CONF_FILE" "$BACKUP_PATH"
        echo "[+] Backup created at $BACKUP_PATH"
    fi
}

apply_and_test() {
    echo "[*] Verifying syntax..."
    if ! nft -c -f "$TMP_RULES"; then
        echo "[!] SYNTAX ERROR: Aborting."
        return 1
    fi

    cp "$TMP_RULES" "$CONF_FILE"
    systemctl restart nftables
    
    echo -e "\n--- SAFETY REVERT CHECK ---"
    read -t 10 -n 1 -p "Press 'y' to KEEP these settings. Reverting in 10s: " confirm
    if [[ $confirm == [yY] ]]; then
        echo -e "\n[+] Settings CONFIRMED."
    else
        echo -e "\n[!] REVERTING to backup..."
        cp "$BACKUP_PATH" "$CONF_FILE"
        systemctl restart nftables
        exit 1
    fi
}

# === RULE GENERATION ===
echo "[*] Generating ruleset..."

cat <<EOF > "$TMP_RULES"
flush ruleset

table inet filter {
    # Sets for cleaner rules
    set scoreboard_ips { type ipv4_addr; elements = { $(echo $SCOREBOARD_IPS | tr -d ' ') } }
    set dc_ips { type ipv4_addr; flags interval; elements = { $(echo $DC_IPS | tr -d ' ') } }
    set domain_ips { type ipv4_addr; flags interval; elements = { $(echo $DOMAIN_IPS | tr -d ' ') } }
    set all_trusted { type ipv4_addr; flags interval; elements = { $(echo $ALL_IPS | tr -d ' ') } }

    chain input {
        type filter hook input priority 0; policy drop;

        # Global Defaults
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop

        # ICMP (Ping) - Types 3, 8, 11
        icmp type { echo-request, destination-unreachable, time-exceeded } accept

        # Management (RDP/WinRM equivalents: SSH/Webmin)
        ip saddr @domain_ips tcp dport { 22, 5985, 5986 } accept comment "MGMT-In"
EOF

if [ "$IS_DC" = true ]; then
    cat <<EOF >> "$TMP_RULES"
        # Domain Controller Inbound
        ip saddr @domain_ips tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535 } accept comment "AD-Services-TCP"
        ip saddr @domain_ips udp dport { 53, 88, 123, 135, 389, 445, 464 } accept comment "AD-Services-UDP"
        ip saddr @dc_ips tcp dport 5722 accept comment "DC-DFS-R"
EOF
elif [ "$IS_DM" = true ]; then
    cat <<EOF >> "$TMP_RULES"
        # Domain Member Inbound (RPC High Ports from DC)
        ip saddr @dc_ips tcp dport 49152-65535 accept comment "DM-In-RPC"
EOF
fi

cat <<EOF >> "$TMP_RULES"
    }

    chain output {
        type filter hook output priority 0; policy accept;
        
        # Outbound AD requirements (Specific to DC/DM)
EOF

if [ "$IS_DM" = true ]; then
    echo "        ip daddr @dc_ips tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535 } accept" >> "$TMP_RULES"
fi

cat <<EOF >> "$TMP_RULES"
    }
}
EOF

# === EXECUTION ===
backup_rules
apply_and_test

# === OPTIONAL SERVICES ===
# TODO: Optional services, may need to put above during rule generation
