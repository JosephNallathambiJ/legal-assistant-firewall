#!/usr/bin/env bash
# ==============================================================================
# HNX26EPS01 Security Gateway — Firewall Setup & Management Script
# Deploys, audits, or validates Layer 3 nftables rules.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
NFT_RULES="${GATEWAY_DIR}/firewall_rules.nft"

if ! command -v nft >/dev/null 2>&1; then
    echo "[-] ERROR: 'nft' utility is not installed on this host."
    exit 1
fi

if [[ ! -f "${NFT_RULES}" ]]; then
    echo "[-] ERROR: Firewall rules file not found: ${NFT_RULES}"
    exit 1
fi

ACTION="${1:-apply}"

case "${ACTION}" in
    --check|check)
        echo "[*] Checking nftables syntax for ${NFT_RULES}..."
        if [[ "$(id -u)" -eq 0 ]]; then
            nft -c -f "${NFT_RULES}"
            echo "[✓] nftables syntax validation passed."
        else
            echo "[!] Non-root user: kernel netlink verification requires root privileges."
            echo "[*] Verifying file structure and readability..."
            test -r "${NFT_RULES}"
            grep -q "table inet security_gateway" "${NFT_RULES}"
            grep -q "policy drop" "${NFT_RULES}"
            grep -q "iifname != \"lo\" tcp dport 3000" "${NFT_RULES}"
            echo "[✓] Static syntax and policy structure verified."
            echo "[i] To load rules into the kernel, run with root privileges: sudo ./scripts/setup_firewall.sh apply"
        fi
        ;;

    --status|status)
        echo "[*] Inspecting active nftables security_gateway table..."
        if [[ "$(id -u)" -eq 0 ]]; then
            nft list table inet security_gateway 2>/dev/null || echo "[!] security_gateway table is not currently loaded in kernel."
        else
            echo "[i] Root privileges required to inspect kernel nftables. Run: sudo nft list table inet security_gateway"
        fi
        ;;

    apply)
        if [[ "$(id -u)" -ne 0 ]]; then
            echo "[-] ERROR: Applying firewall rules to the kernel requires root privileges."
            echo "[i] Please run: sudo ./scripts/setup_firewall.sh apply"
            exit 1
        fi
        echo "[+] Loading nftables rules into Linux kernel..."
        nft -f "${NFT_RULES}"
        echo "[✓] Layer 3 packet filtering active: Default Deny, Loopback Port 3000 Isolation, Anti-Scan, Rate Limiting."
        ;;

    flush)
        if [[ "$(id -u)" -ne 0 ]]; then
            echo "[-] ERROR: Flushing firewall rules requires root privileges."
            exit 1
        fi
        echo "[!] Flushing security_gateway table..."
        nft delete table inet security_gateway 2>/dev/null || true
        echo "[✓] Table flushed."
        ;;

    *)
        echo "Usage: $0 [apply|check|status|flush]"
        exit 1
        ;;
esac
