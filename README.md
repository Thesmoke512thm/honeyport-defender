# Honeyport Defender

Defensive Python TCP honey port listener for isolated lab environments that logs decoy port connections as JSON Lines (jsonl) and optionally adds UFW deny rules when --enforce is passed.

## Architecture & Safety Design
- Safe default: Runs in dry-run simulation mode unless --enforce is explicitly passed.
- Explicit allowlisting: Keeps --whitelist addresses (such as 127.0.0.1 and trusted lab IPs) logged without blocking.
- Defensive-only scope: Listens on decoy TCP ports and blocks locally; performs no scanning back or offensive actions.

## Usage (Isolated Lab VM)
- Dry-run test: python3 honeyport.py --ports 2323 8088 9001 --whitelist 127.0.0.1
- Live UFW enforcement: sudo python3 honeyport.py --ports 2323 8088 9001 --whitelist 127.0.0.1 <TRUSTED_IP> --enforce

## Precautions, Cleanup & Limitations
- Self-lockout prevention: Never bind active SSH/management ports or omit trusted IPs from --whitelist when running --enforce.
- Reversing blocks: Stop with Ctrl+C, inspect rules with sudo ufw status numbered, and delete rules with sudo ufw delete <rule-number>.
- Limitations: Monitors completed TCP connections on decoy ports; does not cover UDP scans, spoofed-IP risks, NAT side effects, or automatic ban expiration.
