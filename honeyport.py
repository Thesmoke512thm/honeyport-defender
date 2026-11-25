import argparse
import datetime
import json
import socket
import subprocess
import threading


def log_event(log_file: str, payload: dict) -> None:
    line = json.dumps(payload)
    print(line, flush=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def block_ip(ip: str, whitelist: set[str], enforce: bool, log_file: str) -> None:
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if ip in whitelist:
        log_event(log_file, {
            "timestamp": timestamp,
            "event": "whitelisted_hit",
            "source_ip": ip,
            "action": "allowed_logged",
        })
        return

    cmd = ["ufw", "prepend", "deny", "from", ip, "to", "any"]
    if not enforce:
        log_event(log_file, {
            "timestamp": timestamp,
            "event": "honeyport_triggered",
            "source_ip": ip,
            "action": "dry_run_simulated",
            "command": " ".join(cmd),
        })
        return

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    log_event(log_file, {
        "timestamp": timestamp,
        "event": "honeyport_triggered",
        "source_ip": ip,
        "action": "ufw_deny_added" if result.returncode == 0 else "ufw_error",
        "stderr": result.stderr.strip(),
    })


def listen_port(port: int, whitelist: set[str], enforce: bool, log_file: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(16)
        while True:
            client, addr = server.accept()
            with client:
                client_ip = addr[0]
                client.settimeout(2.0)
                try:
                    banner_peek = client.recv(128)
                except socket.timeout:
                    banner_peek = b""
                timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
                log_event(log_file, {
                    "timestamp": timestamp,
                    "event": "connection_received",
                    "source_ip": client_ip,
                    "source_port": addr[1],
                    "honey_port": port,
                    "initial_bytes_len": len(banner_peek),
                })
                block_ip(client_ip, whitelist, enforce, log_file)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Defensive TCP Honey Port & UFW Active-Response Listener"
    )
    parser.add_argument("--ports", nargs="+", type=int, default=[2323, 8088, 9001])
    parser.add_argument("--whitelist", nargs="*", default=["127.0.0.1"])
    parser.add_argument("--log-file", default="honeyport_events.jsonl")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Apply live UFW deny rules (default is safe dry-run simulation)",
    )
    args = parser.parse_args()

    whitelist = set(args.whitelist)
    for port in args.ports:
        t = threading.Thread(
            target=listen_port,
            args=(port, whitelist, args.enforce, args.log_file),
            daemon=True,
        )
        t.start()

    mode = "ENFORCE (live UFW)" if args.enforce else "DRY-RUN (safe simulation)"
    print(f"Listening on TCP ports {args.ports} | mode={mode} | whitelist={sorted(whitelist)}")
    threading.Event().wait()


if __name__ == "__main__":
    main()
