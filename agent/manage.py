import argparse
import getpass
import json
import subprocess
import uuid
from pathlib import Path

from agent.audit_agent import open_spool
from agent.config import load, save
from agent.uploader import request, upload_one


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["enroll", "status", "upload", "test", "diagnostics"])
    parser.add_argument("--kind", choices=["agents", "probes"], default="agents")
    parser.add_argument("--config", default="/opt/xray-audit/config.json")
    parser.add_argument("--server")
    parser.add_argument("--enroll-token")
    parser.add_argument("--name")
    parser.add_argument("--region")
    args = parser.parse_args()
    if args.action == "enroll":
        server = args.server or input("中央 HTTPS 地址: ").strip()
        if not server.startswith("https://"):
            raise SystemExit("HTTPS required")
        token = args.enroll_token or getpass.getpass("一次性 Enrollment Token: ")
        name = args.name or input("VPS / Probe 名称: ").strip()
        region = args.region or input("区域: ").strip()
        config = load(args.config) if Path(args.config).exists() else {}
        config["server"] = server
        result = request(
            config, f"/api/v1/{args.kind}/enroll", dict(token=token, name=name, region=region), False
        )
        config.update(result)
        config.setdefault("spool", str(Path(args.config).parent / "spool.db"))
        config.setdefault("installation_id", str(uuid.uuid4()))
        save(args.config, config)
        print("注册成功，凭据已写入 0600 配置文件。")
        return
    config = load(args.config)
    if args.action == "test":
        request(config, f"/api/v1/{args.kind}/config")
        print("HTTPS / authentication: OK")
        return
    spool = open_spool(config)
    try:
        if args.action == "upload":
            for _ in range(100):
                if not upload_one(config, spool, args.kind):
                    break
        health = spool.health()
        if args.action == "diagnostics":
            health.update(
                server=config["server"],
                agent_id=config["id"],
                vps_id=config.get("vps_id"),
                proxy_independent=True,
                parser_lines=spool.state("parser_lines", 0),
                parser_errors=spool.state("parser_errors", 0),
                cursor=spool.state("cursor"),
            )
            for command in (
                ["systemctl", "is-active", "xboard-audit"],
                ["docker", "exec", "xray-core", "xray", "run", "-test", "-config", "/etc/xray/config.json"],
            ):
                subprocess.run(command, timeout=15, check=False)
        print(json.dumps(health, indent=2))
    finally:
        spool.close()


if __name__ == "__main__":
    main()
