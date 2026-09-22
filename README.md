# Xray Audit · XBoard 多 VPS 审计与关联分析

当前版本：`2.1.0-dev`（第二版）。按维护者要求，本次未运行本地测试或构建，交付后在 VPS 部署验证，不声明已通过生产验收。

第二版聚焦大陆屏蔽事件：大陆与境外对照、事件前 15/30/60 分钟证据快照、7 天明细与长期小时基线、跨事件关联，以及可选的只读 AI 报告。已有部署请按 [V2 升级与使用指南](docs/audit-v2.md) 更新。

## 快速部署（Ubuntu / Debian，root）

三种角色：中央管理服务器、运行 Xray 的 VPS Agent、独立 Probe（大陆和境外对照）。先部署中央并配置 HTTPS，再注册 Agent 和 Probe。

### 1. 下载项目

```bash
sudo -i
apt-get update && apt-get install -y git curl python3 ca-certificates
git clone https://github.com/xiaofujie369/-Xray-Audit.git /opt/xray-audit-src
cd /opt/xray-audit-src
```

中央需要 Docker Engine 与 Compose v2；未安装时可使用 Docker 官方安装器：

```bash
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
sh /tmp/get-docker.sh
```

### 2. 中央管理服务器

将域名解析到中央服务器，并放行 TCP 80、443。配置向导会生成数据库密码与应用密钥，并提示设置后台账户。

```bash
cd /opt/xray-audit-src
python3 audit-server/configure.py
bash audit-server/install-central.sh --https
```

打开配置时填写的 HTTPS 地址登录。`--https` 启用 Caddy 自动证书；已有 HTTPS 反向代理时省略该参数，把代理指向 `127.0.0.1:8080`。现有 `.env` 不会被向导覆盖。

### 3. Xray VPS

在每台 VPS 下载同一项目。全新节点运行：

```bash
cd /opt/xray-audit-src
bash install.sh
```

已有旧版 XBoard 同步服务时使用更新，保留原配置：

```bash
cd /opt/xray-audit-src
bash update.sh
```

中央后台「Agent / Probe」选择 VPS Agent，生成一次性令牌，然后在 VPS 执行：

```bash
bash /opt/xray-audit-src/install-audit-agent.sh
xbr
```

按提示输入中央 HTTPS 地址、一次性令牌、名称和区域。`xbr` 的 20–29 项用于 Audit 状态、启停、注册、日志、spool、上传和诊断。Agent 配置在 `/opt/xray-audit/config.json`。

### 4. 独立大陆 Probe

在至少两台来自不同大陆网络的探测机器及至少一台独立境外机器下载项目。中央分别生成 Probe 令牌，准确勾选大陆标记，并填写不同的独立网络分组。境外 Probe 不勾选大陆标记。

```bash
cd /opt/xray-audit-src
bash probe/install-probe.sh
systemctl status xboard-probe --no-pager
```

中央「探测目标」添加 VPS 的公网 IP、端口和协议；「系统设置」配置可靠的 `control_targets`，例如运维人员选定的 `[{"address":"公网IP","port":443}]`。两个凭据来自同一网络时不能视为两个独立探测点。

### 常用操作

```bash
# 中央状态与日志
cd /opt/xray-audit-src/audit-server
docker compose ps
docker compose logs --tail=100 audit-api audit-worker

# 中央备份（目标必须为尚不存在的目录）
bash backup.sh /root/audit-backup-$(date +%Y%m%d-%H%M%S)

# VPS 状态
systemctl status xboard-audit --no-pager
journalctl -u xboard-audit -n 100 --no-pager
```

页面中的“关联度”仅描述统计关联，不能证明某用户或网站导致屏蔽。访问日志通常只提供域名或目标 IP 中的一种，系统不伪造另一种或域名流量。

详细说明：[中央部署](docs/audit-central.md)、[Agent](docs/audit-agent.md)、[Probe](docs/audit-probe.md)、[升级](docs/audit-upgrade.md)、[安全](docs/audit-security.md)、[关联计算](docs/audit-correlation.md)、[验证状态](docs/audit-validation.md)。

---

# XBoard Xray Docker Sync

Official xray-core Docker deployment with XBoard panel sync and traffic report.

This project does not use Xboard-Node, V2bX, or XrayR. It uses official xray-core plus lightweight Python sync/report scripts.

## Features

- Official xray-core Docker
- XBoard node config sync
- XBoard user sync
- XBoard traffic report
- Multi-node support
- Multi-protocol support
- systemd auto start
- Restart on failure after 60 seconds
- Health check script

## Supported Protocols

Supported by official xray-core:

- VLESS
- VLESS Reality
- VMess
- Trojan
- Shadowsocks
- Shadowsocks TCP/UDP

Not supported by official xray-core:

- AnyTLS
- Hysteria2
- TUIC

Use sing-box for AnyTLS, Hysteria2, and TUIC.

## Tested

- VLESS Reality
- Shadowsocks chacha20-ietf-poly1305

## Important Notes

Do not commit real secrets:

- PANEL_TOKEN
- Reality privateKey
- Shadowsocks server_key
- User UUID list
- /opt/xray-sync/.env

For Shadowsocks 2022:

- 2022-blake3-aes-256-gcm requires valid base64 PSK for server and clients.
- If your XBoard only returns UUID as user password, use chacha20-ietf-poly1305 or aes-128-gcm instead.

## Quick Install

bash <(curl -fsSL https://raw.githubusercontent.com/xiaofujie369/-Xray-Audit/main/install.sh)

After installation, use the management menu:

xbr

## Manual Install

git clone https://github.com/xiaofujie369/-Xray-Audit.git
cd ./-Xray-Audit
bash install.sh

## Node List Format

NODES=node_id:protocol,node_id:protocol

Examples:

NODES=3047:vless
NODES=3047:vless,8881:shadowsocks
NODES=3047:vless,8881:shadowsocks,8882:trojan,8883:vmess

## Runtime Files

/opt/xray
/opt/xray/config/config.json
/opt/xray/docker-compose.yml
/opt/xray/logs/access.log
/opt/xray-sync
/opt/xray-sync/.env
/opt/xray-sync/report_state.json
/opt/xray-sync/xboard_sync.py
/opt/xray-sync/xboard_report.py
/opt/xray-sync/healthcheck.sh

## Services

systemctl status xboard-sync --no-pager
systemctl status xboard-report --no-pager

## Management Menu

Run as root:

xbr

The longer `xray-sync` command is still installed as a compatibility alias.

Menu features:

- Edit panel config
- Install, update, uninstall
- Start, stop, restart services
- View status and logs
- Sync panel config now
- Inspect generated node config
- Check Xray config JSON and port conflicts
- Check TLS certificate files and openssl output
- Open generated node ports in ufw
- Backup and restore config.json

## Health Check

/opt/xray-sync/healthcheck.sh

## Traffic and Online Reporting

xboard-report reads Xray Stats API and reports to XBoard through `/api/v2/server/report`.
Each report includes node status, so the panel can keep the node online even when no user traffic is generated.

It also reads /opt/xray/logs/access.log incrementally to report real user IPs and online counts.
Recently active users are kept for `REPORT_ONLINE_TTL` seconds, default `180`, so online counts do not drop just because no new access log line appeared in the current report window.

If online users or traffic are not visible, run:

/opt/xray-sync/healthcheck.sh
journalctl -u xboard-report -n 100 --no-pager

## Update

cd ./-Xray-Audit
git pull
bash update.sh

## Uninstall

bash uninstall.sh

## Firewall

Open all node ports in your server firewall and cloud security group.

Example:

ufw allow 31059/tcp
ufw allow 45123/tcp
ufw allow 45123/udp

## License

MIT

## Custom Outbounds and Routes

This project supports XBoard per-node custom outbounds and custom routes.

You can configure different outbound rules for each node in XBoard.

XBoard route groups selected on a node are also synced. `block`, `direct`, and `proxy` actions are compiled into Xray routing rules bound to that node inbound; `dns` actions are compiled into Xray DNS server rules. Dangerous global matchers such as `*`, `0.0.0.0/0`, and `::/0` are ignored in panel route groups by default, and wildcard default DNS routes are ignored unless `XRAY_ENABLE_PANEL_DEFAULT_DNS=true` is set.

Custom outbounds are definitions only; they do not affect traffic until a custom route or panel proxy route references them. Per-node custom outbound tags are automatically scoped, so two nodes can both define `ss-us` without sharing the same outbound. Per-node custom routes are forced to the current node inbound; routes targeting another node inbound are ignored for stability.
If a route references an outbound that is not defined on that node, that route is ignored instead of being written into Xray config.

Example:

- Node 249 uses VLESS Reality inbound on port 443
- Node 249 custom outbound uses another upstream VLESS/TLS/Vision node
- Only traffic from inbound tag `vless-443` will be routed to this outbound

### Custom Route Example

```json
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-vless-tls"
  }
]
[
  {
    "tag": "relay-vless-tls",
    "protocol": "vless",
    "settings": {
      "vnext": [
        {
          "address": "example.com",
          "port": 443,
          "users": [
            {
              "id": "YOUR-UPSTREAM-VLESS-UUID",
              "encryption": "none",
              "flow": "xtls-rprx-vision"
            }
          ]
        }
      ]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "example.com",
        "allowInsecure": false,
        "fingerprint": "edge"
      }
    }
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-vless-tls"
  }
]
[
  {
    "tag": "relay-vless-reality",
    "protocol": "vless",
    "settings": {
      "vnext": [
        {
          "address": "example.com",
          "port": 443,
          "users": [
            {
              "id": "YOUR-UPSTREAM-VLESS-UUID",
              "encryption": "none",
              "flow": "xtls-rprx-vision"
            }
          ]
        }
      ]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "www.microsoft.com",
        "fingerprint": "edge",
        "publicKey": "YOUR-REALITY-PUBLIC-KEY",
        "shortId": "YOUR-REALITY-SHORT-ID",
        "spiderX": "/"
      }
    }
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-vless-reality"
  }
]
[
  {
    "tag": "relay-trojan-tls",
    "protocol": "trojan",
    "settings": {
      "servers": [
        {
          "address": "example.com",
          "port": 443,
          "password": "YOUR-TROJAN-PASSWORD"
        }
      ]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "example.com",
        "allowInsecure": false,
        "fingerprint": "edge"
      }
    }
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-trojan-tls"
  }
]
[
  {
    "tag": "relay-shadowsocks",
    "protocol": "shadowsocks",
    "settings": {
      "servers": [
        {
          "address": "example.com",
          "port": 8388,
          "method": "chacha20-ietf-poly1305",
          "password": "YOUR-SHADOWSOCKS-PASSWORD"
        }
      ]
    }
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-shadowsocks"
  }
]
[
  {
    "tag": "relay-socks5",
    "protocol": "socks",
    "settings": {
      "servers": [
        {
          "address": "example.com",
          "port": 1080,
          "users": [
            {
              "user": "YOUR-SOCKS-USER",
              "pass": "YOUR-SOCKS-PASSWORD"
            }
          ]
        }
      ]
    }
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-socks5"
  }
]
[
  {
    "tag": "relay-http",
    "protocol": "http",
    "settings": {
      "servers": [
        {
          "address": "example.com",
          "port": 8080,
          "users": [
            {
              "user": "YOUR-HTTP-USER",
              "pass": "YOUR-HTTP-PASSWORD"
            }
          ]
        }
      ]
    }
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "relay-http"
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "direct"
  }
]
[
  {
    "type": "field",
    "inboundTag": [
      "vless-443"
    ],
    "outboundTag": "block"
  }
]

---

## 3. 提交并推送

```bash
git status

git add sync/xboard_sync.py README.md

git commit -m "Support XBoard per-node custom outbounds and add outbound examples"

git push

## Custom Outbounds

This project supports XBoard per-node custom outbounds and custom routes.

See:

docs/custom-outbounds.md

Supported common custom outbound examples:

- VLESS + TLS + Vision
- VLESS + TLS
- VLESS + Reality
- Trojan + TLS
- Shadowsocks
- SOCKS5
- HTTP Proxy
- Direct route
- Block route
