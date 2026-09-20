import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


xboard_sync = load_module("xboard_sync", "sync/xboard_sync.py")
xboard_report = load_module("xboard_report", "sync/xboard_report.py")

TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIBtestcert
-----END CERTIFICATE-----
"""

TEST_KEY = """-----BEGIN EC PRIVATE KEY-----
MHctestkey
-----END EC PRIVATE KEY-----
"""

TEST_ECH_KEY = """-----BEGIN ECH KEYS-----
YWJjZGVm
-----END ECH KEYS-----"""

TEST_ECH_CONFIG = """-----BEGIN ECH CONFIGS-----
YWJjZGVm
-----END ECH CONFIGS-----"""


class NodeParsingTests(unittest.TestCase):
    def test_sync_parses_multi_node_env_with_aliases(self):
        env = {"NODES": "3047:vless, 8881:ss, 8882:v2ray"}

        self.assertEqual(
            xboard_sync.get_nodes(env),
            [("3047", "vless"), ("8881", "shadowsocks"), ("8882", "vmess")],
        )

    def test_report_parses_legacy_single_node_env(self):
        env = {"NODE_ID": "3047", "NODE_TYPE": "ss"}

        self.assertEqual(xboard_report.get_nodes(env), [("3047", "shadowsocks")])

    def test_empty_nodes_are_rejected(self):
        for module in (xboard_sync, xboard_report):
            with self.subTest(module=module.__name__):
                with self.assertRaises(RuntimeError):
                    module.get_nodes({"NODES": " , "})

    def test_incomplete_node_entries_are_rejected(self):
        for module in (xboard_sync, xboard_report):
            with self.subTest(module=module.__name__):
                with self.assertRaises(RuntimeError):
                    module.get_nodes({"NODES": "3047:"})
                with self.assertRaises(RuntimeError):
                    module.get_nodes({"NODES": ":vless"})


class SyncConfigTests(unittest.TestCase):
    def test_client_emails_are_scoped_by_node_for_all_protocols(self):
        user_resp = {
            "users": [
                {
                    "id": 1485,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "password": "trojan-password",
                }
            ]
        }

        self.assertEqual(
            xboard_sync.build_vless_clients(user_resp, flow=None, node_id="3047")[0]["email"],
            "3047:1485",
        )
        self.assertEqual(
            xboard_sync.build_vmess_clients(user_resp, node_id="3047")[0]["email"],
            "3047:1485",
        )
        self.assertEqual(
            xboard_sync.build_trojan_clients(user_resp, node_id="3047")[0]["email"],
            "3047:1485",
        )
        self.assertEqual(
            xboard_sync.build_ss_clients(user_resp, method="aes-128-gcm", node_id="3047")[0]["email"],
            "3047:1485",
        )

    def test_vless_inbound_uses_scoped_email_and_expected_port(self):
        config_resp = {
            "data": {
                "protocol": "vless",
                "server_port": 443,
                "network": "tcp",
                "tls": 0,
            }
        }
        user_resp = {
            "users": [
                {
                    "id": 1485,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                }
            ]
        }

        inbound = xboard_sync.build_vless_inbound(config_resp, user_resp, node_id="3047")

        self.assertEqual(inbound["tag"], "vless-443")
        self.assertEqual(inbound["settings"]["clients"][0]["email"], "3047:1485")

    def test_tls_cert_config_content_writes_cert_and_injects_container_paths(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch.object(xboard_sync, "CONTAINER_CERT_DIR", "/etc/xray/certs"), \
             mock.patch("builtins.print"):
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "tls_settings": {"server_name": "link.shy521.com"},
                "cert_config": {
                    "cert_mode": "content",
                    "certificateContent": TEST_CERT.replace("\n", "\\n"),
                    "privateKey": TEST_KEY.replace("\n", "\\n"),
                },
            }

            stream = xboard_sync.build_stream_settings(server)

            self.assertEqual(stream["security"], "tls")
            self.assertEqual(stream["tlsSettings"]["serverName"], "link.shy521.com")
            self.assertEqual(
                stream["tlsSettings"]["certificates"],
                [
                    {
                        "certificateFile": "/etc/xray/certs/link.shy521.com.crt",
                        "keyFile": "/etc/xray/certs/link.shy521.com.key",
                    }
                ],
            )
            self.assertEqual((Path(tmp) / "link.shy521.com.crt").read_text(), TEST_CERT)
            self.assertEqual((Path(tmp) / "link.shy521.com.key").read_text(), TEST_KEY)

    def test_tls_advanced_panel_settings_are_mapped_when_present(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch.object(xboard_sync, "CONTAINER_CERT_DIR", "/etc/xray/certs"), \
             mock.patch("builtins.print"):
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "utls": {"enabled": True, "fingerprint": "Edge"},
                "tls_settings": {
                    "server_name": "link.shy521.com",
                    "allow_insecure": True,
                    "pinnedPeerCertSha256": "abc123",
                    "alpn": "h2,http/1.1",
                    "ech": {
                        "enabled": True,
                        "key": TEST_ECH_KEY,
                        "config": TEST_ECH_CONFIG,
                    },
                },
                "cert_config": {
                    "cert": TEST_CERT,
                    "key": TEST_KEY,
                },
            }

            stream = xboard_sync.build_stream_settings(server)
            tls = stream["tlsSettings"]

            self.assertEqual(tls["fingerprint"], "edge")
            self.assertNotIn("allowInsecure", tls)
            self.assertEqual(tls["pinnedPeerCertSha256"], "abc123")
            self.assertEqual(tls["alpn"], ["h2", "http/1.1"])
            self.assertEqual(tls["echServerKeys"], TEST_ECH_KEY)
            self.assertEqual(tls["echConfigList"], "YWJjZGVm")

    def test_tls_disabled_or_empty_advanced_settings_are_omitted(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch.object(xboard_sync, "CONTAINER_CERT_DIR", "/etc/xray/certs"), \
             mock.patch("builtins.print"):
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "utls": {"enabled": False, "fingerprint": "Edge"},
                "tls_settings": {
                    "server_name": "link.shy521.com",
                    "allow_insecure": False,
                    "ech": {
                        "enabled": False,
                        "key": TEST_ECH_KEY,
                        "config": TEST_ECH_CONFIG,
                    },
                },
                "cert_config": {
                    "cert": TEST_CERT,
                    "key": TEST_KEY,
                },
            }

            tls = xboard_sync.build_stream_settings(server)["tlsSettings"]

            self.assertNotIn("fingerprint", tls)
            self.assertNotIn("allowInsecure", tls)
            self.assertNotIn("echServerKeys", tls)
            self.assertNotIn("echConfigList", tls)

    def test_vless_flow_and_nested_encryption_are_mapped_when_present(self):
        config_resp = {
            "data": {
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 0,
                "flow": "xtls-rprx-vision",
                "encryption": {
                    "enabled": True,
                    "decryption": "mlkem768x25519plus.example-private-key",
                    "encryption": "mlkem768x25519plus.example-public-key",
                },
            }
        }
        user_resp = {
            "users": [
                {
                    "id": 1485,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                }
            ]
        }

        inbound = xboard_sync.build_vless_inbound(config_resp, user_resp, node_id="371")

        self.assertEqual(inbound["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(inbound["settings"]["decryption"], "mlkem768x25519plus.example-private-key")

    def test_vless_empty_flow_and_disabled_encryption_keep_runnable_defaults(self):
        config_resp = {
            "data": {
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 0,
                "flow": "",
                "encryption": {
                    "enabled": False,
                    "decryption": "should-not-be-used",
                },
            }
        }
        user_resp = {
            "users": [
                {
                    "id": 1485,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                }
            ]
        }

        inbound = xboard_sync.build_vless_inbound(config_resp, user_resp, node_id="371")

        self.assertNotIn("flow", inbound["settings"]["clients"][0])
        self.assertEqual(inbound["settings"]["decryption"], "none")

    def test_tls_uses_existing_local_cert_fallback(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch.object(xboard_sync, "CONTAINER_CERT_DIR", "/etc/xray/certs"), \
             mock.patch("builtins.print"):
            (Path(tmp) / "link.shy521.com.crt").write_text(TEST_CERT)
            (Path(tmp) / "link.shy521.com.key").write_text(TEST_KEY)
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "tls_settings": {"server_name": "link.shy521.com"},
            }

            stream = xboard_sync.build_stream_settings(server)

            self.assertEqual(
                stream["tlsSettings"]["certificates"],
                [
                    {
                        "certificateFile": "/etc/xray/certs/link.shy521.com.crt",
                        "keyFile": "/etc/xray/certs/link.shy521.com.key",
                    }
                ],
            )

    def test_tls_server_name_can_fallback_to_cert_domain(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch.object(xboard_sync, "CONTAINER_CERT_DIR", "/etc/xray/certs"), \
             mock.patch("builtins.print"):
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "tls_settings": {},
                "cert_config": {
                    "cert_mode": "content",
                    "cert_domain": "link.shy521.com",
                    "cert": TEST_CERT,
                    "key": TEST_KEY,
                },
            }

            stream = xboard_sync.build_stream_settings(server)

            self.assertEqual(stream["tlsSettings"]["serverName"], "link.shy521.com")
            self.assertEqual(
                stream["tlsSettings"]["certificates"][0]["certificateFile"],
                "/etc/xray/certs/link.shy521.com.crt",
            )

    def test_tls_preserves_panel_provided_container_cert_paths(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch("builtins.print"):
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "tls_settings": {"server_name": "link.shy521.com"},
                "cert_config": {
                    "certificateFile": "/etc/xray/certs/custom.crt",
                    "keyFile": "/etc/xray/certs/custom.key",
                },
            }

            stream = xboard_sync.build_stream_settings(server)

            self.assertEqual(
                stream["tlsSettings"]["certificates"],
                [
                    {
                        "certificateFile": "/etc/xray/certs/custom.crt",
                        "keyFile": "/etc/xray/certs/custom.key",
                    }
                ],
            )

    def test_tls_safe_cert_filename_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(xboard_sync, "HOST_CERT_DIR", tmp), \
             mock.patch.object(xboard_sync, "CONTAINER_CERT_DIR", "/etc/xray/certs"), \
             mock.patch("builtins.print"):
            server = {
                "id": 371,
                "protocol": "vless",
                "server_port": 8443,
                "network": "tcp",
                "tls": 1,
                "tls_settings": {"server_name": "../link.shy521.com/../../evil"},
                "cert_config": {
                    "cert": TEST_CERT,
                    "key": TEST_KEY,
                },
            }

            stream = xboard_sync.build_stream_settings(server)

            cert_file = stream["tlsSettings"]["certificates"][0]["certificateFile"]
            self.assertTrue(cert_file.startswith("/etc/xray/certs/"))
            self.assertNotIn("..", cert_file)
            self.assertTrue((Path(tmp) / "link.shy521.com_._._evil.crt").exists())

    def test_xray_config_includes_stats_api_and_user_policies(self):
        config = xboard_sync.build_xray_config([])

        self.assertIn("stats", config)
        self.assertEqual(config["inbounds"][0]["tag"], "api")
        self.assertEqual(config["log"]["access"], "/var/log/xray/access.log")
        self.assertEqual(config["log"]["error"], "/var/log/xray/error.log")
        self.assertTrue(config["policy"]["levels"]["0"]["statsUserUplink"])
        self.assertTrue(config["policy"]["levels"]["0"]["statsUserDownlink"])

    def test_custom_outbounds_do_not_become_default_outbound(self):
        config = xboard_sync.build_xray_config(
            [],
            custom_outbounds=[
                {
                    "tag": "node-1159-relay-vless-reality",
                    "protocol": "vless",
                    "settings": {"vnext": []},
                }
            ],
        )

        self.assertEqual(config["outbounds"][0]["tag"], "direct")
        self.assertEqual(config["outbounds"][1]["tag"], "block")
        self.assertEqual(config["outbounds"][2]["tag"], "node-1159-relay-vless-reality")

    def test_panel_route_groups_compile_to_routing_and_dns(self):
        server = {
            "routes": [
                {
                    "remarks": "禁止访问",
                    "match": [".coinclaim.site", "geoip:private"],
                    "action": "block",
                },
                {
                    "remarks": "国内域名优化",
                    "match": ["geosite:cn", ".baidu.com"],
                    "action": "dns",
                    "action_value": "DNS: 223.5.5.5,119.29.29.29",
                },
                {
                    "remarks": "默认DNS兜底解析",
                    "match": ["*"],
                    "action": "dns",
                    "action_value": "1.1.1.1,8.8.8.8",
                },
            ]
        }

        routes, dns = xboard_sync.extract_panel_routes(server, inbound_tag="vless-8443")

        self.assertEqual(routes[0]["domain"], ["domain:coinclaim.site"])
        self.assertEqual(routes[0]["outboundTag"], "block")
        self.assertEqual(routes[0]["inboundTag"], ["vless-8443"])
        self.assertEqual(routes[1]["ip"], ["geoip:private"])
        self.assertEqual(dns[0]["address"], "223.5.5.5")
        self.assertEqual(dns[0]["domains"], ["geosite:cn", "domain:baidu.com"])
        self.assertEqual(dns[1]["address"], "119.29.29.29")
        self.assertNotIn("1.1.1.1", dns)

    def test_panel_route_groups_skip_dangerous_global_matchers(self):
        server = {
            "routes": [
                {"match": ["*"], "action": "block"},
                {"match": ["0.0.0.0/0", "::/0"], "action": "block"},
                {"match": ["*"], "action": "dns", "action_value": "9.9.9.9"},
            ]
        }

        routes, dns = xboard_sync.extract_panel_routes(server, inbound_tag="vless-8443")

        self.assertEqual(routes, [])
        self.assertEqual(dns, [])

    def test_panel_route_groups_ignore_comment_lines(self):
        server = {
            "routes": [
                {
                    "match": [
                        "# ===== 电商 / 特定地区限制 =====",
                        "// comment.example",
                        "; another comment",
                        ".blocked.example",
                    ],
                    "action": "block",
                }
            ]
        }

        routes, dns = xboard_sync.extract_panel_routes(server, inbound_tag="vless-8443")

        self.assertEqual(dns, [])
        self.assertEqual(routes[0]["domain"], ["domain:blocked.example"])
        self.assertNotIn("ip", routes[0])

    def test_ip_matcher_requires_real_ip_or_cidr(self):
        self.assertTrue(xboard_sync.is_ip_matcher("192.168.1.1"))
        self.assertTrue(xboard_sync.is_ip_matcher("10.0.0.0/8"))
        self.assertTrue(xboard_sync.is_ip_matcher("2001:db8::/32"))
        self.assertFalse(xboard_sync.is_ip_matcher("# ===== 电商 / 特定地区限制 ====="))
        self.assertFalse(xboard_sync.is_ip_matcher("example.com/path"))

    def test_panel_default_dns_requires_explicit_opt_in(self):
        route = {"match": ["*"], "action": "dns", "action_value": "9.9.9.9"}

        self.assertEqual(xboard_sync.compile_panel_route(route), ([], []))
        self.assertEqual(
            xboard_sync.compile_panel_route(route, allow_default_dns=True),
            ([], ["9.9.9.9"]),
        )

    def test_custom_outbounds_are_scoped_and_routes_are_rewritten(self):
        outbounds, tag_map = xboard_sync.scope_custom_outbounds(
            [
                {
                    "tag": "ss-us",
                    "protocol": "shadowsocks",
                    "settings": {"servers": []},
                }
            ],
            "266",
        )

        self.assertEqual(outbounds[0]["tag"], "node-266-ss-us")
        self.assertEqual(tag_map, {"ss-us": "node-266-ss-us"})

        routes = xboard_sync.extract_custom_routes(
            {
                "custom_routes": [
                    {
                        "type": "field",
                        "outboundTag": "ss-us",
                    }
                ]
            },
            inbound_tag="shadowsocks-8333",
            outbound_tag_map=tag_map,
        )

        self.assertEqual(routes[0]["inboundTag"], ["shadowsocks-8333"])
        self.assertEqual(routes[0]["outboundTag"], "node-266-ss-us")

    def test_custom_routes_cannot_target_another_node_inbound(self):
        routes = xboard_sync.extract_custom_routes(
            {
                "custom_routes": [
                    {
                        "type": "field",
                        "inboundTag": ["vless-9443"],
                        "outboundTag": "ss-us",
                    }
                ]
            },
            inbound_tag="shadowsocks-8333",
            outbound_tag_map={"ss-us": "node-266-ss-us"},
        )

        self.assertEqual(routes, [])

    def test_custom_route_to_missing_outbound_is_ignored(self):
        routes = xboard_sync.extract_custom_routes(
            {
                "custom_routes": [
                    {
                        "type": "field",
                        "outboundTag": "ss-us",
                    }
                ]
            },
            inbound_tag="shadowsocks-8333",
            outbound_tag_map={},
        )

        self.assertEqual(routes, [])

    def test_panel_proxy_route_rewrites_local_custom_outbound_tag(self):
        routes, _dns = xboard_sync.extract_panel_routes(
            {
                "routes": [
                    {
                        "match": [".example.com"],
                        "action": "proxy",
                        "action_value": "ss-us",
                    }
                ]
            },
            inbound_tag="shadowsocks-8333",
            outbound_tag_map={"ss-us": "node-266-ss-us"},
        )

        self.assertEqual(routes[0]["outboundTag"], "node-266-ss-us")

    def test_panel_proxy_route_to_missing_outbound_is_ignored(self):
        routes, dns = xboard_sync.extract_panel_routes(
            {
                "routes": [
                    {
                        "match": [".example.com"],
                        "action": "proxy",
                        "action_value": "ss-us",
                    }
                ]
            },
            inbound_tag="shadowsocks-8333",
            outbound_tag_map={},
        )

        self.assertEqual(routes, [])
        self.assertEqual(dns, [])

    def test_xray_config_includes_panel_dns_routes_before_defaults(self):
        dns = [
            {"address": "223.5.5.5", "domains": ["geosite:cn"]},
            "1.1.1.1",
        ]

        config = xboard_sync.build_xray_config([], custom_dns_servers=dns)
        servers = config["dns"]["servers"]

        self.assertEqual(servers[0], {"address": "223.5.5.5", "domains": ["geosite:cn"]})
        self.assertEqual(servers.count("1.1.1.1"), 1)
        self.assertEqual(servers.count("8.8.8.8"), 1)

    def test_xray_config_validation_rejects_duplicate_ports(self):
        config = {
            "inbounds": [
                {"tag": "vless-8443", "port": 8443},
                {"tag": "trojan-8443", "port": 8443},
            ],
            "outbounds": [],
        }

        with self.assertRaises(RuntimeError):
            xboard_sync.validate_xray_config(config)

    def test_redact_secrets_masks_panel_token(self):
        text = "https://panel.example.com/api?node_id=371&token=secret-token-value&node_type=vless"

        redacted = xboard_sync.redact_secrets(text)

        self.assertNotIn("secret-token-value", redacted)
        self.assertIn("token=***", redacted)

    def test_config_backup_prunes_and_restore_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            backups = []

            for i in range(3):
                config_path.write_text(f'{{"version": {i}}}')
                backups.append(xboard_sync.backup_config(config_path, keep=2))

            remaining = sorted((Path(tmp) / "backups").glob("config.json.*"))
            self.assertEqual(len(remaining), 2)
            self.assertFalse(backups[0].exists())

            config_path.write_text('{"version": "new"}')
            self.assertTrue(xboard_sync.restore_config(backups[-1], config_path))
            self.assertEqual(config_path.read_text(), '{"version": 2}')

    def test_sync_once_restores_previous_config_when_restart_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            log_dir = Path(tmp) / "logs"
            old_config = {
                "inbounds": [],
                "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
            }
            config_path.write_text(json.dumps(old_config, ensure_ascii=False, indent=2))
            env = {
                "PANEL_URL": "https://panel.example.com",
                "PANEL_TOKEN": "token",
                "NODES": "371:vless",
                "XRAY_CONFIG": str(config_path),
                "XRAY_LOG_DIR": str(log_dir),
                "XRAY_CONTAINER": "xray-core",
            }
            node_data = {
                "inbound": {
                    "tag": "vless-8443",
                    "listen": "0.0.0.0",
                    "port": 8443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none",
                    },
                },
                "custom_outbounds": [],
                "custom_routes": [],
            }

            with mock.patch.object(xboard_sync, "load_env", return_value=env), \
                 mock.patch.object(xboard_sync, "fetch_node", return_value=node_data), \
                 mock.patch.object(xboard_sync, "run_xray_config_test"), \
                 mock.patch.object(xboard_sync, "restart_xray", side_effect=RuntimeError("boom")), \
                 mock.patch("builtins.print"):
                with self.assertRaises(RuntimeError):
                    xboard_sync.sync_once()

            self.assertEqual(config_path.read_text(), json.dumps(old_config, ensure_ascii=False, indent=2))

    def test_sync_once_does_not_replace_config_when_xray_pretest_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            log_dir = Path(tmp) / "logs"
            old_config = {
                "inbounds": [],
                "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
            }
            old_text = json.dumps(old_config, ensure_ascii=False, indent=2)
            config_path.write_text(old_text)
            env = {
                "PANEL_URL": "https://panel.example.com",
                "PANEL_TOKEN": "token",
                "NODES": "371:vless",
                "XRAY_CONFIG": str(config_path),
                "XRAY_LOG_DIR": str(log_dir),
                "XRAY_CONTAINER": "xray-core",
            }
            node_data = {
                "inbound": {
                    "tag": "vless-8443",
                    "listen": "0.0.0.0",
                    "port": 8443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": "uuid", "email": "371:1"}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none",
                    },
                },
                "custom_outbounds": [],
                "custom_routes": [],
            }

            with mock.patch.object(xboard_sync, "load_env", return_value=env), \
                 mock.patch.object(xboard_sync, "fetch_node", return_value=node_data), \
                 mock.patch.object(xboard_sync, "run_xray_config_test", side_effect=RuntimeError("bad config")), \
                 mock.patch.object(xboard_sync, "write_config_atomically") as write_config, \
                 mock.patch.object(xboard_sync, "restart_xray") as restart, \
                 mock.patch("builtins.print"):
                with self.assertRaisesRegex(RuntimeError, "bad config"):
                    xboard_sync.sync_once()

            self.assertEqual(config_path.read_text(), old_text)
            write_config.assert_not_called()
            restart.assert_not_called()

    def test_xray_pretest_temp_file_keeps_json_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_text = json.dumps({"inbounds": [], "outbounds": []})

            def fake_run(cmd, **kwargs):
                self.assertIn("/etc/xray/.config.test.json", cmd)
                result = mock.Mock()
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
                return result

            with mock.patch.object(xboard_sync.subprocess, "run", side_effect=fake_run):
                xboard_sync.run_xray_config_test(
                    "xray-core",
                    config_path,
                    config_text,
                    container_config_dir="/etc/xray",
                )

            self.assertFalse((Path(tmp) / ".config.test.json").exists())

    def test_ensure_xray_log_files_creates_writable_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            xboard_sync.ensure_xray_log_files(tmp)

            access_log = Path(tmp) / "access.log"
            error_log = Path(tmp) / "error.log"

            self.assertTrue(access_log.exists())
            self.assertTrue(error_log.exists())
            access_log.write_text("ok\n")
            error_log.write_text("ok\n")


class ReportTrafficTests(unittest.TestCase):
    def test_parse_traffic_by_node_aggregates_scoped_and_legacy_stats(self):
        stats = {
            "stat": [
                {"name": "user>>>3047:1485>>>traffic>>>uplink", "value": "100"},
                {"name": "user>>>3047:1485>>>traffic>>>downlink", "value": "200"},
                {"name": "user>>>8881:42>>>traffic>>>uplink", "value": "7"},
                {"name": "user>>>99>>>traffic>>>downlink", "value": "5"},
                {"name": "inbound>>>api>>>traffic>>>uplink", "value": "999"},
            ]
        }

        scoped, legacy = xboard_report.parse_traffic_by_node(stats)

        self.assertEqual(scoped, {"3047": {1485: [100, 200]}, "8881": {42: [7, 0]}})
        self.assertEqual(legacy, {99: [0, 5]})

    def test_parse_alive_from_access_lines_groups_ips_by_node_and_user(self):
        lines = [
            "2026/05/19 10:00:00 1.2.3.4:12345 accepted tcp:example.com:443 email: 3047:1485",
            "2026/05/19 10:00:01 1.2.3.4:12345 accepted tcp:example.com:443 email: 3047:1485",
            "2026/05/19 10:00:02 [2001:db8::1]:443 accepted tcp:example.com:443 email: 8881:42",
            "2026/05/19 10:00:03 5.6.7.8:2222 accepted tcp:example.com:443 [99]",
        ]

        scoped, legacy = xboard_report.parse_alive_from_access_lines(lines)

        self.assertEqual(scoped, {"3047": {1485: ["1.2.3.4"]}, "8881": {42: ["2001:db8::1"]}})
        self.assertEqual(legacy, {99: ["5.6.7.8"]})

    def test_read_access_log_since_tracks_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "access.log"
            state_path = Path(tmp) / "state.json"
            log_path.write_text(
                "2026/05/19 10:00:00 1.2.3.4:12345 accepted tcp:x email: 3047:1485\n"
            )

            env = {"XRAY_ACCESS_LOG": str(log_path), "REPORT_STATE": str(state_path)}
            scoped, legacy = xboard_report.read_access_log_since(env)
            self.assertEqual(scoped, {"3047": {1485: ["1.2.3.4"]}})
            self.assertEqual(legacy, {})

            scoped, legacy = xboard_report.read_access_log_since(env)
            self.assertEqual(scoped, {})
            self.assertEqual(legacy, {})

            with log_path.open("a") as f:
                f.write("2026/05/19 10:00:01 5.6.7.8:2222 accepted tcp:x email: 3047:42\n")

            scoped, legacy = xboard_report.read_access_log_since(env)
            self.assertEqual(scoped, {"3047": {42: ["5.6.7.8"]}})
            self.assertEqual(legacy, {})

    def test_alive_uses_ipv6_source_not_ipv4_destination(self):
        line = "2026/09/19 10:00:00 from tcp:[2001:db8::1]:2345 accepted tcp:8.8.8.8:443 [vless-3 -> direct] email: 3:7"
        scoped, legacy = xboard_report.parse_alive_from_access_lines([line])
        self.assertEqual(scoped, {"3": {7: ["2001:db8::1"]}})
        self.assertEqual(legacy, {})


    def test_refresh_online_cache_keeps_recent_alive_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            env = {
                "REPORT_STATE": str(state_path),
                "REPORT_ONLINE_TTL": "180",
            }
            nodes = [("3047", "vless")]

            active = xboard_report.refresh_online_cache(
                env,
                {"3047": {1485: ["1.2.3.4"]}},
                nodes,
                now=1000,
            )
            self.assertEqual(active, {"3047": {1485: ["1.2.3.4"]}})

            active = xboard_report.refresh_online_cache(env, {}, nodes, now=1100)
            self.assertEqual(active, {"3047": {1485: ["1.2.3.4"]}})

            active = xboard_report.refresh_online_cache(env, {}, nodes, now=1200)
            self.assertEqual(active, {})

    def test_main_posts_scoped_traffic_to_each_configured_node(self):
        stats = {
            "stat": [
                {"name": "user>>>3047:1485>>>traffic>>>uplink", "value": "100"},
                {"name": "user>>>8881:42>>>traffic>>>downlink", "value": "7"},
            ]
        }
        env = {
            "PANEL_URL": "https://panel.example.com",
            "PANEL_TOKEN": "token",
            "NODES": "3047:vless,8881:ss",
        }

        with mock.patch.object(xboard_report, "load_env", return_value=env), \
             mock.patch.object(xboard_report, "run_statsquery", return_value=stats), \
             mock.patch.object(xboard_report, "read_access_log_since", return_value=({}, {})), \
             mock.patch.object(xboard_report, "refresh_online_cache", return_value={}), \
             mock.patch.object(xboard_report, "collect_status", return_value={"cpu": 1}), \
             mock.patch.object(xboard_report, "post_node_report") as post_node_report:
            xboard_report.main()

        calls = [
            (args[1], args[2], args[3], args[4], args[5])
            for args, _kwargs in post_node_report.call_args_list
        ]
        self.assertEqual(
            calls,
            [
                ("3047", "vless", {1485: [100, 0]}, {}, {"cpu": 1}),
                ("8881", "shadowsocks", {42: [0, 7]}, {}, {"cpu": 1}),
            ],
        )

    def test_main_merges_legacy_traffic_for_single_node_configs(self):
        stats = {"stat": [{"name": "user>>>1485>>>traffic>>>uplink", "value": "100"}]}
        env = {
            "PANEL_URL": "https://panel.example.com",
            "PANEL_TOKEN": "token",
            "NODE_ID": "3047",
            "NODE_TYPE": "vless",
        }

        with mock.patch.object(xboard_report, "load_env", return_value=env), \
             mock.patch.object(xboard_report, "run_statsquery", return_value=stats), \
             mock.patch.object(xboard_report, "read_access_log_since", return_value=({}, {})), \
             mock.patch.object(xboard_report, "refresh_online_cache", return_value={}), \
             mock.patch.object(xboard_report, "collect_status", return_value={"cpu": 1}), \
             mock.patch.object(xboard_report, "post_node_report") as post_node_report:
            xboard_report.main()

        post_node_report.assert_called_once_with(env, "3047", "vless", {1485: [100, 0]}, {}, {"cpu": 1})

    def test_main_posts_alive_users_and_zero_traffic_for_online_count(self):
        env = {
            "PANEL_URL": "https://panel.example.com",
            "PANEL_TOKEN": "token",
            "NODES": "3047:vless",
        }
        alive = {"3047": {1485: ["1.2.3.4"]}}

        with mock.patch.object(xboard_report, "load_env", return_value=env), \
             mock.patch.object(xboard_report, "run_statsquery", return_value={"stat": []}), \
             mock.patch.object(xboard_report, "read_access_log_since", return_value=(alive, {})), \
             mock.patch.object(xboard_report, "refresh_online_cache", return_value=alive), \
             mock.patch.object(xboard_report, "collect_status", return_value={"cpu": 1}), \
             mock.patch.object(xboard_report, "post_node_report") as post_node_report:
            xboard_report.main()

        post_node_report.assert_called_once_with(
            env,
            "3047",
            "vless",
            {1485: [0, 0]},
            {1485: ["1.2.3.4"]},
            {"cpu": 1},
        )

    def test_alive_to_online_counts_unique_ips(self):
        self.assertEqual(
            xboard_report.alive_to_online({1485: ["1.2.3.4", "1.2.3.4", "5.6.7.8"]}),
            {1485: 2},
        )

    def test_build_v2_report_payload_matches_xboard_node_shape(self):
        env = {"PANEL_TOKEN": "token", "REPORT_KERNEL_STATUS": "true"}

        payload = xboard_report.build_v2_report_payload(
            env,
            "3047",
            "vless",
            {1485: [100, 200]},
            {1485: ["1.2.3.4"]},
            {"cpu": 1, "mem": {"total": 2, "used": 1}},
        )

        self.assertEqual(payload["token"], "token")
        self.assertEqual(payload["node_id"], 3047)
        self.assertEqual(payload["node_type"], "vless")
        self.assertEqual(payload["traffic"], {"1485": [100, 200]})
        self.assertEqual(payload["alive"], {"1485": ["1.2.3.4"]})
        self.assertEqual(payload["online"], {"1485": 1})
        self.assertEqual(payload["status"]["cpu"], 1)
        self.assertEqual(payload["metrics"], {"kernel_status": True})

    def test_post_node_report_uses_v2_report_without_user_fetch(self):
        env = {
            "PANEL_URL": "https://panel.example.com",
            "PANEL_TOKEN": "token",
        }
        response = mock.Mock(status_code=200)
        response.json.return_value = {"ok": True}

        with mock.patch.object(xboard_report.requests, "post", return_value=response) as post, \
             mock.patch("builtins.print"):
            xboard_report.post_node_report(env, "3047", "vless", {}, {}, {"cpu": 1})

        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], "https://panel.example.com/api/v2/server/report")
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["node_id"], 3047)
        self.assertEqual(payload["status"], {"cpu": 1})
        self.assertNotIn("traffic", payload)
        self.assertNotIn("alive", payload)

    def test_post_node_report_falls_back_to_legacy_endpoints(self):
        env = {
            "PANEL_URL": "https://panel.example.com",
            "PANEL_TOKEN": "token",
        }

        with mock.patch.object(xboard_report, "post_report_v2", side_effect=RuntimeError("boom")), \
             mock.patch.object(xboard_report, "post_traffic") as post_traffic, \
             mock.patch.object(xboard_report, "post_alive") as post_alive, \
             mock.patch.object(xboard_report, "post_status_legacy") as post_status, \
             mock.patch("builtins.print"):
            xboard_report.post_node_report(
                env,
                "3047",
                "vless",
                {1485: [1, 2]},
                {1485: ["1.2.3.4"]},
                {"cpu": 1},
            )

        post_traffic.assert_called_once_with(env, "3047", "vless", {1485: [1, 2]})
        post_alive.assert_called_once_with(env, "3047", "vless", {1485: ["1.2.3.4"]})
        post_status.assert_called_once_with(env, "3047", "vless", {"cpu": 1})

    def test_post_traffic_skips_empty_payload(self):
        with mock.patch.object(xboard_report.requests, "post") as post, \
             mock.patch("builtins.print"):
            xboard_report.post_traffic(
                {"PANEL_URL": "https://panel.example.com", "PANEL_TOKEN": "token"},
                "3047",
                "vless",
                {},
            )

        post.assert_not_called()

    def test_post_alive_skips_empty_payload(self):
        with mock.patch.object(xboard_report.requests, "post") as post, \
             mock.patch("builtins.print"):
            xboard_report.post_alive(
                {"PANEL_URL": "https://panel.example.com", "PANEL_TOKEN": "token"},
                "3047",
                "vless",
                {},
            )

        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
