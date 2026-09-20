import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.access_parser import parse_line
from agent.aggregator import Aggregator
from agent.audit_agent import read_chunk
from agent.spool import Spool
from agent.uploader import upload_one


def line(
    source="1.2.3.4:5000", destination="tcp:Example.COM.:443", tail="[vless-443 -> relay] email: 379:1485"
):
    return f"2026/09/19 07:00:01 {source} accepted {destination} {tail}\n"


class ParserTests(unittest.TestCase):
    def test_fixtures(self):
        fixtures = [
            (line(), "source_ip", "1.2.3.4"),
            (line(), "destination_domain", "example.com"),
            (line(destination="tcp:8.8.8.8:53"), "destination_ip", "8.8.8.8"),
            (line(source="[2001:db8::1]:123"), "source_ip", "2001:db8::1"),
            (line(source="[::ffff:1.2.3.4]:123"), "source_ip", "1.2.3.4"),
            (line(destination="tcp:[2001:db8::2]:443"), "destination_ip", "2001:db8::2"),
            (line(), "node_id", 379),
            (line(), "user_id", 1485),
            (line(tail="email: 42"), "node_id", None),
            (line(tail="email: 42"), "user_id", 42),
            (line(tail=""), "user_id", None),
            (line().replace("accepted", "rejected"), "decision", "rejected"),
            (line(destination="udp:example.com:65535"), "network", "udp"),
            (line(destination="tcp:example.com:1"), "destination_port", 1),
            (line(), "outbound_tag", "relay"),
            (line().replace("1.2.3.4:5000", "from 1.2.3.4:5000"), "source_ip", "1.2.3.4"),
            (
                line(destination="tcp:https://Example.com/private?password=secret"),
                "destination_domain",
                "example.com",
            ),
            (line(destination="tcp:例子.中国:443"), "destination_domain", "xn--fsqu00a.xn--fiqs8s"),
            (line(tail="[in >> direct] email: 1:2"), "inbound_tag", "in"),
            (line().replace("07:00:01", "07:00:01.123456"), "event_time", "2026-09-19T07:00:01.123456+00:00"),
            (line(destination="tcp:http://example.com/a?cookie=b"), "destination_port", 80),
        ]
        for raw, field, expected in fixtures:
            with self.subTest(raw=raw, field=field):
                self.assertEqual(parse_line(raw)[field], expected)
                self.assertNotIn("secret", json.dumps(parse_line(raw)))
        for raw in (
            "garbage",
            line(source="999.2.3.4:12"),
            line(destination="tcp:x:0"),
            line(destination="tcp:bad_name:443"),
            line(destination="tcp:999.1.1.1:443"),
        ):
            self.assertIsNone(parse_line(raw))

    def test_single_node_legacy(self):
        self.assertEqual(parse_line(line(tail="email: 3"), single_node=9)["node_id"], 9)


class AggregatorTests(unittest.TestCase):
    def test_duplicate_rollover_separation_and_bound(self):
        aggregator = Aggregator(max_keys=3)
        aggregator.add(parse_line(line()))
        aggregator.add(parse_line(line()))
        aggregator.add(parse_line(line(source="2.3.4.5:100")))
        aggregator.add(parse_line(line().replace("07:00", "07:01")))
        self.assertEqual([x["connections"] for x in aggregator.rows()], [2, 1, 1])
        with self.assertRaises(BufferError):
            aggregator.add(parse_line(line(destination="tcp:other.test:443")))


class SpoolTests(unittest.TestCase):
    def test_restart_retry_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spool.db"
            spool = Spool(path, reserve_mb=0)
            spool.commit("events", [{"connections": 3}], {"offset": 100})
            batch_id = spool.due()["batch_id"]
            spool.close()
            spool = Spool(path, reserve_mb=0)
            self.assertEqual(spool.state("cursor"), {"offset": 100})
            with patch("agent.uploader.request", side_effect=OSError("offline")):
                upload_one({}, spool)
            self.assertEqual(spool.health()["spool_rows"], 1)
            with spool.db:
                spool.db.execute("UPDATE pending_batches SET next_try=0")
            with patch("agent.uploader.request", return_value={"accepted": True, "batch_id": batch_id}):
                upload_one({}, spool)
            spool.ack(batch_id)
            self.assertEqual(spool.health()["spool_rows"], 0)
            spool.close()

    def test_disk_cap_and_batch_split(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = Spool(Path(directory) / "spool.db", max_mb=1, reserve_mb=0)
            for _ in range(30):
                spool.commit("events", [{"value": "x" * 3000} for _ in range(10)], max_events=5)
            self.assertLessEqual(spool.size(), 1024 * 1024)
            self.assertGreater(spool.state("evicted_batches"), 0)
            self.assertLessEqual(len(json.loads(spool.due()["payload"])["events"]), 5)
            spool.close()

    def test_rotation_truncation_and_partial_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            spool = Spool(Path(directory) / "spool.db", reserve_mb=0)
            config = {"access_log": str(path)}
            path.write_text(line() + "2026/09/19")
            self.assertEqual(read_chunk(config, spool), 1)
            self.assertEqual(read_chunk(config, spool), 0)
            path.rename(path.with_suffix(".old"))
            path.write_text(line(source="2.3.4.5:22"))
            self.assertEqual(read_chunk(config, spool), 1)
            path.write_text(line(source="3.4.5.6:22") * 3)
            self.assertEqual(read_chunk(config, spool), 3)
            spool.close()

    def test_transaction_does_not_advance_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = Spool(Path(directory) / "spool.db", reserve_mb=0)
            with self.assertRaises(ValueError):
                spool.commit("events", [{"value": "x" * 1000}], {"offset": 50}, max_bytes=300)
            self.assertIsNone(spool.state("cursor"))
            spool.close()
