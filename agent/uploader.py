import gzip
import json
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(config, path, body=None, authenticated=True):
    headers = {"Content-Type": "application/json"}
    if authenticated:
        headers.update({"Authorization": "Bearer " + config["token"], "X-Agent-ID": config["id"]})
    if body is not None:
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        body = gzip.compress(raw)
        headers["Content-Encoding"] = "gzip"
    req = Request(config["server"].rstrip("/") + path, data=body, headers=headers)
    with build_opener(NoRedirect).open(req, timeout=15) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("central response too large")
        return json.loads(raw)


def upload_one(config, spool, prefix="agents"):
    row = spool.due()
    if row is None:
        return False
    try:
        result = request(config, f"/api/v1/{prefix}/{row['kind']}/batch", row["payload"])
        if result.get("batch_id") != row["batch_id"] or result.get("accepted") is not True:
            raise ValueError("invalid acknowledgement")
        spool.ack(row["batch_id"])
    except HTTPError as error:
        spool.retry(row["batch_id"], error.code in (400, 413, 422), error.code)
    except (OSError, ValueError):
        spool.retry(row["batch_id"])
    return True
