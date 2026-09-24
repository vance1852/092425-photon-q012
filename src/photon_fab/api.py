"""用于离线验收的无依赖 JSON HTTP API。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import PhotonService


class Handler(BaseHTTPRequestHandler):
    service = PhotonService()

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _token(self) -> str:
        return self.headers.get("Authorization", "").removeprefix("Bearer ")

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"status": "ok", "service": "photon-fab"})
        if self.path.startswith("/lots/"):
            try:
                lot = self.service.get_lot(self._token(), self.path.split("/", 2)[2])
                return self._json(200, lot)
            except PermissionError as exc:
                return self._json(403, {"error": str(exc)})
            except KeyError:
                return self._json(404, {"error": "lot not found"})
            except Exception as exc:
                return self._json(400, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            body = json.loads(raw) if raw.strip() else {}
        except Exception:
            return self._json(400, {"error": "invalid json body"})

        def field(name: str):
            if name not in body:
                raise ValueError(f"missing field: {name}")
            return body[name]

        try:
            if self.path == "/login":
                try:
                    token = self.service.auth.login(field("user_id"), field("password"))
                except PermissionError:
                    return self._json(401, {"error": "invalid credentials"})
                return self._json(200, {"token": token})
            token = self._token()
            if self.path == "/lots":
                return self._json(201, self.service.create_lot(token, field("lot_id"), field("product"), field("process_rev"), field("wafer_count")))
            if self.path.startswith("/lots/") and self.path.endswith("/measurements"):
                lot_id = self.path.split("/")[2]
                return self._json(201, self.service.add_measurement(token, lot_id, field("wavelength_nm"), field("response"), body.get("noise", 0.0), field("instrument")))
            if self.path.startswith("/lots/") and self.path.endswith("/analysis"):
                return self._json(200, self.service.analyze(token, self.path.split("/")[2]))
            if self.path.startswith("/users/") and self.path.endswith("/deactivate"):
                user_id = self.path.split("/")[2]
                return self._json(200, self.service.deactivate_user(token, user_id))
            return self._json(404, {"error": "not found"})
        except PermissionError as exc:
            return self._json(403, {"error": str(exc)})
        except KeyError:
            return self._json(404, {"error": "not found"})
        except Exception as exc:
            return self._json(400, {"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=":memory:")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    Handler.service = PhotonService(args.database)
    Handler.service.bootstrap_admin()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
