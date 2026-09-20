#!/usr/bin/env python3
"""Local System One-compatible server for offline Hook integration tests."""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockJev(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/systemone" or self.headers.get("Authorization") != "Bearer test-key":
            self.send_error(401)
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(body)
        if request["model"] != "test-jev-model":
            self.send_error(400)
            return
        action = request["questions"]["action"]
        if (
            action["type"] != "choice"
            or set(action["criteria"]) != {"allow", "deny"}
            or not action["instructions"]
        ):
            self.send_error(422)
            return
        state = json.loads(request["state"])
        if (
            state["workspace_path"] != state["cwd"]
            or state["permission_policy"]["allowed_mode"] != "0467"
            or state["permission_policy"]["scope_order"] != ["system", "external", "network", "workspace"]
            or state["permission_policy"]["permission_bits"]["read"]["bit"] != 4
            or state["permission_policy"]["permission_bits"]["write"]["bit"] != 2
            or state["permission_policy"]["permission_bits"]["execute"]["bit"] != 1
            or set(state["permission_policy"]["scope_definitions"]) != {"system", "external", "network", "workspace"}
            or not state["permission_policy"]["rule"]
        ):
            self.send_error(422)
            return
        text = " ".join(str(value) for value in state.values() if value)
        choice, probability = ("allow", 0.96)
        if "uncertain" in text:
            probability = 0.60
        elif "sudo reboot" in text or "/etc/" in text or "jev-block" in text:
            choice, probability = ("deny", 0.99)
        response = {
            "model": "mock-jev",
            "answers": {
                "action": {
                    "type": "choice",
                    "choice": choice,
                    "probabilities": {choice: probability},
                }
            },
        }
        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), MockJev).serve_forever()
