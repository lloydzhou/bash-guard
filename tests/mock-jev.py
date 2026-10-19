#!/usr/bin/env python3
"""Local System One-compatible server for offline Hook integration tests."""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

SCOPES = ("system", "external", "network", "workspace")
BITS = ("read", "write", "execute")


def noul_answers(required):
    answers = {}
    for scope in SCOPES:
        for bit in BITS:
            probability = 0.99 if (scope, bit) in required else 0.10
            answers[f"{scope}.{bit}"] = {"type": "noul", "noul": probability}
    return answers


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
        questions = request["questions"]
        expected_keys = {f"{scope}.{bit}" for scope in SCOPES for bit in BITS}
        if (
            set(questions) != expected_keys
            or any(question["type"] != "noul" or not question["instructions"] for question in questions.values())
        ):
            self.send_error(422)
            return
        state = json.loads(request["state"])
        policy = state["permission_policy"]
        if (
            state["workspace_path"] != state["cwd"]
            or "allowed_mode" in policy
            or policy["scope_order"] != ["system", "external", "network", "workspace"]
            or policy["permission_bits"]["read"]["bit"] != 4
            or policy["permission_bits"]["write"]["bit"] != 2
            or policy["permission_bits"]["execute"]["bit"] != 1
            or set(policy["scope_definitions"]) != {"system", "external", "network", "workspace"}
            or not policy["rule"]
        ):
            self.send_error(422)
            return
        text = " ".join(str(value) for value in state.values() if value)
        if "sudo reboot" in text:
            required = {("system", "execute")}
        elif "/etc/" in text:
            required = {("system", "read")}
        elif "jev-block" in text:
            required = {("system", "write")}
        else:
            required = set()
        response = {"model": "mock-jev", "answers": noul_answers(required)}
        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), MockJev).serve_forever()
