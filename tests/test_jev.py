import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ftest.jev import (
    Credentials,
    JevClient,
    JevFailure,
    RuleBrief,
    Verdict,
    credentials,
    interpret,
    review,
)

BRIEF = RuleBrief(
    rule="Terminal shell in container",
    description="A shell was used as the entrypoint into a container with an attached terminal.",
    priority="NOTICE",
    what_it_does=("Matches events `execve`, `execveat`.",),
)


def pick(choice="NOTICE", confidence=0.8):
    return {"type": "choice", "choice": choice, "confidence": confidence, "probabilities": {}}


def answers(priority="NOTICE", pconf=0.8):
    return {"priority": pick(priority, pconf)}


def answering(judge=lambda state: (0.9, 0.1), priority="NOTICE"):
    """A Stub responder. A priority request gets `priority`; an event request gets the in-scope and
    exception probabilities that `judge` returns for its state."""

    def respond(body):
        if "priority" in body["questions"]:
            found = answers(priority)
        else:
            in_scope, exception = judge(body["state"])
            found = {
                "in_scope": {"type": "noul", "noul": in_scope},
                "exception": {"type": "noul", "noul": exception},
            }
        return 200, {"x-typesafe-request-id": "req-1"}, {"model": "jev-1.13", "answers": found, "usage": {}}

    return respond


class Stub:
    """A local System One endpoint. `script` is a list of (status, headers, body) to serve in order, or a
    function from the request body to one of them."""

    def __init__(self, script, host="127.0.0.1"):
        self.script = script if callable(script) else list(script)
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                sent = json.loads(self.rfile.read(length))
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "body": sent})
                status, headers, body = stub.script(sent) if callable(stub.script) else stub.script.pop(0)
                payload = json.dumps(body).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stubs():
    made = []
    yield lambda script: made.append(Stub(script)) or made[-1]
    for s in made:
        s.close()


def client(url, logs=None, sleeps=None):
    return JevClient(
        Credentials(url, "sk-test"),
        timeout=5,
        sleep=(sleeps.append if sleeps is not None else lambda _: None),
        log=(logs.append if logs is not None else lambda _: None),
    )


def test_review_retries_rate_limits_and_reads_typed_answers(stubs):
    ok = {"model": "jev-1.13", "answers": answers(), "usage": {"input_tokens": 1, "output_tokens": 1}}
    stub = stubs(
        [
            (429, {"retry-after": "0.5"}, {"detail": "slow down"}),
            (200, {"x-typesafe-request-id": "req-123"}, ok),
        ]
    )
    logs, sleeps = [], []
    result = review(client(stub.url, logs, sleeps), "jev-latest", BRIEF)

    assert sleeps == [0.5]
    assert len(stub.requests) == 2
    sent = stub.requests[-1]
    assert sent["path"] == "/v1/systemone"
    assert sent["headers"]["Authorization"] == "Bearer sk-test"
    assert sent["body"]["model"] == "jev-latest"
    assert sent["body"]["state"] == {
        "rule": BRIEF.rule,
        "description": BRIEF.description,
        "what_it_does": list(BRIEF.what_it_does),
    }
    assert set(sent["body"]["questions"]) == {"priority"}
    assert sent["body"]["questions"]["priority"]["type"] == "choice"
    assert list(sent["body"]["questions"]["priority"]["criteria"])[0] == "EMERGENCY"

    assert result.model == "jev-1.13" and result.request_id == "req-123"
    assert logs == ["jev: Terminal shell in container: model=jev-1.13 request_id=req-123"]
    assert (result.verdict, result.text) == (Verdict.OK, "priority NOTICE fits (confidence 0.80)")


def test_redirects_are_not_followed_so_the_key_stays_put(stubs):
    elsewhere = stubs([])
    stub = stubs([(302, {"Location": elsewhere.url + "/v1/systemone"}, {})])
    result = review(client(stub.url), "jev-latest", BRIEF)
    assert isinstance(result, JevFailure) and result.error.startswith("HTTP 302")
    assert elsewhere.requests == []


def test_errors_and_malformed_answers_are_failures_not_crashes(stubs):
    stub = stubs([(401, {}, {"detail": "bad key"})])
    assert review(client(stub.url), "m", BRIEF).error.startswith("HTTP 401")
    stub = stubs([(200, {}, {"model": "m", "answers": {"priority": {"type": "noul"}}, "usage": {}})])
    assert review(client(stub.url), "m", BRIEF).error == "response has no valid `priority` answer"


def test_priority_two_levels_off_is_a_finding_and_one_level_a_review():
    assert interpret(BRIEF, pick("CRITICAL")) == (
        Verdict.FINDING,
        "suggests CRITICAL, declared NOTICE (confidence 0.80)",
    )
    assert interpret(BRIEF, pick("WARNING", 0.9))[0] is Verdict.REVIEW
    assert interpret(BRIEF, pick("ALERT", 0.3)) == (
        Verdict.REVIEW,
        "priority unclear (leans ALERT, confidence 0.30)",
    )


def test_credentials_prefer_jev_key_and_default_base_url():
    assert credentials({}) is None
    creds = credentials({"TYPESAFE_API_KEY": "t", "JEV_BASE_URL": "http://localhost:9/"})
    assert creds == Credentials("http://localhost:9", "t")
    assert credentials({"JEV_API_KEY": "j", "TYPESAFE_API_KEY": "t"}).api_key == "j"
    assert credentials({"JEV_API_KEY": "j"}).base_url == "https://api.typesafe.ai"
    assert "j" not in repr(credentials({"JEV_API_KEY": "j"}))
