import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ftest.jev import (
    CaseBrief,
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
    condition="spawned_process and container and shell_procs and proc.tty != 0",
    compiled_condition="evt.type in (execve, execveat) and container.id != host",
    what_it_does=("Matches events `execve`, `execveat`.",),
    intent="Alert on interactive shells in containers except the CI runner image.",
    test_cases=(CaseBrief("bash in nginx", "match", "fired: Terminal shell in container", True),),
    coverage_gaps=("macro `spawned_process` never false",),
)


def answers(desc=0.92, intent=0.81, cover=0.4, priority="NOTICE", pconf=0.8, noise=0.2, nconf=0.7):
    return {
        "desc_matches": {"type": "noul", "noul": desc},
        "intent_matches": {"type": "noul", "noul": intent},
        "tests_cover_intent": {"type": "noul", "noul": cover},
        "priority": {"type": "choice", "choice": priority, "confidence": pconf, "probabilities": {}},
        "noise_risk": {
            "type": "score",
            "score": noise,
            "confidence": nconf,
            "legend": {},
            "probabilities": {},
        },
    }


class Stub:
    """A local System One endpoint. `script` is a list of (status, headers, body) to serve in order."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                stub.requests.append(
                    {
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": json.loads(self.rfile.read(length)),
                    }
                )
                status, headers, body = stub.script.pop(0)
                payload = json.dumps(body).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
    assert sent["body"]["state"]["rule"] == BRIEF.rule
    assert sent["body"]["state"]["test_cases"][0] == {
        "name": "bash in nginx",
        "expected": "match",
        "actual": "fired: Terminal shell in container",
        "passed": True,
    }
    assert set(sent["body"]["questions"]) == {
        "desc_matches",
        "intent_matches",
        "tests_cover_intent",
        "priority",
        "noise_risk",
    }
    assert sent["body"]["questions"]["priority"]["type"] == "choice"
    assert list(sent["body"]["questions"]["priority"]["criteria"])[0] == "EMERGENCY"

    assert result.model == "jev-1.13" and result.request_id == "req-123"
    assert logs == ["jev: Terminal shell in container: model=jev-1.13 request_id=req-123"]
    verdicts = {n.question: n.verdict for n in result.notes}
    assert verdicts == {
        "desc_matches": Verdict.OK,
        "intent_matches": Verdict.OK,
        "tests_cover_intent": Verdict.REVIEW,
        "priority": Verdict.OK,
        "noise_risk": Verdict.OK,
    }


def test_redirects_are_not_followed_so_the_key_stays_put(stubs):
    elsewhere = stubs([])
    stub = stubs([(302, {"Location": elsewhere.url + "/v1/systemone"}, {})])
    result = review(client(stub.url), "jev-latest", BRIEF)
    assert isinstance(result, JevFailure) and result.error.startswith("HTTP 302")
    assert elsewhere.requests == []


def test_errors_and_malformed_answers_are_failures_not_crashes(stubs):
    stub = stubs([(401, {}, {"detail": "bad key"})])
    assert review(client(stub.url), "m", BRIEF).error.startswith("HTTP 401")
    broken = answers()
    del broken["noise_risk"]
    stub = stubs([(200, {}, {"model": "m", "answers": broken, "usage": {}})])
    assert review(client(stub.url), "m", BRIEF).error == "response has no valid `noise_risk` answer"


def test_intent_question_only_when_the_suite_states_an_intent(stubs):
    no_intent = RuleBrief(**{**BRIEF.__dict__, "intent": None})
    a = answers()
    del a["intent_matches"]
    stub = stubs([(200, {}, {"model": "m", "answers": a, "usage": {}})])
    review(client(stub.url), "m", no_intent)
    sent = stub.requests[0]["body"]
    assert "intent_matches" not in sent["questions"] and "intent" not in sent["state"]
    assert "`description`" in sent["questions"]["tests_cover_intent"]["instructions"]


def test_thresholds_turn_answers_into_verdicts():
    notes = {n.question: n for n in interpret(BRIEF, answers(desc=0.12, priority="CRITICAL", noise=1.8))}
    assert notes["desc_matches"].verdict is Verdict.FINDING
    assert notes["desc_matches"].text == "description may not match the condition (p=0.12)"
    assert notes["priority"].verdict is Verdict.FINDING
    assert notes["priority"].text == "suggests CRITICAL, declared NOTICE (confidence 0.80)"
    assert notes["noise_risk"].text == "likely noisy in production (score 1.8, confidence 0.70)"
    near = {
        n.question: n.verdict for n in interpret(BRIEF, answers(priority="WARNING", pconf=0.9, nconf=0.3))
    }
    assert near["priority"] is Verdict.REVIEW and near["noise_risk"] is Verdict.REVIEW
    unsure = {n.question: n.verdict for n in interpret(BRIEF, answers(priority="ALERT", pconf=0.3))}
    assert unsure["priority"] is Verdict.REVIEW


def test_credentials_prefer_jev_key_and_default_base_url():
    assert credentials({}) is None
    creds = credentials({"TYPESAFE_API_KEY": "t", "JEV_BASE_URL": "http://localhost:9/"})
    assert creds == Credentials("http://localhost:9", "t")
    assert credentials({"JEV_API_KEY": "j", "TYPESAFE_API_KEY": "t"}).api_key == "j"
    assert credentials({"JEV_API_KEY": "j"}).base_url == "https://api.typesafe.ai"
    assert "j" not in repr(credentials({"JEV_API_KEY": "j"}))
