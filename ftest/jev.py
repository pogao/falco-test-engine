"""Advisory judgments from Jev (TypeSafe System One).

Jev is weak at negation, arithmetic, and literal logic, so it never reads a rule's condition; the
engine evaluates conditions. Jev judges which priority fits a rule's description.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

DEFAULT_BASE_URL = "https://api.typesafe.ai"
KEY_VARS = ("JEV_API_KEY", "TYPESAFE_API_KEY")

CONFIDENCE_MIN = 0.5

PRIORITIES: tuple[tuple[str, str], ...] = (
    ("EMERGENCY", "The host or cluster is unusable or is being destroyed right now."),
    ("ALERT", "A confirmed active compromise that needs immediate action."),
    ("CRITICAL", "A highly likely compromise, or a critical security control was disabled."),
    ("ERROR", "A serious security event that needs prompt investigation."),
    ("WARNING", "Suspicious activity that is often malicious and should be reviewed."),
    ("NOTICE", "Unusual activity worth recording that is sometimes legitimate."),
    ("INFORMATIONAL", "Routine activity recorded for audit or context."),
    ("DEBUG", "Diagnostic detail with no direct security meaning."),
)


class Verdict(Enum):
    OK = "ok"
    REVIEW = "review"
    FINDING = "finding"


@dataclass(frozen=True)
class RuleBrief:
    rule: str
    description: str
    priority: str
    what_it_does: tuple[str, ...]


@dataclass(frozen=True)
class JevReview:
    """Jev's priority pick compared with the declared priority."""

    rule: str
    model: str
    request_id: str | None
    verdict: Verdict
    text: str


@dataclass(frozen=True)
class JevFailure:
    rule: str
    error: str


@dataclass(frozen=True)
class Credentials:
    base_url: str
    api_key: str = field(repr=False)


def credentials(env: Mapping[str, str] = os.environ) -> Credentials | None:
    key = next((env[v] for v in KEY_VARS if env.get(v)), None)
    if key is None:
        return None
    return Credentials(env.get("JEV_BASE_URL", DEFAULT_BASE_URL).rstrip("/"), key)


PRIORITY_QUESTIONS: dict[str, Any] = {
    "priority": {
        "type": "choice",
        "instructions": "Which Falco priority fits an alert from this rule, judged from `description` "
        "and `what_it_does`?",
        "criteria": dict(PRIORITIES),
    }
}


def state(brief: RuleBrief) -> dict[str, Any]:
    """The declared priority stays out, so Jev's pick is not anchored on it."""
    return {"rule": brief.rule, "description": brief.description, "what_it_does": list(brief.what_it_does)}


def interpret(brief: RuleBrief, pick: Mapping[str, Any]) -> tuple[Verdict, str]:
    chosen, confidence = pick["choice"], float(pick["confidence"])
    names = [n for n, _ in PRIORITIES]
    if confidence < CONFIDENCE_MIN:
        return Verdict.REVIEW, f"priority unclear (leans {chosen}, confidence {confidence:.2f})"
    if brief.priority not in names or chosen == brief.priority:
        return Verdict.OK, f"priority {brief.priority} fits (confidence {confidence:.2f})"
    distance = abs(names.index(chosen) - names.index(brief.priority))
    verdict = Verdict.REVIEW if distance == 1 else Verdict.FINDING
    return verdict, f"suggests {chosen}, declared {brief.priority} (confidence {confidence:.2f})"


class JevError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the request, and so the key, to another URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_ANSWER_KEYS = {"noul": ("noul",), "choice": ("choice", "confidence")}


class JevClient:
    def __init__(
        self,
        creds: Credentials,
        timeout: float = 30,
        attempts: int = 4,
        sleep: Callable[[float], None] = time.sleep,
        log: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
    ):
        self._creds = creds
        self._timeout = timeout
        self._attempts = attempts
        self._sleep = sleep
        self._log = log
        self._opener = urllib.request.build_opener(_NoRedirect)

    def ask(self, model: str, state: dict, questions: dict, label: str = "") -> tuple[dict, str, str | None]:
        body = json.dumps({"model": model, "state": state, "questions": questions}).encode()
        for attempt in range(self._attempts):
            request = urllib.request.Request(
                f"{self._creds.base_url}/v1/systemone",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            request.add_unredirected_header("Authorization", f"Bearer {self._creds.api_key}")
            last = attempt == self._attempts - 1
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    doc = json.load(response)
                    request_id = response.headers.get("x-typesafe-request-id")
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 529) and not last:
                    self._sleep(_retry_delay(e.headers.get("retry-after"), attempt))
                    continue
                raise JevError(f"HTTP {e.code}: {_excerpt(e)}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if not last:
                    self._sleep(_retry_delay(None, attempt))
                    continue
                raise JevError(f"request failed: {getattr(e, 'reason', e)}") from None
            except ValueError as e:
                raise JevError(f"response is not JSON: {e}") from None
        answers = doc.get("answers") if isinstance(doc, dict) else None
        if not isinstance(answers, dict):
            raise JevError("response has no answers")
        for name, q in questions.items():
            a = answers.get(name)
            if (
                not isinstance(a, dict)
                or a.get("type") != q["type"]
                or any(k not in a for k in _ANSWER_KEYS[q["type"]])
            ):
                raise JevError(f"response has no valid `{name}` answer")
        used_model = str(doc.get("model", model))
        self._log(f"jev: {label}: model={used_model} request_id={request_id}")
        return answers, used_model, request_id


def _retry_delay(header: str | None, attempt: int) -> float:
    try:
        return min(max(float(header), 0.0), 60.0) if header is not None else float(2**attempt)
    except ValueError:
        return float(2**attempt)


def _excerpt(error: urllib.error.HTTPError) -> str:
    try:
        return error.read().decode(errors="replace")[:200]
    except OSError:
        return error.reason


def review(client: JevClient, model: str, brief: RuleBrief) -> JevReview | JevFailure:
    try:
        answers, used_model, request_id = client.ask(model, state(brief), PRIORITY_QUESTIONS, brief.rule)
    except JevError as e:
        return JevFailure(brief.rule, str(e))
    return JevReview(brief.rule, used_model, request_id, *interpret(brief, answers["priority"]))
