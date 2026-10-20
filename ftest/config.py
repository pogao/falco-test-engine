"""`falco-test.yaml`: parsed once into a frozen Config. Paths are relative to the file."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


# Share of the ordinary events of a rule's event types that the rule may fire on. Calibrated with
# scripts/noise_calibration.py on the 315 built-in events (97 execve, 146 openat, 72 connect):
# - All 25 stock rules and the example rules fire on 0. That is the floor for a correct rule.
# - One benign false positive is 1.0% of the execs, 0.7% of the opens, 1.4% of the connects. 5% lets a
#   correct but untuned rule have 3 or 4 of them and still pass.
# - Inversions that fire broadly fire on 14.4% to 100%: `not` on the package manager list fires on
#   15.5%, `proc.tty = 0` instead of `!= 0` on 14.4%, the whole condition negated on 100%. 5% leaves a
#   3x margin below the smallest.
# What limits it: an inversion can only fire on the corpus events its other conditions allow. Narrow
# ones (inverting one exception, dropping `container`) fire on 1.4% to 2.1% and pass this check. The
# mutation score finds those, because they need test cases rather than benign traffic.
DEFAULT_MAX_FIRE_RATE = 0.05


@dataclass(frozen=True)
class PluginSpec:
    name: str
    library_path: str
    init_config: str


@dataclass(frozen=True)
class Startup:
    enabled: bool
    falco_config: Path


class JevMode(Enum):
    AUTO = "auto"
    ON = "on"
    OFF = "off"


@dataclass(frozen=True)
class JevSettings:
    mode: JevMode
    model: str
    gate: bool


@dataclass(frozen=True)
class NoiseSettings:
    enabled: bool
    max_fire_rate: float
    corpus: tuple[Path, ...]


@dataclass(frozen=True)
class MutationSettings:
    enabled: bool
    min_score: float | None


@dataclass(frozen=True)
class ReportPaths:
    markdown: Path | None
    json: Path | None


@dataclass(frozen=True)
class Config:
    path: Path
    rules_files: tuple[Path, ...]
    base_rules_files: tuple[Path, ...]
    plugins: tuple[PluginSpec, ...]
    tests: tuple[Path, ...]
    startup: Startup
    lint_disable: frozenset[str]
    jev: JevSettings
    report: ReportPaths
    engine_binary: str
    noise: NoiseSettings
    mutation: MutationSettings

    @property
    def root(self) -> Path:
        return self.path.parent


DEFAULT_PLUGIN = PluginSpec("container", "/usr/share/falco/plugins/libcontainer.so", "{}")
_TOP_KEYS = {
    "rules_files",
    "base_rules_files",
    "plugins",
    "tests",
    "startup",
    "lint",
    "jev",
    "report",
    "engine",
    "noise",
    "mutation",
}


def load_config(path: Path) -> Config:
    path = path.resolve()
    try:
        raw = yaml.safe_load(path.read_text())
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"{path}: invalid YAML: {e}") from e
    return parse_config(raw, path)


def parse_config(raw: Any, path: Path) -> Config:
    doc = _mapping(raw, str(path), _TOP_KEYS)
    root = path.parent

    def paths(key: str, required: bool) -> tuple[Path, ...]:
        items = doc.get(key)
        if items is None and not required:
            return ()
        if not isinstance(items, list) or not items or not all(isinstance(i, str) for i in items):
            raise ConfigError(f"{path}: `{key}` must be a non-empty list of paths")
        return tuple(root / i for i in items)

    startup = _mapping(doc.get("startup", {}), "startup", {"enabled", "falco_config"})
    lint = _mapping(doc.get("lint", {}), "lint", {"disable"})
    jev = _mapping(doc.get("jev", {}), "jev", {"enabled", "model", "gate"})
    report = _mapping(doc.get("report", {}), "report", {"markdown", "json"})
    engine = _mapping(doc.get("engine", {}), "engine", {"binary"})
    noise = _mapping(doc.get("noise", {}), "noise", {"enabled", "max_fire_rate", "corpus"})
    mutation = _mapping(doc.get("mutation", {}), "mutation", {"enabled", "min_score"})
    corpus = noise.get("corpus", [])
    if not isinstance(corpus, list) or not all(isinstance(c, str) for c in corpus):
        raise ConfigError("noise.corpus must be a list of paths")

    disable = lint.get("disable", [])
    if not isinstance(disable, list) or not all(isinstance(c, str) for c in disable):
        raise ConfigError("lint.disable must be a list of finding codes")

    binary = _str(engine, "binary", "falco-test-engine", "engine")
    return Config(
        path=path,
        rules_files=paths("rules_files", required=True),
        base_rules_files=paths("base_rules_files", required=False),
        plugins=_plugins(doc.get("plugins")),
        tests=paths("tests", required=True),
        startup=Startup(
            enabled=_bool(startup, "enabled", True, "startup"),
            falco_config=root / _str(startup, "falco_config", "/etc/falco/falco.yaml", "startup"),
        ),
        lint_disable=frozenset(disable),
        jev=JevSettings(
            mode=_jev_mode(jev.get("enabled", "auto")),
            model=_str(jev, "model", "jev-latest", "jev"),
            gate=_bool(jev, "gate", False, "jev"),
        ),
        report=ReportPaths(
            markdown=_optional_path(report, "markdown", "falco-test-report.md", root),
            json=_optional_path(report, "json", "falco-test-report.json", root),
        ),
        engine_binary=str(root / binary) if "/" in binary else binary,
        noise=NoiseSettings(
            enabled=_bool(noise, "enabled", True, "noise"),
            max_fire_rate=fraction(noise.get("max_fire_rate", DEFAULT_MAX_FIRE_RATE), "noise.max_fire_rate"),
            corpus=tuple(root / c for c in corpus),
        ),
        mutation=MutationSettings(
            enabled=_bool(mutation, "enabled", True, "mutation"),
            min_score=None
            if mutation.get("min_score") is None
            else fraction(mutation["min_score"], "mutation.min_score"),
        ),
    )


def fraction(value: Any, where: str, error: type[Exception] = ConfigError) -> float:
    """A share between 0 and 1, such as 0.05 for 5%."""
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
        raise error(f"{where} must be a number from 0 to 1, such as 0.05 for 5%")
    return float(value)


def _plugins(raw: Any) -> tuple[PluginSpec, ...]:
    if raw is None:
        return (DEFAULT_PLUGIN,)
    if not isinstance(raw, list):
        raise ConfigError("plugins must be a list")
    specs = []
    for i, item in enumerate(raw):
        entry = _mapping(item, f"plugins[{i}]", {"name", "library_path", "init_config"})
        init = entry.get("init_config", {})
        if not isinstance(init, str | dict):
            raise ConfigError(f"plugins[{i}].init_config must be a mapping or a JSON string")
        specs.append(
            PluginSpec(
                name=_str(entry, "name", None, f"plugins[{i}]"),
                library_path=_str(entry, "library_path", None, f"plugins[{i}]"),
                init_config=init if isinstance(init, str) else json.dumps(init),
            )
        )
    return tuple(specs)


def _jev_mode(value: Any) -> JevMode:
    match value:
        case True:
            return JevMode.ON
        case False:
            return JevMode.OFF
        case "auto":
            return JevMode.AUTO
    raise ConfigError("jev.enabled must be true, false, or auto")


def _mapping(raw: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a mapping")
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}; allowed: {sorted(allowed)}")
    return raw


def _str(doc: dict[str, Any], key: str, default: str | None, where: str) -> str:
    value = doc.get(key, default)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}.{key} must be a non-empty string")
    return value


def _bool(doc: dict[str, Any], key: str, default: bool, where: str) -> bool:
    value = doc.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be true or false")
    return value


def _optional_path(doc: dict[str, Any], key: str, default: str, root: Path) -> Path | None:
    value = doc.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"report.{key} must be a path or null")
    return root / value
