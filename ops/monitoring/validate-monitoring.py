#!/usr/bin/env python3
"""Validate Kovanica Grafana dashboards and Prometheus alert rules.

Uses Python standard library only.
- Cross-checks every referenced `stratum_*` metric in both
  `kovanica-stratum-dashboard.json` and `kovanica-stratum-alerts.yml`
  against the metrics registered in `crates/kovanica-stratum/src/gateway.rs`.
- Cross-checks `kovanica-ecosystem-overview.json` (JSON structure, unique panel
  IDs, valid gridPos, templating datasource variable, minimum panel count,
  balanced non-empty PromQL targets, and every referenced metric against all
  metrics exported by the `kovanica-l1` codebase).
- Cross-checks `kovanica-ecosystem-alerts.yml` (YAML structure, required fields
  `alert`/`expr`/`for`/`labels.severity`/`annotations.summary`/`annotations.description`,
  minimum alert rule count, required coverage metrics, and zero unknown metrics
  against all metrics exported by the `kovanica-l1` codebase including
  `kovanica-comms-relay`).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
GATEWAY_RS = REPO_ROOT / "crates" / "kovanica-stratum" / "src" / "gateway.rs"
CONSENSUS_METRICS_RS = REPO_ROOT / "crates" / "kovanica-consensus" / "src" / "metrics.rs"
RPC_LIB_RS = REPO_ROOT / "crates" / "kovanica-rpc" / "src" / "lib.rs"
INDEXER_RS = REPO_ROOT / "crates" / "kovanica-indexer" / "src" / "indexer.rs"
FAUCET_RS = REPO_ROOT / "crates" / "kovanica-faucet" / "src" / "main.rs"
COMMS_RELAY_SERVER_RS = REPO_ROOT / "crates" / "kovanica-comms-relay" / "src" / "server.rs"

DASHBOARD_JSON = SCRIPT_DIR / "kovanica-stratum-dashboard.json"
ALERTS_YML = SCRIPT_DIR / "kovanica-stratum-alerts.yml"
ECOSYSTEM_DASHBOARD_JSON = SCRIPT_DIR / "kovanica-ecosystem-overview.json"
ECOSYSTEM_ALERTS_YML = SCRIPT_DIR / "kovanica-ecosystem-alerts.yml"

MIN_ECOSYSTEM_PANELS = 12
MIN_ECOSYSTEM_ALERT_RULES = 6
REQUIRED_ECOSYSTEM_METRICS = (
    "rpc_get_logs_max_span_rejected_total",
    "rpc_get_logs_cursor_requests_total",
)
REQUIRED_ECOSYSTEM_ALERT_METRICS = (
    "indexer_store_integrity_ok",
    "kovanica_comms_relay_envelopes_queued",
    "kovanica_comms_relay_envelopes_rate_limited_total",
    "kovanica_faucet_balance_atoms",
    "kovanica_faucet_rate_limited_total",
    "rpc_get_logs_max_span_rejected_total",
)
VALID_ALERT_SEVERITIES = frozenset({"info", "warning", "critical"})
PROM_DURATION_RE = re.compile(r"^\d+[smhdwy]$")

METRIC_RE = re.compile(r"\bstratum_[a-z0-9_]+\b")
PROMQL_IDENT_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")
PROMQL_KEYWORDS = frozenset(
    {
        "abs",
        "and",
        "avg",
        "bool",
        "by",
        "ceil",
        "changes",
        "clamp",
        "clamp_max",
        "clamp_min",
        "count",
        "count_values",
        "delta",
        "floor",
        "group",
        "group_left",
        "group_right",
        "histogram_quantile",
        "idelta",
        "ignoring",
        "increase",
        "irate",
        "max",
        "min",
        "offset",
        "on",
        "or",
        "quantile",
        "rate",
        "resets",
        "round",
        "scalar",
        "sort",
        "sort_desc",
        "stddev",
        "stdvar",
        "sum",
        "time",
        "topk",
        "unless",
        "up",
        "vector",
        "without",
    }
)


def extract_exported_metrics(gateway_path: Path) -> set[str]:
    """Parse GatewayMetrics::new() in gateway.rs and return all exported Prometheus names."""
    source = gateway_path.read_text(encoding="utf-8")

    # Map local variable name -> kind ("counter", "gauge", "histogram")
    var_kinds: dict[str, str] = {}
    for match in re.finditer(
        r"let\s+([a-z0-9_]+)\s*=\s*([^;]+);",
        source,
        re.MULTILINE,
    ):
        var_name, rhs = match.group(1), match.group(2)
        if "Counter" in rhs:
            var_kinds[var_name] = "counter"
        elif "Histogram" in rhs:
            var_kinds[var_name] = "histogram"
        elif "Gauge" in rhs:
            var_kinds[var_name] = "gauge"

    exported: set[str] = set()
    reg_pattern = re.compile(
        r'registry\.register\(\s*"(stratum_[a-z0-9_]+)"\s*,\s*"[^"]*"\s*,\s*([a-z0-9_]+)\.clone\(\)\s*,?\s*\)',
        re.MULTILINE,
    )
    for match in reg_pattern.finditer(source):
        base_name, var_name = match.group(1), match.group(2)
        kind = var_kinds.get(var_name)
        if kind == "counter":
            # prometheus_client automatically appends `_total` to Counters.
            exported.add(f"{base_name}_total")
        elif kind == "histogram":
            exported.add(base_name)
            exported.add(f"{base_name}_bucket")
            exported.add(f"{base_name}_sum")
            exported.add(f"{base_name}_count")
        elif kind == "gauge":
            exported.add(base_name)
        else:
            raise ValueError(
                f"Could not determine metric type for registered metric '{base_name}' (var '{var_name}')"
            )

    if not exported:
        raise ValueError(f"No stratum_* metrics found in {gateway_path}")
    return exported


def strip_test_modules(source: str) -> str:
    """Strip top-level `#[cfg(test)] mod ...` sections without dropping earlier `#[cfg(test)]` helper methods."""
    return re.split(r"(?m)^#\[cfg\(test\)\]\s*\nmod\s+", source, maxsplit=1)[0]


def extract_consensus_metrics(metrics_path: Path) -> set[str]:
    """Parse crates/kovanica-consensus/src/metrics.rs for all registered Prometheus metrics."""
    source = strip_test_modules(metrics_path.read_text(encoding="utf-8"))

    exported: set[str] = set()
    static_pattern = re.compile(
        r"static\s+[A-Z0-9_]+:\s*Lazy<([^>]+(?:<[^>]+>)?)\s*>\s*=\s*Lazy::new\(\|\|\s*\{(.*?)\n\}\);",
        re.DOTALL,
    )
    reg_pattern = re.compile(
        r'registry\.register(?:_with_unit)?\(\s*"([a-z0-9_]+)"\s*,\s*"[^"]*"\s*,(?:\s*Unit::([A-Za-z]+)\s*,)?',
        re.MULTILINE,
    )

    for match in static_pattern.finditer(source):
        type_decl, body = match.group(1), match.group(2)
        if "Counter" in type_decl:
            kind = "counter"
        elif "Histogram" in type_decl:
            kind = "histogram"
        elif "Gauge" in type_decl:
            kind = "gauge"
        else:
            continue

        for reg_match in reg_pattern.finditer(body):
            base_name = reg_match.group(1)
            unit = reg_match.group(2)
            if unit == "Seconds":
                base_name = f"{base_name}_seconds"
            elif unit == "Bytes":
                base_name = f"{base_name}_bytes"

            if kind == "counter":
                exported.add(f"{base_name}_total")
            elif kind == "histogram":
                exported.add(base_name)
                exported.add(f"{base_name}_bucket")
                exported.add(f"{base_name}_sum")
                exported.add(f"{base_name}_count")
            elif kind == "gauge":
                exported.add(base_name)

    if not exported:
        raise ValueError(f"No consensus metrics found in {metrics_path}")
    return exported


def extract_text_exposition_metrics(source_path: Path) -> set[str]:
    """Extract Prometheus metrics emitted via `# TYPE <name> <kind>` lines in Rust sources."""
    source = strip_test_modules(source_path.read_text(encoding="utf-8"))

    exported: set[str] = set()
    type_pattern = re.compile(r"# TYPE ([a-z][a-z0-9_]+) (counter|gauge|histogram)\b")
    for match in type_pattern.finditer(source):
        name, kind = match.group(1), match.group(2)
        exported.add(name)
        if kind == "counter" and not name.endswith("_total"):
            # OpenMetrics 1.0 declares `# TYPE <family> counter` and emits `<family>_total` samples.
            exported.add(f"{name}_total")
        elif kind == "histogram":
            exported.add(f"{name}_bucket")
            exported.add(f"{name}_sum")
            exported.add(f"{name}_count")

    if not exported:
        raise ValueError(f"No `# TYPE` metrics found in {source_path}")
    return exported


def extract_all_codebase_metrics() -> set[str]:
    """Collect every Prometheus metric name exported across all kovanica-l1 crates."""
    exported: set[str] = set()
    exported |= extract_exported_metrics(GATEWAY_RS)
    exported |= extract_consensus_metrics(CONSENSUS_METRICS_RS)
    exported |= extract_text_exposition_metrics(RPC_LIB_RS)
    exported |= extract_text_exposition_metrics(INDEXER_RS)
    exported |= extract_text_exposition_metrics(FAUCET_RS)
    exported |= extract_text_exposition_metrics(COMMS_RELAY_SERVER_RS)
    return exported


def extract_promql_metrics(expr: str) -> set[str]:
    """Extract metric names from a PromQL expression, ignoring labels, strings, durations, and keywords."""
    # Remove double- and single-quoted strings.
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", expr)
    # Remove label matchers `{...}`.
    cleaned = re.sub(r"\{[^}]*\}", " ", cleaned)
    # Remove range/subquery durations `[5m]`, `[1h:5m]`.
    cleaned = re.sub(r"\[[^\]]*\]", " ", cleaned)
    # Remove grouping label lists `by (a, b)` / `without (a)` / `on (...)` / `ignoring (...)`.
    cleaned = re.sub(
        r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
        " ",
        cleaned,
    )

    metrics: set[str] = set()
    for token in PROMQL_IDENT_RE.findall(cleaned):
        if token in PROMQL_KEYWORDS:
            continue
        metrics.add(token)
    return metrics


def check_balanced_delimiters(expr: str) -> bool:
    """Verify parentheses, brackets, and braces are balanced in a PromQL expression."""
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    in_quote: str | None = None
    escaped = False
    for ch in expr:
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
        elif ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return in_quote is None and not stack


def validate_grid_pos(pid: object, title: str, grid_pos: object, errors: list[str]) -> None:
    """Validate Grafana panel gridPos coordinates within the 24-column layout."""
    if not isinstance(grid_pos, dict):
        errors.append(f"Panel id={pid} ('{title}') has non-object gridPos")
        return
    for key in ("x", "y", "w", "h"):
        val = grid_pos.get(key)
        if not isinstance(val, int) or isinstance(val, bool):
            errors.append(f"Panel id={pid} ('{title}') gridPos missing integer '{key}'")
            return
    if grid_pos["x"] < 0 or grid_pos["y"] < 0:
        errors.append(f"Panel id={pid} ('{title}') has negative gridPos coordinates")
    if grid_pos["w"] <= 0 or grid_pos["h"] <= 0:
        errors.append(f"Panel id={pid} ('{title}') has non-positive gridPos dimensions")
    if grid_pos["x"] + grid_pos["w"] > 24:
        errors.append(
            f"Panel id={pid} ('{title}') exceeds 24-column Grafana grid (x={grid_pos['x']}, w={grid_pos['w']})"
        )


def validate_dashboard(dashboard_path: Path, exported_metrics: set[str]) -> tuple[int, set[str], list[str]]:
    """Validate Stratum Grafana dashboard JSON structure and `stratum_*` metric references."""
    errors: list[str] = []
    data = json.loads(dashboard_path.read_text(encoding="utf-8"))

    for key in ("title", "uid", "schemaVersion", "panels"):
        if key not in data:
            errors.append(f"Dashboard missing required top-level key: '{key}'")

    panels = data.get("panels", [])
    if not isinstance(panels, list) or not panels:
        errors.append("Dashboard 'panels' must be a non-empty list")
        return 0, set(), errors

    seen_ids: set[int] = set()
    referenced_metrics: set[str] = set()

    for idx, panel in enumerate(panels):
        pid = panel.get("id")
        title = panel.get("title", f"<panel #{idx}>")
        if pid in seen_ids:
            errors.append(f"Duplicate panel id {pid} ('{title}')")
        elif isinstance(pid, int):
            seen_ids.add(pid)
        else:
            errors.append(f"Panel '{title}' missing integer id")

        for field in ("title", "type", "gridPos", "targets"):
            if field not in panel:
                errors.append(f"Panel id={pid} ('{title}') missing required field '{field}'")

        targets = panel.get("targets", [])
        if not targets:
            errors.append(f"Panel id={pid} ('{title}') has no targets")

        for target in targets:
            expr = target.get("expr", "")
            if not expr.strip():
                errors.append(f"Panel id={pid} ('{title}') has empty target expr")
                continue
            if not check_balanced_delimiters(expr):
                errors.append(f"Panel id={pid} ('{title}') has unbalanced PromQL expr: {expr}")
            for metric in METRIC_RE.findall(expr):
                referenced_metrics.add(metric)
                if metric not in exported_metrics:
                    errors.append(
                        f"Dashboard panel id={pid} ('{title}') references unknown metric '{metric}'"
                    )

    return len(panels), referenced_metrics, errors


def validate_ecosystem_dashboard(
    dashboard_path: Path,
    all_exported_metrics: set[str],
) -> tuple[int, set[str], list[str]]:
    """Validate unified Kovanica Ecosystem Overview Grafana dashboard against all codebase metrics."""
    errors: list[str] = []
    try:
        data = json.loads(dashboard_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return 0, set(), [f"Ecosystem dashboard invalid JSON: {exc}"]

    for key in ("title", "uid", "schemaVersion", "panels", "templating"):
        if key not in data:
            errors.append(f"Ecosystem dashboard missing required top-level key: '{key}'")

    templating_list = data.get("templating", {}).get("list", [])
    if not any(
        isinstance(var, dict) and var.get("type") == "datasource" and var.get("query") == "prometheus"
        for var in templating_list
    ):
        errors.append("Ecosystem dashboard missing Prometheus datasource templating variable")

    panels = data.get("panels", [])
    if not isinstance(panels, list) or not panels:
        errors.append("Ecosystem dashboard 'panels' must be a non-empty list")
        return 0, set(), errors

    if len(panels) < MIN_ECOSYSTEM_PANELS:
        errors.append(
            f"Ecosystem dashboard has {len(panels)} panels; minimum required is {MIN_ECOSYSTEM_PANELS}"
        )

    seen_ids: set[int] = set()
    referenced_metrics: set[str] = set()

    for idx, panel in enumerate(panels):
        pid = panel.get("id")
        title = panel.get("title", f"<panel #{idx}>")
        if pid in seen_ids:
            errors.append(f"Ecosystem dashboard duplicate panel id {pid} ('{title}')")
        elif isinstance(pid, int) and not isinstance(pid, bool):
            seen_ids.add(pid)
        else:
            errors.append(f"Ecosystem dashboard panel '{title}' missing integer id")

        for field in ("title", "type", "gridPos", "targets"):
            if field not in panel:
                errors.append(f"Ecosystem dashboard panel id={pid} ('{title}') missing required field '{field}'")

        if "gridPos" in panel:
            validate_grid_pos(pid, title, panel["gridPos"], errors)

        targets = panel.get("targets", [])
        if not isinstance(targets, list) or not targets:
            errors.append(f"Ecosystem dashboard panel id={pid} ('{title}') has no targets")
            continue

        for target in targets:
            expr = target.get("expr", "")
            if not isinstance(expr, str) or not expr.strip():
                errors.append(f"Ecosystem dashboard panel id={pid} ('{title}') has empty target expr")
                continue
            if not check_balanced_delimiters(expr):
                errors.append(f"Ecosystem dashboard panel id={pid} ('{title}') has unbalanced PromQL expr: {expr}")
            expr_metrics = extract_promql_metrics(expr)
            if not expr_metrics:
                errors.append(
                    f"Ecosystem dashboard panel id={pid} ('{title}') target expr references no metrics: {expr}"
                )
            for metric in sorted(expr_metrics):
                referenced_metrics.add(metric)
                if metric not in all_exported_metrics:
                    errors.append(
                        f"Ecosystem dashboard panel id={pid} ('{title}') references unknown metric '{metric}'"
                    )

    for required_metric in REQUIRED_ECOSYSTEM_METRICS:
        if required_metric not in referenced_metrics:
            errors.append(
                f"Ecosystem dashboard missing required telemetry metric '{required_metric}'"
            )

    return len(panels), referenced_metrics, errors


def validate_alerts(alerts_path: Path, exported_metrics: set[str]) -> tuple[list[str], set[str], list[str]]:
    """Validate Prometheus alerting rules YAML (stdlib-only) and metric references."""
    errors: list[str] = []
    raw = alerts_path.read_text(encoding="utf-8")
    lines = raw.splitlines()

    if "\t" in raw:
        errors.append("Alerts YAML contains tab characters (YAML requires spaces)")

    if not any(line.strip() == "groups:" for line in lines):
        errors.append("Alerts YAML missing top-level 'groups:' key")
    if not any(re.match(r"^\s*-\s+name:\s+kovanica_stratum_alerts\s*$", line) for line in lines):
        errors.append("Alerts YAML missing group '- name: kovanica_stratum_alerts'")

    rules: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        alert_match = re.match(r"^\s*-\s+alert:\s+(\S+)\s*$", line)
        if alert_match:
            if current is not None:
                rules.append(current)
            current = {"alert": alert_match.group(1), "line": str(lineno)}
            continue

        if current is None:
            continue

        for field in ("expr", "for", "severity", "summary", "description"):
            field_match = re.match(rf"^\s*{field}:\s*(.+?)\s*$", line)
            if field_match:
                current[field] = field_match.group(1)

    if current is not None:
        rules.append(current)

    if not rules:
        errors.append("Alerts YAML contains no alert rules")
        return [], set(), errors

    alert_names: list[str] = []
    referenced_metrics: set[str] = set()
    seen_alerts: set[str] = set()

    for rule in rules:
        name = rule["alert"]
        if name in seen_alerts:
            errors.append(f"Duplicate alert rule name: '{name}'")
        seen_alerts.add(name)
        alert_names.append(name)

        for req in ("expr", "for", "severity", "summary", "description"):
            if not rule.get(req):
                errors.append(f"Alert '{name}' (line {rule['line']}) missing required field '{req}'")

        expr = rule.get("expr", "")
        if expr and not check_balanced_delimiters(expr):
            errors.append(f"Alert '{name}' has unbalanced PromQL expr: {expr}")

        for metric in METRIC_RE.findall(expr):
            referenced_metrics.add(metric)
            if metric not in exported_metrics:
                errors.append(f"Alert '{name}' references unknown metric '{metric}'")

    return alert_names, referenced_metrics, errors


def validate_ecosystem_alerts(
    alerts_path: Path,
    all_exported_metrics: set[str],
) -> tuple[list[str], set[str], list[str]]:
    """Validate ecosystem Prometheus alerting rules YAML (stdlib-only) against all codebase metrics."""
    errors: list[str] = []
    raw = alerts_path.read_text(encoding="utf-8")
    lines = raw.splitlines()

    if "\t" in raw:
        errors.append("Ecosystem alerts YAML contains tab characters (YAML requires spaces)")

    if not any(line.strip() == "groups:" for line in lines):
        errors.append("Ecosystem alerts YAML missing top-level 'groups:' key")

    group_names: list[str] = []
    rules: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    current_section: str | None = None
    section_indent = -1

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        group_match = re.match(r"^\s*-\s+name:\s+(\S+)\s*$", line)
        if group_match:
            group_names.append(group_match.group(1))
            current_section = None
            section_indent = -1
            continue

        alert_match = re.match(r"^\s*-\s+alert:\s+(\S+)\s*$", line)
        if alert_match:
            if current is not None:
                rules.append(current)
            current = {
                "alert": alert_match.group(1),
                "line": str(lineno),
                "labels": {},
                "annotations": {},
            }
            current_section = None
            section_indent = -1
            continue

        if current is None:
            continue

        if current_section is not None and indent <= section_indent:
            current_section = None
            section_indent = -1

        if stripped in ("labels:", "annotations:"):
            current_section = stripped[:-1]
            section_indent = indent
            continue

        if current_section in ("labels", "annotations"):
            kv_match = re.match(r"^\s*([a-zA-Z0-9_]+):\s*(.+?)\s*$", line)
            if kv_match:
                section_map = current[current_section]
                assert isinstance(section_map, dict)
                section_map[kv_match.group(1)] = kv_match.group(2).strip().strip("\"'")
            continue

        for field in ("expr", "for"):
            field_match = re.match(rf"^\s*{field}:\s*(.+?)\s*$", line)
            if field_match:
                current[field] = field_match.group(1)

    if current is not None:
        rules.append(current)

    if not group_names:
        errors.append("Ecosystem alerts YAML contains no rule groups ('- name: ...')")

    if not rules:
        errors.append("Ecosystem alerts YAML contains no alert rules")
        return [], set(), errors

    if len(rules) < MIN_ECOSYSTEM_ALERT_RULES:
        errors.append(
            f"Ecosystem alerts YAML has {len(rules)} rules; minimum required is {MIN_ECOSYSTEM_ALERT_RULES}"
        )

    alert_names: list[str] = []
    referenced_metrics: set[str] = set()
    seen_alerts: set[str] = set()

    for rule in rules:
        name = str(rule["alert"])
        lineno_str = str(rule["line"])
        if name in seen_alerts:
            errors.append(f"Ecosystem alerts duplicate rule name: '{name}'")
        seen_alerts.add(name)
        alert_names.append(name)

        expr = str(rule.get("expr", "")).strip()
        if not expr:
            errors.append(f"Ecosystem alert '{name}' (line {lineno_str}) missing required field 'expr'")
        else:
            if not check_balanced_delimiters(expr):
                errors.append(f"Ecosystem alert '{name}' has unbalanced PromQL expr: {expr}")
            expr_metrics = extract_promql_metrics(expr)
            if not expr_metrics:
                errors.append(f"Ecosystem alert '{name}' expr references no metrics: {expr}")
            for metric in sorted(expr_metrics):
                referenced_metrics.add(metric)
                if metric not in all_exported_metrics:
                    errors.append(f"Ecosystem alert '{name}' references unknown metric '{metric}'")

        for_dur = str(rule.get("for", "")).strip().strip("\"'")
        if not for_dur:
            errors.append(f"Ecosystem alert '{name}' (line {lineno_str}) missing required field 'for'")
        elif not PROM_DURATION_RE.match(for_dur):
            errors.append(f"Ecosystem alert '{name}' has invalid 'for' duration: '{for_dur}'")

        labels = rule["labels"]
        assert isinstance(labels, dict)
        severity = str(labels.get("severity", "")).strip()
        if not severity:
            errors.append(f"Ecosystem alert '{name}' (line {lineno_str}) missing required field 'labels.severity'")
        elif severity not in VALID_ALERT_SEVERITIES:
            errors.append(
                f"Ecosystem alert '{name}' has invalid labels.severity '{severity}' "
                f"(expected one of {sorted(VALID_ALERT_SEVERITIES)})"
            )

        annotations = rule["annotations"]
        assert isinstance(annotations, dict)
        if not str(annotations.get("summary", "")).strip():
            errors.append(f"Ecosystem alert '{name}' (line {lineno_str}) missing required field 'annotations.summary'")
        if not str(annotations.get("description", "")).strip():
            errors.append(
                f"Ecosystem alert '{name}' (line {lineno_str}) missing required field 'annotations.description'"
            )

    for required_metric in REQUIRED_ECOSYSTEM_ALERT_METRICS:
        if required_metric not in referenced_metrics:
            errors.append(
                f"Ecosystem alerts YAML missing required coverage metric '{required_metric}'"
            )

    return alert_names, referenced_metrics, errors


def main() -> int:
    required_paths = (
        GATEWAY_RS,
        CONSENSUS_METRICS_RS,
        RPC_LIB_RS,
        INDEXER_RS,
        FAUCET_RS,
        COMMS_RELAY_SERVER_RS,
        DASHBOARD_JSON,
        ALERTS_YML,
        ECOSYSTEM_DASHBOARD_JSON,
        ECOSYSTEM_ALERTS_YML,
    )
    for path in required_paths:
        if not path.is_file():
            print(f"ERROR: Required file not found: {path}", file=sys.stderr)
            return 1

    exported_stratum_metrics = extract_exported_metrics(GATEWAY_RS)
    all_codebase_metrics = extract_all_codebase_metrics()

    panel_count, dash_metrics, dash_errors = validate_dashboard(DASHBOARD_JSON, exported_stratum_metrics)
    alert_names, alert_metrics, alert_errors = validate_alerts(ALERTS_YML, exported_stratum_metrics)
    eco_panels, eco_metrics, eco_errors = validate_ecosystem_dashboard(
        ECOSYSTEM_DASHBOARD_JSON,
        all_codebase_metrics,
    )
    eco_alert_names, eco_alert_metrics, eco_alert_errors = validate_ecosystem_alerts(
        ECOSYSTEM_ALERTS_YML,
        all_codebase_metrics,
    )

    all_errors = dash_errors + alert_errors + eco_errors + eco_alert_errors

    print(f"Exported stratum_* metrics in gateway.rs : {len(exported_stratum_metrics)}")
    print(f"Exported metrics across kovanica-l1      : {len(all_codebase_metrics)}")
    print(f"Stratum dashboard panels validated       : {panel_count} ({len(dash_metrics)} unique metrics)")
    print(f"Ecosystem dashboard panels validated     : {eco_panels} ({len(eco_metrics)} unique metrics)")
    print(f"Stratum alert rules validated            : {len(alert_names)} ({len(alert_metrics)} unique metrics)")
    print(f"Stratum alert rules                      : {', '.join(alert_names)}")
    print(f"Ecosystem alert rules validated          : {len(eco_alert_names)} ({len(eco_alert_metrics)} unique metrics)")
    print(f"Ecosystem alert rules                    : {', '.join(eco_alert_names)}")

    if all_errors:
        print("\nVALIDATION FAILED:", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        "\nVALIDATION PASSED: Stratum dashboard, Ecosystem Overview dashboard, Stratum alerts YAML, "
        "Ecosystem alerts YAML, and all referenced metrics verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
