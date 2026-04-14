"""
IOCEngine — Stage B, step 2.

Evaluates all loaded YAML rules against normalized log entries.
Three detection types:
  - pattern   : regex match per log line, each hit is a finding event
  - threshold : N pattern matches from the same field within a time window
  - sequence  : two ordered patterns within a time window

Rules are YAML files under rules/. They are loaded once at startup.
Remote log content is never executed or eval'd.
"""
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

import config


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class RuleMatch:
    rule_id: str
    timestamp: Optional[str]
    ts_epoch: float
    service: str
    hostname: str
    message: str
    source_file: str
    captured: dict


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    subcategory: str
    severity: str           # critical / high / medium / low / info
    confidence: str         # high / medium / low
    status: str             # Confirmado / Altamente probable / Sospechoso / Sin evidencia suficiente
    mitre_technique: str
    mitre_tactic: str
    description: str
    service: str
    matches: list
    match_count: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    affected_entities: dict  # {src_ip: {count, first, last}, user: {...}, ...}
    recommendation: str
    false_positives: list
    references: list
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "subcategory": self.subcategory,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "description": self.description,
            "service": self.service,
            "match_count": self.match_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "affected_entities": self.affected_entities,
            "recommendation": self.recommendation,
            "false_positives": self.false_positives,
            "references": self.references,
            "sample_matches": [
                {
                    "timestamp": m.timestamp,
                    "service": m.service,
                    "hostname": m.hostname,
                    "message": m.message[:512],
                    "captured": m.captured,
                }
                for m in self.matches[:5]  # Top 5 samples only
            ],
        }


# ------------------------------------------------------------------
# Engine
# ------------------------------------------------------------------

class IOCEngine:
    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = rules_dir
        self._rules: list[dict] = []
        self._load_all_rules()

    def evaluate(self, entries: list[dict]) -> list[Finding]:
        """Evaluate all rules against *entries*. Returns list of Finding."""
        service_idx: dict[str, list] = defaultdict(list)
        for e in entries:
            service_idx[e.get("service", "")].append(e)

        findings = []
        for rule in self._rules:
            if not rule.get("enabled", True):
                continue
            service_filter = rule.get("_service_filter", "*")
            if service_filter != "*" and not any(service_filter in svc for svc in service_idx):
                continue
            finding = self._evaluate_rule(rule, entries, service_idx)
            if finding:
                findings.append(finding)

        # Sort by severity
        _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: _severity_order.get(f.severity, 99))
        return findings

    def _scoped_entries(self, rule: dict, all_entries: list, service_idx: dict) -> list:
        """Return only the entries relevant to this rule's service filter."""
        svc_filter = rule.get("_service_filter", rule.get("service", "*") or "*")
        if svc_filter == "*":
            return all_entries
        result: list = []
        for svc, svc_entries in service_idx.items():
            if svc_filter in svc:
                result.extend(svc_entries)
        return result

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_all_rules(self) -> None:
        if not self.rules_dir.exists():
            return
        for yaml_path in sorted(self.rules_dir.rglob("*.yaml")):
            try:
                with open(yaml_path, "r", encoding="utf-8") as fh:
                    rule = yaml.safe_load(fh)
                if isinstance(rule, dict) and rule.get("id"):
                    rule["_compiled"] = _compile_rule_patterns(rule)
                    rule["_service_filter"] = str(rule.get("service", "*") or "*").lower().strip()
                    self._rules.append(rule)
            except Exception:
                pass  # Malformed rule — skip silently

    # ------------------------------------------------------------------
    # Rule evaluation dispatcher
    # ------------------------------------------------------------------

    def _evaluate_rule(self, rule: dict, entries: list[dict], service_idx: dict) -> Optional[Finding]:
        det = rule.get("detection", {})
        det_type = det.get("type", "pattern")
        scoped = self._scoped_entries(rule, entries, service_idx)
        if not scoped:
            return None

        if det_type == "pattern":
            return self._eval_pattern(rule, scoped)
        if det_type == "threshold":
            return self._eval_threshold(rule, scoped)
        if det_type == "sequence":
            return self._eval_sequence(rule, scoped)
        return None

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------

    def _eval_pattern(self, rule: dict, entries: list[dict]) -> Optional[Finding]:
        compiled_info = rule.get("_compiled", {})
        compiled: list[re.Pattern] = compiled_info.get("patterns", [])
        anchors: list[str] = compiled_info.get("anchors", [])
        if not compiled:
            return None

        # entries are already service-scoped by caller (_scoped_entries)
        matches: list[RuleMatch] = []

        for entry in entries:
            msg = entry.get("message", "")
            # Anchor pre-filter: if no pattern's required literal is present,
            # no pattern can match — skip without invoking the regex engine.
            # Anchors are lowercase; compare against msg.lower() (C-speed).
            if anchors:
                msg_lower = msg.lower()
                if not any(a in msg_lower for a in anchors):
                    continue
            for pattern in compiled:
                m = pattern.search(msg)
                if m:
                    captured = m.groupdict()
                    # Also merge pre-extracted fields from normalizer
                    captured.update({k: v for k, v in entry.get("extracted", {}).items() if v})
                    matches.append(
                        RuleMatch(
                            rule_id=rule["id"],
                            timestamp=entry.get("timestamp"),
                            ts_epoch=entry.get("ts_epoch", 0),
                            service=entry.get("service", "unknown"),
                            hostname=entry.get("hostname", "unknown"),
                            message=msg[:1024],
                            source_file=entry.get("source_file", ""),
                            captured=captured,
                        )
                    )
                    break  # one match per entry per rule

        if not matches:
            return None

        return self._build_finding(rule, matches)

    # ------------------------------------------------------------------
    # Threshold detection
    # ------------------------------------------------------------------

    def _eval_threshold(self, rule: dict, entries: list[dict]) -> Optional[Finding]:
        compiled_info = rule.get("_compiled", {})
        compiled: list[re.Pattern] = compiled_info.get("patterns", [])
        if not compiled:
            return None

        agg = rule.get("detection", {}).get("aggregation", {})
        group_field = agg.get("field", "src_ip")
        threshold = agg.get("count", config.DEFAULT_BRUTE_FORCE_THRESHOLD)
        window_sec = agg.get("window_seconds", config.DEFAULT_BRUTE_FORCE_WINDOW_SEC)

        anchors: list[str] = compiled_info.get("anchors", [])

        # entries are already service-scoped; collect all pattern matches
        all_matches: list[RuleMatch] = []
        for entry in entries:
            msg = entry.get("message", "")
            if anchors:
                msg_lower = msg.lower()
                if not any(a in msg_lower for a in anchors):
                    continue
            for pattern in compiled:
                m = pattern.search(msg)
                if m:
                    captured = m.groupdict()
                    captured.update({k: v for k, v in entry.get("extracted", {}).items() if v})
                    all_matches.append(
                        RuleMatch(
                            rule_id=rule["id"],
                            timestamp=entry.get("timestamp"),
                            ts_epoch=entry.get("ts_epoch", 0),
                            service=entry.get("service", "unknown"),
                            hostname=entry.get("hostname", "unknown"),
                            message=entry.get("message", "")[:1024],
                            source_file=entry.get("source_file", ""),
                            captured=captured,
                        )
                    )
                    break

        if not all_matches:
            return None

        # Group by field value
        groups: dict[str, list[RuleMatch]] = defaultdict(list)
        for match in all_matches:
            key = match.captured.get(group_field, "unknown")
            groups[key].append(match)

        # Check if any group fires
        fired_matches: list[RuleMatch] = []
        for key, group_ms in groups.items():
            if len(group_ms) < threshold:
                continue
            # Check time window
            sorted_ms = sorted(group_ms, key=lambda x: x.ts_epoch)
            for i in range(len(sorted_ms) - threshold + 1):
                window = sorted_ms[i: i + threshold]
                if window[-1].ts_epoch - window[0].ts_epoch <= window_sec:
                    fired_matches.extend(group_ms)
                    break

        if not fired_matches:
            return None

        return self._build_finding(rule, fired_matches)

    # ------------------------------------------------------------------
    # Sequence detection
    # ------------------------------------------------------------------

    def _eval_sequence(self, rule: dict, entries: list[dict]) -> Optional[Finding]:
        det = rule.get("detection", {})
        steps = det.get("steps", [])
        within_sec = det.get("within_seconds", 300)

        if len(steps) < 2:
            return None

        compiled_steps = rule.get("_compiled", {}).get("steps", [])
        if len(compiled_steps) < 2:
            return None

        step1_re, step2_re = compiled_steps[0], compiled_steps[1]

        # entries are already service-scoped
        step1_matches: list[RuleMatch] = []
        step2_matches: list[RuleMatch] = []

        for entry in entries:
            msg = entry.get("message", "")
            m1 = step1_re.search(msg)
            if m1:
                step1_matches.append(
                    RuleMatch(
                        rule_id=rule["id"],
                        timestamp=entry.get("timestamp"),
                        ts_epoch=entry.get("ts_epoch", 0),
                        service=entry.get("service", "unknown"),
                        hostname=entry.get("hostname", "unknown"),
                        message=msg[:1024],
                        source_file=entry.get("source_file", ""),
                        captured=m1.groupdict(),
                    )
                )
            m2 = step2_re.search(msg)
            if m2:
                step2_matches.append(
                    RuleMatch(
                        rule_id=rule["id"],
                        timestamp=entry.get("timestamp"),
                        ts_epoch=entry.get("ts_epoch", 0),
                        service=entry.get("service", "unknown"),
                        hostname=entry.get("hostname", "unknown"),
                        message=msg[:1024],
                        source_file=entry.get("source_file", ""),
                        captured=m2.groupdict(),
                    )
                )

        if not step1_matches or not step2_matches:
            return None

        # Check if any step1 is followed by step2 within window
        fired: list[RuleMatch] = []
        for s1 in step1_matches:
            for s2 in step2_matches:
                if s2.ts_epoch >= s1.ts_epoch and (s2.ts_epoch - s1.ts_epoch) <= within_sec:
                    fired.extend([s1, s2])

        if not fired:
            return None

        return self._build_finding(rule, fired)

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    def _build_finding(self, rule: dict, matches: list[RuleMatch]) -> Finding:
        sorted_m = sorted(matches, key=lambda x: x.ts_epoch)
        affected = _extract_affected_entities(matches)
        status = _determine_status(rule.get("confidence", "medium"), len(matches))

        return Finding(
            rule_id=rule["id"],
            title=rule.get("title", "Unknown"),
            category=rule.get("category", "unknown"),
            subcategory=rule.get("subcategory", ""),
            severity=rule.get("severity", "medium"),
            confidence=rule.get("confidence", "medium"),
            status=status,
            mitre_technique=rule.get("mitre_technique", ""),
            mitre_tactic=rule.get("mitre_tactic", ""),
            description=rule.get("description", ""),
            service=rule.get("service", "*"),
            matches=matches,
            match_count=len(matches),
            first_seen=sorted_m[0].timestamp if sorted_m else None,
            last_seen=sorted_m[-1].timestamp if sorted_m else None,
            affected_entities=affected,
            recommendation=rule.get("recommendation", ""),
            false_positives=rule.get("false_positives", []),
            references=rule.get("references", []),
        )


# ------------------------------------------------------------------
# Module helpers
# ------------------------------------------------------------------

def _compile_rule_patterns(rule: dict) -> dict:
    """Pre-compile all regex patterns in a rule. Returns compiled dict.

    Also extracts a lightweight 'anchor' keyword per pattern — a plain
    literal substring that MUST appear for any match to be possible.
    Used as a C-speed str.__contains__ pre-filter before invoking the
    regex engine, eliminating ~99% of entries without backtracking cost.
    """
    result: dict = {"patterns": [], "steps": [], "combined": None, "anchors": []}
    det = rule.get("detection", {})
    det_type = det.get("type", "pattern")

    if det_type in ("pattern", "threshold"):
        for pat in det.get("patterns", []):
            regex_str = pat.get("regex", "")
            if regex_str:
                try:
                    result["patterns"].append(re.compile(regex_str, re.IGNORECASE))
                except re.error:
                    pass
                anchor = _extract_anchor(regex_str)
                if anchor:
                    result["anchors"].append(anchor)

    elif det_type == "sequence":
        for step in det.get("steps", []):
            regex_str = step.get("regex", "")
            if regex_str:
                try:
                    result["steps"].append(re.compile(regex_str, re.IGNORECASE))
                except re.error:
                    pass

    return result


def _extract_anchor(regex_str: str) -> Optional[str]:
    """Extract the longest plain-literal substring from a regex pattern.

    The returned string is a REQUIRED lowercase substring — if it is absent
    from msg.lower() the pattern cannot match. Used as a C-speed pre-filter.
    Returns None when no safe literal of ≥4 chars can be identified.
    """
    s = regex_str
    # 1. Remove named capture groups: (?P<name>  and  (?P=name)
    s = re.sub(r'\(\?P[<=][^)>]+\)?', '', s)
    # 2. Remove non-capturing / lookahead / lookbehind group openers
    s = re.sub(r'\(\?[!:=<#]', '(', s)
    # 3. Replace escape sequences that don't produce useful literals
    for esc in (r'\S', r'\s', r'\d', r'\w', r'\b', r'\A', r'\Z',
                r'\n', r'\r', r'\t'):
        s = s.replace(esc, ' ')
    # 4. Replace escaped metacharacters with a space (they're single chars)
    s = re.sub(r'\\[^a-zA-Z0-9]', ' ', s)
    # 5. Find runs of purely alphabetic/digit/hyphen chars (no metacharacters)
    #    Require at least 4 chars and no trailing regex metacharacter confusion
    literals = re.findall(r'[a-zA-Z][a-zA-Z0-9_-]{3,}', s)
    if not literals:
        return None
    # 6. Filter out known regex syntax words that slip through
    _REGEX_KEYWORDS = {'true', 'false', 'none', 'null', 'implicit', 'success',
                       'from_server', 'from_client', 'accepted', 'rejected'}
    candidates = [l for l in literals if l.lower() not in _REGEX_KEYWORDS and len(l) >= 4]
    if not candidates:
        return None
    # 7. Prefer longest (most selective)
    best = max(candidates, key=len)
    return best.lower()


def _extract_affected_entities(matches: list[RuleMatch]) -> dict:
    """Aggregate IP, user, port counts from captured groups."""
    entities: dict = {}
    for field in ("src_ip", "user", "username", "port", "uri"):
        counts: dict = defaultdict(int)
        for m in matches:
            val = m.captured.get(field)
            if val and val != "-":
                counts[val] += 1
        if counts:
            entities[field] = dict(sorted(counts.items(), key=lambda x: -x[1])[:20])
    return entities


def _determine_status(confidence: str, count: int) -> str:
    if confidence == "high" and count >= 3:
        return "Confirmado"
    if confidence in ("high", "medium") and count >= 1:
        return "Altamente probable"
    if confidence == "medium":
        return "Sospechoso"
    return "Sin evidencia suficiente"
