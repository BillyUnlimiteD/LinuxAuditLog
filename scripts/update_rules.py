#!/usr/bin/env python3
"""
update_rules.py — Download and import new community Sigma rules into the local dictionary.

What it does:
  1. Fetches the file tree of linux/ and web/ rules from the SigmaHQ GitHub repository.
  2. Downloads each rule YAML file.
  3. Converts the Sigma format to the local rule format.
  4. Saves new rules under rules/ (never overwrites existing ones unless --force).
  5. Prints a summary of what was added, skipped, or failed.

Usage:
  python scripts/update_rules.py
  python scripts/update_rules.py --dry-run
  python scripts/update_rules.py --force
  python scripts/update_rules.py --token YOUR_GITHUB_TOKEN  (avoids rate limiting)

GitHub API rate limit:
  Unauthenticated: 60 requests/hour
  Authenticated:   5000 requests/hour
  For large updates, pass --token or set GITHUB_TOKEN env var.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests
import yaml

# Add parent to path so we can import config
sys.path.insert(0, str(Path(__file__).parent.parent))
import config

SIGMA_REPO = "SigmaHQ/sigma"
SIGMA_BRANCH = "master"
RAW_BASE = f"https://raw.githubusercontent.com/{SIGMA_REPO}/{SIGMA_BRANCH}"
API_BASE = "https://api.github.com"

# Sigma paths to scan for relevant rules
SIGMA_PATHS = [
    "rules/linux/auditd",
    "rules/linux/builtin",
    "rules/linux/file_event",
    "rules/linux/network_connection",
    "rules/linux/process_creation",
    "rules/linux/other",
    "rules/web",
]

# Map Sigma path prefix -> local rules/ subdirectory
PATH_MAP = {
    "rules/linux/auditd": "linux/audit",
    "rules/linux/builtin": "linux/builtin",
    "rules/linux/file_event": "linux/other",
    "rules/linux/network_connection": "linux/network",
    "rules/linux/network": "linux/network",
    "rules/linux/process_creation": "linux/process",
    "rules/linux/other": "linux/other",
    "rules/web": "web",
}

# Sigma level -> local severity
LEVEL_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}

# Sigma tactic tags -> mitre_tactic
TACTIC_MAP = {
    "attack.initial_access": "initial_access",
    "attack.execution": "execution",
    "attack.persistence": "persistence",
    "attack.privilege_escalation": "privilege_escalation",
    "attack.defense_evasion": "defense_evasion",
    "attack.credential_access": "credential_access",
    "attack.discovery": "discovery",
    "attack.lateral_movement": "lateral_movement",
    "attack.collection": "collection",
    "attack.command_and_control": "command_and_control",
    "attack.exfiltration": "exfiltration",
    "attack.impact": "impact",
    "attack.reconnaissance": "reconnaissance",
    "attack.resource_development": "resource_development",
}


class RuleConverter:
    """Convert a Sigma YAML rule to the local format."""

    def convert(self, sigma_rule: dict, source_path: str) -> dict | None:
        if not isinstance(sigma_rule, dict):
            return None

        title = sigma_rule.get("title", "")
        rule_id = sigma_rule.get("id", "")
        if not title or not rule_id:
            return None

        # Generate local ID from source path
        local_id = self._make_local_id(source_path, title)

        # Extract MITRE info from tags
        tags = sigma_rule.get("tags", []) or []
        mitre_technique = ""
        mitre_tactic = ""
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t") and not mitre_technique:
                # e.g. attack.t1110.001 -> T1110.001
                mitre_technique = tag[7:].upper().replace(".", ".")
            for sigma_tactic, local_tactic in TACTIC_MAP.items():
                if tag_lower == sigma_tactic:
                    mitre_tactic = local_tactic

        # Try to extract simple regex patterns from detection
        patterns = self._extract_patterns(sigma_rule.get("detection", {}))

        # Build local rule
        local_rule = {
            "id": local_id,
            "title": title[:128],
            "category": self._infer_category(source_path),
            "subcategory": self._infer_subcategory(sigma_rule),
            "mitre_technique": mitre_technique,
            "mitre_tactic": mitre_tactic,
            "severity": LEVEL_MAP.get(sigma_rule.get("level", "medium"), "medium"),
            "confidence": "low",  # conservative for auto-imported rules
            "enabled": True,
            "description": (sigma_rule.get("description", "") or "")[:512],
            "service": self._infer_service(sigma_rule),
            "detection": {
                "type": "pattern",
                "patterns": patterns,
            },
            "false_positives": sigma_rule.get("falsepositives", []) or [],
            "recommendation": (
                f"Review the activity matching this rule. "
                f"Original Sigma rule: {source_path}. "
                f"References: {', '.join(sigma_rule.get('references', []) or [])}"
            )[:1024],
            "references": sigma_rule.get("references", []) or [],
            "tags": [t for t in tags if t.startswith("attack.")],
            "_sigma_source": source_path,
            "_sigma_status": sigma_rule.get("status", ""),
            "_sigma_author": sigma_rule.get("author", ""),
            "_sigma_date": sigma_rule.get("date", ""),
        }

        # Only return rules with at least one usable pattern
        if not local_rule["detection"]["patterns"]:
            local_rule["detection"]["patterns"] = [
                {"regex": "PLACEHOLDER — review and add patterns manually",
                 "_note": f"Auto-imported from Sigma: {source_path}"}
            ]
            local_rule["enabled"] = False  # Disable until patterns are set

        return local_rule

    def _make_local_id(self, source_path: str, title: str) -> str:
        """Generate a short readable ID from the source path and title."""
        parts = source_path.split("/")
        area = parts[1].upper()[:3] if len(parts) > 1 else "UNK"
        slug = "".join(c.upper() if c.isalpha() else "_" for c in title[:20]).rstrip("_")
        return f"SIGMA-{area}-{slug}"

    def _infer_category(self, source_path: str) -> str:
        if "linux" in source_path:
            if "auth" in source_path or "builtin" in source_path:
                return "authentication"
            if "process" in source_path:
                return "process"
            if "network" in source_path:
                return "network"
            if "audit" in source_path:
                return "audit"
        if "web" in source_path:
            return "web"
        return "generic"

    def _infer_subcategory(self, rule: dict) -> str:
        title = rule.get("title", "").lower()
        for kw in ("brute", "password"):
            if kw in title:
                return "brute_force"
        for kw in ("privesc", "privilege", "escalat"):
            if kw in title:
                return "privilege_escalation"
        for kw in ("execut", "command", "shell"):
            if kw in title:
                return "execution"
        return "detection"

    def _infer_service(self, rule: dict) -> str:
        logsource = rule.get("logsource", {}) or {}
        service = logsource.get("service", "")
        if service:
            return str(service)[:64]
        product = logsource.get("product", "")
        if product:
            return str(product)[:64]
        return "*"

    def _extract_patterns(self, detection: dict) -> list[dict]:
        """Best-effort extraction of string patterns from Sigma detection."""
        if not isinstance(detection, dict):
            return []

        patterns = []
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            if isinstance(value, dict):
                for field, conditions in value.items():
                    if field in ("condition", "timeframe"):
                        continue
                    if isinstance(conditions, list):
                        for cond in conditions:
                            if isinstance(cond, str) and len(cond) > 3:
                                escaped = cond.replace("*", ".*")
                                patterns.append({"regex": re.quote_maybe(escaped)})
                    elif isinstance(conditions, str) and len(conditions) > 3:
                        escaped = conditions.replace("*", ".*")
                        patterns.append({"regex": re.quote_maybe(escaped)})
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and len(item) > 3:
                        escaped = item.replace("*", ".*")
                        patterns.append({"regex": re.quote_maybe(escaped)})

        return patterns[:10]  # Limit to 10 patterns per rule


class re:
    """Minimal re helper — not the re module."""
    @staticmethod
    def quote_maybe(s: str) -> str:
        """Escape special regex characters except .* (already wildcard)."""
        import re as _re
        # Split on .* wildcards, escape each part, rejoin
        parts = s.split(".*")
        return ".*".join(_re.escape(p) for p in parts)


# ------------------------------------------------------------------
# GitHub API helpers
# ------------------------------------------------------------------

def get_tree(token: str | None = None) -> list[dict]:
    """Fetch the full file tree from the SigmaHQ repo."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"{API_BASE}/repos/{SIGMA_REPO}/git/trees/{SIGMA_BRANCH}?recursive=1"
    resp = requests.get(url, headers=headers, timeout=30)

    if resp.status_code == 403:
        print("[WARN] GitHub API rate limit reached. Use --token to authenticate.")
        sys.exit(1)
    resp.raise_for_status()
    return resp.json().get("tree", [])


def filter_relevant(tree: list[dict]) -> list[str]:
    """Filter tree for YAML/YML files under our target paths."""
    relevant = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        if not (path.endswith(".yaml") or path.endswith(".yml")):
            continue
        for sigma_path in SIGMA_PATHS:
            if path.startswith(sigma_path + "/"):
                relevant.append(path)
                break
    return relevant


def download_rule(path: str, token: str | None = None) -> dict | None:
    """Download and parse a single Sigma rule YAML."""
    url = f"{RAW_BASE}/{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return yaml.safe_load(resp.text)
    except Exception as exc:
        return None


def local_path_for(sigma_path: str) -> Path:
    """Compute the local rules/ path for a sigma path."""
    for prefix, local_subdir in PATH_MAP.items():
        if sigma_path.startswith(prefix + "/"):
            filename = Path(sigma_path).name
            return config.RULES_DIR / local_subdir / filename
    # Fallback
    filename = Path(sigma_path).name
    return config.RULES_DIR / "imported" / filename


def save_rule(rule: dict, dest: Path, force: bool = False) -> str:
    """Save converted rule to YAML. Returns 'added', 'skipped', or 'error'."""
    if dest.exists() and not force:
        return "skipped"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            yaml.dump(rule, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)
        return "added"
    except Exception as exc:
        return f"error: {exc}"


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Update local rules dictionary from SigmaHQ")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without writing files")
    parser.add_argument("--force", action="store_true", help="Overwrite existing rules")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""), help="GitHub personal access token")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of rules to download (0 = all)")
    args = parser.parse_args()

    token = args.token or None
    converter = RuleConverter()

    print(f"[*] Fetching rule tree from {SIGMA_REPO}...")
    tree = get_tree(token)
    relevant = filter_relevant(tree)
    print(f"[*] Found {len(relevant)} relevant rule files")

    if args.limit > 0:
        relevant = relevant[: args.limit]
        print(f"[*] Limited to {args.limit} rules")

    stats = {"added": 0, "skipped": 0, "disabled": 0, "error": 0, "failed_download": 0}

    for i, sigma_path in enumerate(relevant, 1):
        dest = local_path_for(sigma_path)

        if dest.exists() and not args.force:
            stats["skipped"] += 1
            if i % 20 == 0:
                print(f"  [{i}/{len(relevant)}] {stats}")
            continue

        sigma_rule = download_rule(sigma_path, token)
        if not sigma_rule:
            stats["failed_download"] += 1
            continue

        local_rule = converter.convert(sigma_rule, sigma_path)
        if not local_rule:
            stats["error"] += 1
            continue

        if args.dry_run:
            print(f"  [DRY] Would write: {dest.relative_to(config.RULES_DIR)}")
            stats["added"] += 1
            continue

        result = save_rule(local_rule, dest, force=args.force)
        if result == "added":
            stats["added"] += 1
            if not local_rule.get("enabled", True):
                stats["disabled"] += 1
        elif result == "skipped":
            stats["skipped"] += 1
        else:
            stats["error"] += 1
            print(f"  [ERR] {result} — {sigma_path}")

        # Polite rate limiting for unauthenticated requests
        if not token and i % 30 == 0:
            time.sleep(2)

        if i % 25 == 0:
            print(f"  [{i}/{len(relevant)}] added={stats['added']} skipped={stats['skipped']} errors={stats['error']}")

    print()
    print("=" * 50)
    print("  Update complete")
    print("=" * 50)
    print(f"  Added:           {stats['added']}")
    print(f"  Skipped:         {stats['skipped']} (already exist)")
    print(f"  Disabled:        {stats['disabled']} (need manual pattern review)")
    print(f"  Download fails:  {stats['failed_download']}")
    print(f"  Errors:          {stats['error']}")
    print()
    print(f"  Rules directory: {config.RULES_DIR}")
    if stats["disabled"] > 0:
        print()
        print(f"  [!] {stats['disabled']} rules were saved as enabled=false.")
        print("      Review rules with 'PLACEHOLDER' patterns and add regexes manually.")


if __name__ == "__main__":
    main()
