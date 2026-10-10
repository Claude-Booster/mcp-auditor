#!/usr/bin/env python3
"""mcp-auditor - scan MCP server metadata for prompt-injection / "tool poisoning".

An MCP server advertises tools / resources / prompts, each carrying a name, a
description and (for tools) an inputSchema/outputSchema whose fields also carry
text. A client loads that *metadata* into the model's context at session init
(before anything is ever called). A malicious server can therefore hide orders
for the model in that text. Reviewing the server's *code* never catches this
because the payload lives in the metadata.

This tool ONLY pattern-matches and reports on that text. It NEVER follows,
executes, or evaluates any instruction found inside it. In --stdio / --config
modes it does spawn / contact the server being audited (that is the point), but
it treats everything the server returns as inert data, with a hard timeout, and
never feeds server output into a shell or eval.

Checks:
  1. Full-schema scan (inputSchema/outputSchema: property names, titles, nested
     descriptions, enum values) - not just the top-level description.
  2. Audits resources, resource templates and prompts too (not only tools).
  3. Rug-pull / drift detection vs a trust-on-first-use baseline.
  4. Cross-server shadowing / tool-name collisions.
  5. Server provenance / supply-chain (unpinned npx/uvx/pipx, curl|sh, plaintext
     URL, static creds - KEY NAMES only, never values).
  6. Dangerous-capability notes (exec / file-write / network).

Stdlib only. Windows-safe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.request
import urllib.error
from pathlib import Path

# --------------------------------------------------------------------------- #
# Detection heuristics
# --------------------------------------------------------------------------- #

# HIGH - model-directed instructions / prompt injection.
INSTRUCTION_PATTERNS = [
    (r"ignore\s+(?:the\s+)?(?:previous|above|prior)",
     "Tells the model to ignore earlier/previous instructions."),
    (r"disregard",
     "Tells the model to disregard something (often prior instructions)."),
    (r"before\s+(?:using|calling|running)\s+(?:any|each|every|other|the)\s+tool",
     "Injects a step the model should run before every tool call."),
    (r"do\s+not\s+(?:tell|mention|inform|reveal)",
     "Tries to make the model hide something from the user."),
    (r"system\s+prompt",
     "References the hidden system prompt."),
    (r"you\s+must",
     "Issues a direct command to the model."),
    (r"instead,?\s+(?:call|use|read)",
     "Redirects the model to a different action."),
    (r"as\s+an\s+ai",
     "Addresses the model directly as an AI."),
    (r"always\s+(?:read|send|include|attach|call|run)",
     "Commands the model to always perform an action."),
]

# HIGH - credential / file / exfiltration references.
CREDENTIAL_PATTERNS = [
    (r"~/\.ssh", "Points at SSH private-key directory (~/.ssh)."),
    (r"id_rsa", "Names an SSH private key file (id_rsa)."),
    (r"\.env\b", "References a .env secrets file."),
    (r"password", "Mentions a password."),
    (r"secret", "Mentions a secret."),
    (r"api[_ -]?key", "Mentions an API key."),
    (r"token", "Mentions a token (possible credential)."),
    (r"AWS_", "References an AWS_ environment variable (cloud credential)."),
    (r"exfiltrat", "Mentions exfiltration (data theft)."),
    (r"base64", "Mentions base64 (often used to smuggle/obfuscate data)."),
    (r"[A-Za-z]:\\[^\s\"']+", "Contains an absolute Windows filesystem path."),
    (r"(?:^|[\s\"'(`])/(?:etc|usr|var|home|root|bin|sbin|opt|tmp|private|Users|proc|sys)/[^\s\"']*",
     "Contains an absolute filesystem path."),
]

CRED_WHAT = "References sensitive credentials / files that the model could be told to read or leak."

# MEDIUM - dangerous capability (informational: shows the server's blast radius).
CAPABILITY_PATTERNS = [
    ("code / command execution",
     r"\b(exec|execute|eval|shell|spawn|subprocess|system|run[_-]?command|runcommand|bash|powershell|cmd)\b"),
    ("file write / delete",
     r"\b(write[_-]?file|writefile|delete|remove|unlink|overwrite|truncate|rmdir|chmod)\b"),
    ("network access",
     r"\b(https?|fetch|download|upload|curl|wget|webhook|network|requesturl|api[_-]?call)\b"),
]

PADDING_LIMIT = 1500
SNIPPET_LEN = 80
SEV_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": 0}


def _is_hidden_char(cp: int, ch: str) -> bool:
    if 0x200B <= cp <= 0x200D or cp == 0xFEFF:            # zero-width
        return True
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:  # bidi controls
        return True
    if cp < 0x20 and ch not in "\t\n\r":                  # C0 controls
        return True
    if 0x7F <= cp <= 0x9F:                                 # DEL + C1 controls
        return True
    return False


def _snippet(text: str, match: "re.Match") -> str:
    start = max(0, match.start() - 20)
    end = min(len(text), match.end() + 40)
    snip = text[start:end].replace("\n", " ").replace("\r", " ").strip()
    if len(snip) > SNIPPET_LEN:
        snip = snip[:SNIPPET_LEN] + "..."
    if start > 0:
        snip = "..." + snip
    return snip


def _find_hidden_chars(text: str):
    labels = []
    for ch in text:
        cp = ord(ch)
        if _is_hidden_char(cp, ch):
            name = unicodedata.name(ch, "")
            label = f"U+{cp:04X}" + (f" {name}" if name else "")
            if label not in labels:
                labels.append(label)
    return labels


def _max_sev(findings):
    sev = "NONE"
    for f in findings:
        if SEV_ORDER[f["severity"]] > SEV_ORDER[sev]:
            sev = f["severity"]
    return sev


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f["severity"], f["category"], f.get("field"), f.get("snippet"), f["what"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scan_text(text, field):
    """Return findings for a single text field. Read-only; never executes text."""
    findings = []
    if not isinstance(text, str) or not text:
        return findings

    for pat, what in INSTRUCTION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            findings.append({
                "severity": "HIGH",
                "category": "model-directed instruction / injection",
                "what": what,
                "snippet": _snippet(text, m),
                "field": field,
            })

    for pat, what in CREDENTIAL_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            findings.append({
                "severity": "HIGH",
                "category": "credential / exfiltration reference",
                "what": f"{what} {CRED_WHAT}",
                "snippet": _snippet(text, m),
                "field": field,
            })

    hidden = _find_hidden_chars(text)
    if hidden:
        findings.append({
            "severity": "HIGH",
            "category": "hidden / obfuscated text",
            "what": ("Contains invisible/hidden characters (" + ", ".join(hidden[:5]) +
                     ") that can conceal instructions from a human reviewer."),
            "snippet": "[non-printable characters present]",
            "field": field,
        })

    return findings


def scan_schema(node, prefix, path="", findings=None):
    """Recursively scan EVERY string in a JSON schema: property names, titles,
    nested descriptions at all depths, and enum values."""
    if findings is None:
        findings = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                # Property names live under a "properties" map; scanning all keys is
                # harmless (schema keywords never match the heuristics) and catches them.
                label = f"{prefix} name:{path}{k}".strip()
                findings += scan_text(k, label)
            scan_schema(v, prefix, f"{path}{k}.", findings)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            scan_schema(item, prefix, f"{path}[{i}].", findings)
    elif isinstance(node, str):
        findings += scan_text(node, f"{prefix}:{path.rstrip('.')}".strip())
    return findings


def _capability_findings(name, desc):
    text = f"{name}\n{desc}"
    matched = []
    for cap, pat in CAPABILITY_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            matched.append(cap)
    if not matched:
        return []
    return [{
        "severity": "MEDIUM",
        "category": "capability",
        "what": ("High-impact capability implied by name/description (" +
                 ", ".join(matched) + "). Not an injection finding - shown so you see "
                 "this server's blast radius; confirm the tool really needs it."),
        "snippet": (name or desc)[:SNIPPET_LEN],
        "field": "name/description",
    }]


def audit_tools(tools, all_names=None):
    """Run heuristics over a list of tool metadata dicts."""
    if not isinstance(tools, list):
        tools = []
    own_names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    steer_names = all_names if all_names is not None else own_names
    results = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name", "") or ""
        desc = t.get("description", "") or ""
        findings = []

        findings += scan_text(name, "name")
        findings += scan_text(desc, "description")

        if len(desc) > PADDING_LIMIT:
            findings.append({
                "severity": "MEDIUM",
                "category": "padding",
                "what": (f"Description is {len(desc)} characters long - unusually long, "
                         "leaving room to bury hidden instructions in text a reviewer may skim."),
                "snippet": desc[:SNIPPET_LEN] + "...",
                "field": "description",
            })

        # Full-schema scan (input + output).
        schema = t.get("inputSchema")
        if isinstance(schema, (dict, list)):
            findings += scan_schema(schema, "inputSchema")
        oschema = t.get("outputSchema")
        if isinstance(oschema, (dict, list)):
            findings += scan_schema(oschema, "outputSchema")

        # Dangerous-capability note.
        findings += _capability_findings(name, desc)

        # Cross-tool / cross-server steering.
        combined = f"{name}\n{desc}"
        if re.search(r"\b(call|use|then|run|invoke)\b", combined, re.IGNORECASE):
            for other in steer_names:
                if other and other != name and len(other) >= 3:
                    m = re.search(r"\b" + re.escape(other) + r"\b", combined, re.IGNORECASE)
                    if m:
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "cross-tool steering",
                            "what": (f"Mentions another tool ('{other}') together with an action "
                                     "verb - may steer the model to chain/redirect tools."),
                            "snippet": _snippet(combined, m),
                            "field": "description",
                        })
                        break

        findings = _dedupe(findings)
        results.append({"name": name, "kind": "tool",
                        "findings": findings, "max_severity": _max_sev(findings)})
    return results


def audit_meta(items, kind):
    """Audit resources / resource-templates / prompts (name/title/description, prompt args)."""
    results = []
    if not isinstance(items, list):
        return results
    for it in items:
        if not isinstance(it, dict):
            continue
        name = (it.get("name") or it.get("uri") or it.get("uriTemplate")
                or it.get("title") or "")
        findings = []
        findings += scan_text(it.get("name", "") or "", "name")
        findings += scan_text(it.get("title", "") or "", "title")
        findings += scan_text(it.get("description", "") or "", "description")
        if kind == "prompt":
            for arg in it.get("arguments", []) or []:
                if isinstance(arg, dict):
                    aname = arg.get("name", "") or ""
                    findings += scan_text(aname, f"argument '{aname}' name")
                    findings += scan_text(arg.get("description", "") or "",
                                          f"argument '{aname}' description")
        findings = _dedupe(findings)
        results.append({"name": name, "kind": kind,
                        "findings": findings, "max_severity": _max_sev(findings)})
    return results


# --------------------------------------------------------------------------- #
# Provenance / supply-chain (reads launch def; NEVER prints env/header VALUES)
# --------------------------------------------------------------------------- #

def _make_server_finding(sev, category, what, snippet=None):
    return {"severity": sev, "category": category, "what": what,
            "snippet": snippet or "", "field": "server launch def"}


def _tool_basename(tok):
    base = tok.replace("\\", "/").split("/")[-1].lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def _has_tool(tokens, name):
    return any(_tool_basename(t) == name for t in tokens)


def _first_arg_after(tokens, name):
    idx = None
    for i, t in enumerate(tokens):
        if _tool_basename(t) == name:
            idx = i
            break
    if idx is None:
        return None
    for t in tokens[idx + 1:]:
        if not t.startswith("-"):
            return t
    return None


def _is_pinned_node(spec):
    if spec.startswith("@"):
        return "@" in spec[1:]
    return "@" in spec


def _is_pinned_py(spec):
    return bool(re.search(r"(==|>=|<=|~=|@)", spec))


def analyze_provenance(spec):
    """Return supply-chain findings for a server launch definition."""
    findings = []
    args = spec.get("args") or []
    cmdline = " ".join(str(a) for a in args)
    low = cmdline.lower()

    # Remote script piped into a shell -> arbitrary remote code at every start.
    if (re.search(r"\b(curl|wget|iwr|invoke-webrequest)\b", low)
            and re.search(r"(\|\s*(sh|bash|zsh|pwsh|powershell)\b|\biex\b|invoke-expression)", low)):
        findings.append(_make_server_finding(
            "HIGH", "supply-chain / provenance",
            "Launch command downloads and pipes a remote script into a shell "
            "(curl|sh / iwr|iex) - runs arbitrary remote code at every start.",
            cmdline[:SNIPPET_LEN]))

    # npx - unpinned or auto-confirmed.
    if _has_tool(args, "npx"):
        reasons = []
        if any(t in ("-y", "--yes") for t in args):
            reasons.append("uses -y/--yes (auto-confirms install)")
        pkg = _first_arg_after(args, "npx")
        if pkg and not _is_pinned_node(pkg):
            reasons.append(f"package '{pkg}' is not version-pinned")
        if reasons:
            findings.append(_make_server_finding(
                "MEDIUM", "supply-chain / provenance",
                "npx launch pulls latest each run - rug-pull vector; pin a version/commit. ("
                + "; ".join(reasons) + ")", cmdline[:SNIPPET_LEN]))

    # uvx / pipx run - unpinned.
    if _has_tool(args, "uvx"):
        pkg = _first_arg_after(args, "uvx")
        if pkg and not _is_pinned_py(pkg):
            findings.append(_make_server_finding(
                "MEDIUM", "supply-chain / provenance",
                f"uvx launch of '{pkg}' is not version-pinned - pulls latest each run; "
                "pin a version/commit.", cmdline[:SNIPPET_LEN]))
    if _has_tool(args, "pipx") and "run" in args:
        pkg = _first_arg_after(args, "run")
        if pkg and not _is_pinned_py(pkg):
            findings.append(_make_server_finding(
                "MEDIUM", "supply-chain / provenance",
                f"pipx run of '{pkg}' is not version-pinned - pulls latest each run; "
                "pin a version.", cmdline[:SNIPPET_LEN]))

    # Non-HTTPS transport for an http server.
    url = spec.get("url")
    if url and not str(url).lower().startswith("https://"):
        findings.append(_make_server_finding(
            "HIGH", "supply-chain / provenance",
            "HTTP MCP endpoint uses a non-HTTPS (plaintext) URL - credentials and tool "
            "data are exposed in transit.", str(url)[:SNIPPET_LEN]))

    # Static credentials in env/headers - KEY NAMES only, never values.
    cred_keys = []
    for k in list(spec.get("env_keys") or []) + list(spec.get("header_keys") or []):
        if re.search(r"(token|key|secret|password|passwd|auth|credential|cred|pat|bearer|apikey)",
                     str(k), re.IGNORECASE):
            cred_keys.append(str(k))
    if cred_keys:
        findings.append(_make_server_finding(
            "MEDIUM", "supply-chain / provenance",
            "Static credential(s) configured for this server (key name(s) only): "
            + ", ".join(cred_keys) +
            " - prefer OAuth 2.1 + scoped tokens, and isolate this server."))

    return findings


# --------------------------------------------------------------------------- #
# Rug-pull / drift (trust-on-first-use baseline)
# --------------------------------------------------------------------------- #

def baseline_dir():
    override = os.environ.get("MCP_AUDITOR_HOME")
    if override:
        return Path(override)
    return Path.home() / ".claude" / "mcp-auditor"


def load_baseline():
    path = baseline_dir() / "baseline.json"
    data = _load_json(path)
    return data if isinstance(data, dict) else {}


def save_baseline(data):
    d = baseline_dir()
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "baseline.json", "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def canonical_hash(raw):
    payload = {
        "tools": raw.get("tools", []),
        "resources": raw.get("resources", []),
        "resourceTemplates": raw.get("resourceTemplates", []),
        "prompts": raw.get("prompts", []),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _note(what):
    return {"severity": "INFO", "category": "baseline",
            "what": what, "snippet": "", "field": "baseline"}


def eval_drift(baseline, key, raw, accept):
    """Return (finding_or_None, baseline_changed)."""
    h = canonical_hash(raw)
    servers = baseline.setdefault("servers", {})
    entry = servers.get(key)
    if accept:
        servers[key] = {"hash": h}
        return _note(f"Baseline (re)accepted for this server ({key})."), True
    if entry is None:
        servers[key] = {"hash": h}
        return (_note("First time this server was seen - baseline recorded. Future changes "
                      "to its tool/resource/prompt definitions will be flagged as drift."), True)
    if entry.get("hash") != h:
        return (_make_server_finding(
            "HIGH", "rug-pull / definition drift",
            "Definition changed since first seen - possible rug-pull. This server's "
            "tool/resource/prompt metadata differs from the recorded baseline. Re-review, "
            "then run with --accept to approve the new definition."), False)
    return (None, False)


# --------------------------------------------------------------------------- #
# Cross-server shadowing
# --------------------------------------------------------------------------- #

def add_shadowing(results):
    name_map = {}
    for sr in results:
        if sr["status"] != "audited":
            continue
        for e in sr["entities"]:
            if e["kind"] == "tool" and e["name"]:
                name_map.setdefault(e["name"], set()).add(sr["label"])
    for sr in results:
        if sr["status"] != "audited":
            continue
        own_tool_names = {e["name"] for e in sr["entities"] if e["kind"] == "tool"}
        for tool_name in own_tool_names:
            servers = name_map.get(tool_name, set())
            if len(servers) > 1:
                others = sorted(servers - {sr["label"]})
                sr["server_findings"].append(_make_server_finding(
                    "MEDIUM", "cross-server shadowing",
                    f"Tool name '{tool_name}' is also provided by another server "
                    f"(shadowing / name collision): {', '.join(others)}. A malicious "
                    "server can shadow a trusted tool of the same name."))


# --------------------------------------------------------------------------- #
# Live server communication - server output treated as inert data
# --------------------------------------------------------------------------- #

INIT_MSG = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "mcp-auditor", "version": "0.1"}},
}
INITIALIZED_MSG = {"jsonrpc": "2.0", "method": "notifications/initialized"}

LIST_METHODS = [
    (2, "tools/list", "tools", "tools"),
    (3, "resources/list", "resources", "resources"),
    (4, "resources/templates/list", "resourceTemplates", "resourceTemplates"),
    (5, "prompts/list", "prompts", "prompts"),
]


def _dequote(tokens):
    out = []
    for tok in tokens:
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
            out.append(tok[1:-1])
        else:
            out.append(tok)
    return out


def parse_stdio_command(command: str):
    """shlex-split a command string, Windows-safe (keep backslashes, strip quotes)."""
    return _dequote(shlex.split(command, posix=False))


def fetch_stdio(args, timeout=15.0):
    """Spawn a stdio MCP server, handshake, and collect tools/resources/prompts.

    Raises on handshake failure. Child is always terminated/killed in finally.
    Server output is parsed as JSON data only - never executed or shell-interpreted.
    """
    try:
        proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            errors="replace", bufsize=1,
        )
    except (OSError, ValueError) as e:
        raise RuntimeError(f"could not start server process: {e}")

    q: "queue.Queue" = queue.Queue()

    def reader():
        try:
            for line in proc.stdout:
                q.put(line)
        except Exception:
            pass
        finally:
            q.put(None)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.time() + timeout

    def send(obj):
        try:
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as e:
            raise RuntimeError(f"server closed its input: {e}")

    def wait_for_id(want, per_timeout=None):
        local_deadline = deadline
        if per_timeout is not None:
            local_deadline = min(deadline, time.time() + per_timeout)
        while True:
            remaining = local_deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for server response")
            try:
                line = q.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError("timed out waiting for server response")
            if line is None:
                raise RuntimeError("server closed its output before responding")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue  # ignore non-JSON log/notification lines
            if isinstance(msg, dict) and msg.get("id") == want:
                return msg

    raw = {"tools": [], "resources": [], "resourceTemplates": [], "prompts": []}
    try:
        send(INIT_MSG)
        wait_for_id(1)
        send(INITIALIZED_MSG)
        for req_id, method, result_key, store_key in LIST_METHODS:
            send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": {}})
            critical = (method == "tools/list")
            try:
                resp = wait_for_id(req_id, per_timeout=None if critical else 6.0)
            except (TimeoutError, RuntimeError):
                if critical:
                    raise
                continue  # optional capability absent / slow - skip
            if not isinstance(resp, dict) or "error" in resp:
                continue  # method not found / unsupported - graceful
            items = (resp.get("result") or {}).get(result_key, [])
            if isinstance(items, list):
                raw[store_key] = items
        return raw
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _parse_jsonrpc_body(body: str, content_type: str):
    ct = (content_type or "").lower()
    if "text/event-stream" in ct or body.lstrip().startswith(("event:", "data:")):
        payloads = []
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                data = line[len("data:"):].strip()
                if data and data != "[DONE]":
                    try:
                        payloads.append(json.loads(data))
                    except (json.JSONDecodeError, ValueError):
                        pass
        if not payloads:
            raise RuntimeError("no JSON found in SSE stream")
        return payloads[-1]
    return json.loads(body)


def fetch_http(url, timeout=15.0):
    """Best-effort HTTP JSON-RPC: initialize + list methods. No auth header sent.

    Raises on failure (caller marks skipped/unreachable). Never prints/forwards tokens.
    """
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}

    def post(obj, extra=None):
        h = dict(headers)
        if extra:
            h.update(extra)
        req = urllib.request.Request(url, data=json.dumps(obj).encode("utf-8"),
                                     headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return (_parse_jsonrpc_body(body, resp.headers.get("Content-Type", "")),
                    resp.headers.get("Mcp-Session-Id"))

    _, session = post(INIT_MSG)
    extra = {"Mcp-Session-Id": session} if session else None
    try:
        post(INITIALIZED_MSG, extra)
    except Exception:
        pass

    raw = {"tools": [], "resources": [], "resourceTemplates": [], "prompts": []}
    for req_id, method, result_key, store_key in LIST_METHODS:
        try:
            resp, _ = post({"jsonrpc": "2.0", "id": req_id, "method": method, "params": {}},
                           extra)
        except Exception:
            if method == "tools/list":
                raise
            continue
        if not isinstance(resp, dict) or "error" in resp:
            continue
        items = (resp.get("result") or {}).get(result_key, [])
        if isinstance(items, list):
            raw[store_key] = items
    return raw


# --------------------------------------------------------------------------- #
# Config discovery (key-scoped; never dumps whole files or secret values)
# --------------------------------------------------------------------------- #

def _load_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def discover_servers(extra_path=None):
    """Return server launch specs from ~/.claude.json and optional .mcp.json files.

    Reads only mcpServers keys. Captures env/header KEY NAMES only - never values.
    """
    servers = []
    seen = set()

    def add_map(mapping, source):
        if not isinstance(mapping, dict):
            return
        for name, cfg in mapping.items():
            if not isinstance(cfg, dict):
                continue
            key = (source, name)
            if key in seen:
                continue
            seen.add(key)
            env_keys = list((cfg.get("env") or {}).keys()) if isinstance(cfg.get("env"), dict) else []
            header_keys = (list((cfg.get("headers") or {}).keys())
                           if isinstance(cfg.get("headers"), dict) else [])
            spec = {"label": f"{name} ({source})", "env_keys": env_keys,
                    "header_keys": header_keys, "drift_key": f"{source}:{name}"}
            if cfg.get("command"):
                spec["kind"] = "stdio"
                spec["args"] = [str(cfg["command"])] + [str(a) for a in cfg.get("args", []) or []]
            elif cfg.get("url"):
                spec["kind"] = "http"
                spec["url"] = str(cfg["url"])
            else:
                spec["kind"] = "unknown"
            servers.append(spec)

    data = _load_json(Path.home() / ".claude.json")
    if isinstance(data, dict):
        add_map(data.get("mcpServers"), "~/.claude.json")
        projects = data.get("projects")
        if isinstance(projects, dict):
            cwd = str(Path.cwd())
            proj = projects.get(cwd)
            if isinstance(proj, dict):
                add_map(proj.get("mcpServers"), f"~/.claude.json projects[{cwd}]")

    if extra_path:
        root = Path(extra_path)
        candidates = []
        if root.is_file() and root.name == ".mcp.json":
            candidates = [root]
        elif root.is_dir():
            candidates = list(root.rglob(".mcp.json"))
        for mcp_file in candidates:
            fdata = _load_json(mcp_file)
            if isinstance(fdata, dict):
                add_map(fdata.get("mcpServers"), str(mcp_file))

    return servers


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

INTRO = (
    "WHY THIS MATTERS: an MCP server tells the model the NAME, DESCRIPTION and\n"
    "parameter/schema notes of each tool, resource and prompt. That text loads into\n"
    "the model's context at session start - before anything is ever run. A malicious\n"
    "server can hide orders to the model inside that text (\"tool poisoning\").\n"
    "Reviewing the server's code does not catch this. This report only reads and\n"
    "flags that text; it never follows any instruction found inside it.\n"
)

FOOTER = (
    "Not covered by this static metadata audit (operational / runtime concerns):\n"
    "  - Indirect prompt injection via tool RESULTS/outputs at runtime (a server can\n"
    "    return a clean-looking description but inject via the DATA it returns later).\n"
    "  - Sandboxing, egress controls, and logging/monitoring of the running server.\n"
    "  - Confused-deputy / token-passthrough abuse where the server forwards your\n"
    "    credentials or acts on your authority against another service.\n"
    "These need runtime monitoring and least-privilege isolation, not a static scan."
)


def _entity_findings(server_results, sev):
    rows = []
    for sr in server_results:
        for f in sr.get("server_findings", []):
            if f["severity"] == sev:
                rows.append((sr["label"], f"server '{sr['label']}'", f))
        if sr["status"] != "audited":
            continue
        for e in sr["entities"]:
            for f in e["findings"]:
                if f["severity"] == sev:
                    rows.append((sr["label"], f"{e['kind']} '{e['name']}'", f))
    return rows


def build_report(server_results):
    lines = []
    high = med = 0
    audited_servers = 0
    total_entities = 0
    not_audited = []
    notes = []

    for sr in server_results:
        if sr["status"] == "audited":
            audited_servers += 1
            total_entities += len(sr["entities"])
        else:
            not_audited.append(sr)
        for f in sr.get("server_findings", []):
            if f["severity"] == "HIGH":
                high += 1
            elif f["severity"] == "MEDIUM":
                med += 1
            elif f["severity"] == "INFO":
                notes.append((sr["label"], f))
        if sr["status"] == "audited":
            for e in sr["entities"]:
                for f in e["findings"]:
                    if f["severity"] == "HIGH":
                        high += 1
                    elif f["severity"] == "MEDIUM":
                        med += 1

    if high:
        verdict = (f"VERDICT: REVIEW NEEDED - HIGH risk. {high} HIGH-severity "
                   f"and {med} MEDIUM-severity finding(s) across {audited_servers} audited server(s).")
    elif med:
        verdict = (f"VERDICT: REVIEW - {med} MEDIUM-severity finding(s); no HIGH-severity "
                   f"findings. Across {audited_servers} audited server(s).")
    elif audited_servers:
        verdict = (f"VERDICT: no obvious issues found across {total_entities} item(s) "
                   f"in {audited_servers} audited server(s) (LOW).")
    else:
        verdict = "VERDICT: COULD NOT AUDIT - no server was successfully audited."

    if not_audited:
        verdict += (f" {len(not_audited)} server(s) were NOT audited "
                    "(unreachable / errored / need auth) - treat those as NOT safe, not clean.")

    lines.append(verdict)
    lines.append("")
    lines.append(INTRO)

    if not_audited:
        lines.append("SERVERS NOT AUDITED (treat as NOT safe - absence of findings is NOT a clean bill):")
        for sr in not_audited:
            lines.append(f"  - {sr['label']}: {sr['status'].upper()} - {sr.get('detail', '')}")
        lines.append("")

    for sev, header in (("HIGH", "HIGH-RISK FINDINGS"), ("MEDIUM", "MEDIUM-RISK FINDINGS")):
        rows = _entity_findings(server_results, sev)
        if not rows:
            continue
        lines.append(f"{header} ({len(rows)}):")
        for label, who, f in rows:
            lines.append(f"  [{sev}] {who} - field: {f.get('field', '')} - {f['category']}")
            lines.append(f"         what it would do: {f['what']}")
            if f.get("snippet"):
                lines.append(f"         matched text: {f['snippet']}")
            lines.append(f"         server: {label}")
            lines.append("")

    if notes:
        lines.append("NOTES:")
        for label, f in notes:
            lines.append(f"  - {label}: {f['what']}")
        lines.append("")

    lines.append("Reminder: a flagged item has NOT attacked anything yet - but its metadata")
    lines.append("loads into the model's context at session init, so review or remove the")
    lines.append("server before using it.")
    lines.append("")
    lines.append(FOOTER)

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Mode handlers
# --------------------------------------------------------------------------- #

FETCH_ERRORS = (RuntimeError, TimeoutError, OSError, ValueError,
                urllib.error.URLError, urllib.error.HTTPError)


def _audit_raw(raw, all_names):
    return (audit_tools(raw.get("tools", []), all_names)
            + audit_meta(raw.get("resources", []), "resource")
            + audit_meta(raw.get("resourceTemplates", []), "resource-template")
            + audit_meta(raw.get("prompts", []), "prompt"))


def mode_file(path):
    p = Path(path)
    if not p.is_file():
        return [{"label": str(p), "status": "errored", "detail": "file not found",
                 "entities": [], "server_findings": []}]
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, ValueError, OSError) as e:
        return [{"label": str(p), "status": "errored", "detail": f"could not parse JSON: {e}",
                 "entities": [], "server_findings": []}]

    if isinstance(data, dict) and "tools" in data:
        tools = data.get("tools")
        raw = {"tools": tools, "resources": data.get("resources", []),
               "resourceTemplates": data.get("resourceTemplates", []),
               "prompts": data.get("prompts", [])}
    elif isinstance(data, list):
        raw = {"tools": data, "resources": [], "resourceTemplates": [], "prompts": []}
    else:
        return [{"label": str(p), "status": "errored",
                 "detail": "JSON is neither {\"tools\":[...]} nor a bare [...] array",
                 "entities": [], "server_findings": []}]

    return [{"label": str(p), "status": "audited", "detail": "",
             "entities": _audit_raw(raw, None), "server_findings": []}]


def mode_stdio(command, accept=False):
    spec = {"label": f"stdio: {command}", "kind": "stdio",
            "args": [], "env_keys": [], "header_keys": [], "drift_key": f"stdio:{command}"}
    try:
        spec["args"] = parse_stdio_command(command)
        if not spec["args"]:
            raise RuntimeError("empty command")
    except ValueError as e:
        return [{"label": spec["label"], "status": "errored",
                 "detail": f"could not parse command: {e}",
                 "entities": [], "server_findings": []}]

    sr = {"label": spec["label"], "status": "audited", "detail": "",
          "entities": [], "server_findings": analyze_provenance(spec)}
    try:
        raw = fetch_stdio(spec["args"])
    except FETCH_ERRORS as e:
        sr["status"] = "unreachable"
        sr["detail"] = f"handshake failed: {e}"
        return [sr]

    all_names = [t.get("name", "") for t in raw.get("tools", []) if isinstance(t, dict)]
    sr["entities"] = _audit_raw(raw, all_names)
    baseline = load_baseline()
    finding, changed = eval_drift(baseline, spec["drift_key"], raw, accept)
    if finding:
        sr["server_findings"].append(finding)
    if changed:
        save_baseline(baseline)
    return [sr]


def mode_config(path, accept=False):
    servers = discover_servers(path)
    if not servers:
        return [{"label": "config", "status": "errored",
                 "detail": "no MCP servers found in ~/.claude.json or given path",
                 "entities": [], "server_findings": []}]

    fetched = []
    for s in servers:
        if s["kind"] == "stdio":
            try:
                fetched.append((s, "audited", "", fetch_stdio(s["args"])))
            except FETCH_ERRORS as e:
                fetched.append((s, "unreachable", f"handshake failed: {e}", None))
        elif s["kind"] == "http":
            try:
                fetched.append((s, "audited", "", fetch_http(s["url"])))
            except FETCH_ERRORS as e:
                fetched.append((s, "skipped", f"needs auth / unreachable: {e}", None))
        else:
            fetched.append((s, "skipped", "no command or url in config", None))

    all_names = []
    for s, st, dt, raw in fetched:
        if raw:
            all_names += [t.get("name", "") for t in raw.get("tools", []) if isinstance(t, dict)]

    baseline = load_baseline()
    changed = False
    results = []
    for s, st, dt, raw in fetched:
        sr = {"label": s["label"], "status": st, "detail": dt,
              "entities": [], "server_findings": analyze_provenance(s)}
        if st == "audited" and raw is not None:
            sr["entities"] = _audit_raw(raw, all_names)
            finding, ch = eval_drift(baseline, s.get("drift_key", s["label"]), raw, accept)
            if finding:
                sr["server_findings"].append(finding)
            changed = changed or ch
        results.append(sr)

    add_shadowing(results)
    if changed:
        save_baseline(baseline)
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        prog="mcp-auditor",
        description="Audit MCP server metadata for prompt-injection / tool poisoning.")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="Audit MCP metadata from a file, a stdio server, or config.")
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", metavar="PATH",
                   help="Read a tools/list JSON file (READ-ONLY, no process spawned).")
    g.add_argument("--stdio", metavar="COMMAND",
                   help="Spawn a stdio MCP server and audit it live.")
    g.add_argument("--config", nargs="?", const="__CONFIG_NONE__", metavar="PATH",
                   help="Audit configured MCP servers (optionally scan PATH for .mcp.json).")
    a.add_argument("--accept", action="store_true",
                   help="Re-baseline audited servers after review (approve current definitions).")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "audit":
        if args.file is not None:
            results = mode_file(args.file)
        elif args.stdio is not None:
            results = mode_stdio(args.stdio, accept=args.accept)
        else:
            path = None if args.config == "__CONFIG_NONE__" else args.config
            results = mode_config(path, accept=args.accept)
        report = build_report(results)
        try:
            print(report)
        except UnicodeEncodeError:
            # Narrow console codepage + non-ASCII in an untrusted snippet: never crash.
            enc = (sys.stdout.encoding or "utf-8")
            sys.stdout.buffer.write(report.encode(enc, "replace") + b"\n")
        any_high = any(
            any(f["severity"] == "HIGH" for f in sr.get("server_findings", []))
            or (sr["status"] == "audited"
                and any(f["severity"] == "HIGH" for e in sr["entities"] for f in e["findings"]))
            for sr in results
        )
        return 1 if any_high else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
