#!/usr/bin/env python3
"""TLS certificate expiry probe for the hostnames served by Nginx Proxy Manager (NPM).

For every hostname, connects to NPM's TLS listener (--target, default 127.0.0.1:443) with SNI set
to that hostname, so it checks exactly the certificate NPM presents for it, and appends one JSON
line per host to --out. The Wazuh manager reads that file with a <localfile> log_format json block
(rules 101713-101716 in npm_rules.xml).

  {"integration":"npm-certs","npm_cert":{"host":"app.example.com","target":"127.0.0.1:443",
   "status":"ok","days_left":56,"issuer":"Let's Encrypt","not_after":"2027-03-01T00:00:00Z",
   "san":"app.example.com"}}

status:  ok | expiring (< --warn-days, default 14) | critical (< --crit-days, default 3) |
         expired | name_mismatch (valid dates but no SAN covers the host) |
         probe_error (connect / handshake failed; "error" holds the reason)

Hostnames come from any combination of:
  --hosts-file FILE   one hostname per line (# comments allowed)
  --npm-conf GLOB     NPM's generated nginx configs, server_name lines
                      (e.g. /opt/npm/data/nginx/proxy_host/*.conf)
  --npm-logs GLOB     NPM proxy-host access logs, host field
                      (e.g. '/opt/npm/data/logs/proxy-host-*_access.log'; the last --log-bytes of
                      each file are read)
Only names that look like DNS hostnames are probed (no IPs, no wildcards), at most --max-hosts.
Probes only ever go to --target; a hostname only selects the SNI value.

The certificate is fetched WITHOUT verification on purpose (an expired or mismatched certificate
must still be reported). stdlib only; CPython 3.8+.
"""
import argparse
import glob
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time

INTEGRATION = "npm-certs"
HOST_RE = re.compile(r"(?=.{4,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
# NPM access log (proxy or standard format): [time] ... status - METHOD scheme HOST "uri" [Client ...
LOG_HOST_RE = re.compile(r'^\[[^\]]+\] .*?\b\d{3} - \S* https? (\S+) \\?"')
CONF_RE = re.compile(r"^\s*server_name\s+([^;]+);", re.M)


# ------------------------------------------------------------------------------- host sources ----

def valid_host(h):
    h = h.strip().lower().rstrip(".")
    return h if HOST_RE.fullmatch(h) else None


def hosts_from_lines(lines):
    out = set()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            h = valid_host(line)
            if h:
                out.add(h)
    return out


def hosts_from_log_lines(lines):
    out = set()
    for line in lines:
        m = LOG_HOST_RE.match(line)
        if m:
            h = valid_host(m.group(1))
            if h:
                out.add(h)
    return out


def hosts_from_conf_text(text):
    out = set()
    for m in CONF_RE.finditer(text):
        for name in m.group(1).split():
            h = valid_host(name)
            if h:
                out.add(h)
    return out


def tail_lines(path, nbytes):
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - nbytes))
        data = f.read()
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > nbytes else lines   # first line may be cut


def collect_hosts(hosts_files=(), conf_globs=(), log_globs=(), log_bytes=5_000_000):
    hosts = set()
    for p in hosts_files:
        with open(p, encoding="utf-8") as f:
            hosts |= hosts_from_lines(f)
    for g in conf_globs:
        for p in sorted(glob.glob(g)):
            with open(p, encoding="utf-8", errors="replace") as f:
                hosts |= hosts_from_conf_text(f.read())
    for g in log_globs:
        for p in sorted(glob.glob(g)):
            hosts |= hosts_from_log_lines(tail_lines(p, log_bytes))
    return hosts


# ------------------------------------------------------------------------------------ probing ----

def fetch_cert(host, target_host, target_port, timeout):
    """Return the decoded certificate dict NPM presents for SNI=host (no verification)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target_host, target_port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
    if not der:
        raise ValueError("no certificate presented")
    # getpeercert() returns {} without verification; decode the DER via a temp PEM file.
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as t:
            t.write(pem)
        return ssl._ssl._test_decode_cert(path)
    finally:
        os.unlink(path)


def san_matches(host, sans):
    for s in sans:
        s = s.lower()
        if s == host:
            return True
        if s.startswith("*.") and host.endswith(s[1:]) and host.count(".") == s.count("."):
            return True
    return False


def classify(not_after_ts, now, matches, warn_days, crit_days):
    days = int((not_after_ts - now) // 86400)
    if not_after_ts <= now:
        st = "expired"
    elif days < crit_days:
        st = "critical"
    elif days < warn_days:
        st = "expiring"
    else:
        st = "ok"
    if st == "ok" and not matches:
        st = "name_mismatch"
    return st, days


def probe_host(host, target_host, target_port, timeout, now, warn_days, crit_days, fetch=fetch_cert):
    ev = {"host": host, "target": f"{target_host}:{target_port}"}
    try:
        c = fetch(host, target_host, target_port, timeout)
        na = ssl.cert_time_to_seconds(c["notAfter"])
        sans = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
        issuer = dict(x[0] for x in c.get("issuer", ())).get("organizationName", "")
        st, days = classify(na, now, san_matches(host, sans), warn_days, crit_days)
        ev.update(status=st, days_left=days, issuer=issuer,
                  not_after=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(na)),
                  san=",".join(sans)[:500])
    except Exception as e:  # report, never crash the run
        ev.update(status="probe_error", error=(type(e).__name__ + ": " + str(e))[:200])
    return {"integration": INTEGRATION, "npm_cert": ev}


# ----------------------------------------------------------------------------------------- main ----

def parse_target(s):
    if s.startswith("["):                       # [v6]:port
        h, _, p = s[1:].partition("]:")
    else:
        h, _, p = s.rpartition(":") if ":" in s else (s, "", "443")
    return h, int(p or 443)


def build_parser():
    ap = argparse.ArgumentParser(description="Probe TLS certificate expiry of NPM-served hostnames.")
    ap.add_argument("--hosts-file", action="append", default=[], help="file with one hostname per line")
    ap.add_argument("--npm-conf", action="append", default=[], help="glob of NPM nginx configs (server_name)")
    ap.add_argument("--npm-logs", action="append", default=[], help="glob of NPM proxy-host access logs")
    ap.add_argument("--target", default=os.environ.get("NPM_CERTS_TARGET", "127.0.0.1:443"),
                    help="NPM TLS listener host:port to connect to (default 127.0.0.1:443)")
    ap.add_argument("--out", default=os.environ.get("NPM_CERTS_OUT", "/var/log/npm-certs.json"),
                    help="JSON-lines output file, appended (default /var/log/npm-certs.json)")
    ap.add_argument("--warn-days", type=int, default=14)
    ap.add_argument("--crit-days", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-hosts", type=int, default=500)
    ap.add_argument("--log-bytes", type=int, default=5_000_000, help="bytes read from the end of each log")
    return ap


def main(argv=None, fetch=fetch_cert, now=None):
    a = build_parser().parse_args(argv)
    if not (a.hosts_file or a.npm_conf or a.npm_logs):
        print("no host source: give --hosts-file, --npm-conf and/or --npm-logs", file=sys.stderr)
        return 2
    hosts = sorted(collect_hosts(a.hosts_file, a.npm_conf, a.npm_logs, a.log_bytes))
    if len(hosts) > a.max_hosts:
        print(f"{len(hosts)} hostnames found, probing the first {a.max_hosts} (--max-hosts)", file=sys.stderr)
        hosts = hosts[:a.max_hosts]
    th, tp = parse_target(a.target)
    now = time.time() if now is None else now
    with open(a.out, "a", encoding="utf-8") as f:
        for h in hosts:
            ev = probe_host(h, th, tp, a.timeout, now, a.warn_days, a.crit_days, fetch=fetch)
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")
    print(f"probed {len(hosts)} hosts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
