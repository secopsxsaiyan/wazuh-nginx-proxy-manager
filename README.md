# Nginx Proxy Manager → Wazuh: decoders, web-threat rules, cert expiry & dashboard

Custom Wazuh content for **[Nginx Proxy Manager](https://nginxproxymanager.com/)** (NPM), the
Docker-based reverse proxy. It decodes NPM's own access and error logs, turns them into alerts
for probes, scans, brute force and upstream outages, checks the TLS certificates NPM serves for
upcoming expiry, and ships a ready-made **"Nginx Proxy Manager - Web Threats"** dashboard.

1. **Access logs** (`proxy-host-*_access.log` and the other `*_access.log` files) — NPM's custom
   log format (`[time] - 200 200 - GET https host "/path" [Client ip] ... [Sent-to upstream] "ua" "ref"`)
   is not understood by the stock web decoders. These decoders extract the client as canonical
   `srcip`, plus `status`, `url`, method, host, upstream, upstream status, user agent and referer.
2. **Error logs** (`*_error.log`) — plain nginx error lines. The stock nginx decoder and rules
   already handle them (including access-list basic-auth failures); this pack adds host, request
   and upstream fields and an upstream-failure rule.
3. **Certificate expiry (optional poller)** — `poller/npm_certs.py` connects to NPM with SNI for
   each hostname and reports days left, issuer and SAN as JSON lines for Wazuh.

> Primary collection path: a **Wazuh agent on the NPM host** reading NPM's log files. An optional
> syslog path is supported for hosts where no agent can be installed. The poller is a small
> stdlib-only Python script run from cron.

## Contents

```
custom_rules/
  npm_decoders.xml   # NPM access-log decoders (file + syslog path), extra nginx error-log fields
  npm_rules.xml      # classification + detection rules (IDs 101700–101718)
dashboards/
  gen_npm_dashboard.py        # generator for the "Nginx Proxy Manager - Web Threats" dashboard (stdlib only)
  wazuh_npm_dashboard.ndjson  # pre-generated saved-objects export (import this)
poller/
  npm_certs.py                # TLS certificate expiry probe -> JSON lines (stdlib only)
  npm-hosts.example           # example hostname list (one per line)
  tests/test_npm_certs.py     # unit tests (no network): python3 -m unittest discover -s poller/tests
```

## Requirements

- **Wazuh manager 4.x** (validated on 4.14.5; uses PCRE2 in decoders and rules).
- A **Wazuh agent** on the host that runs NPM, with read access to NPM's data directory
  (the directory mounted at `/data` in the NPM container, e.g. `/opt/npm/data`).
- **Wazuh dashboard / OpenSearch Dashboards 2.16.x** with a `wazuh-alerts-*` index pattern
  (for the dashboard).
- Python 3.8+ (CPython) for the optional certificate poller.

## How the decoding works (read once)

- NPM access lines start with an nginx-style `[01/Jan/2026:12:00:00 +0000]` timestamp. The stock
  ruleset contains a decoder for the discontinued **Zeus** web server that claims every line
  starting that way, and stock decoders always win over custom parent decoders. The NPM access
  decoders are therefore **children of the stock `zeus` decoder**: alerts show
  `decoder.name: zeus`, and the base rule `101700` chains off the stock Zeus grouping rule
  `31200`. Rules and the dashboard key on rule IDs and `data.npm.*` fields, so this is cosmetic.
  A compatibility child keeps the stock Zeus `host=` extraction working. Do not exclude the stock
  Zeus decoder.
- NPM error lines are decoded by the stock `nginx-errorlog` decoder. Two extra same-named sibling
  decoders add `npm.host`, `npm.method`, `url` and `npm.upstream`; stock fields and rules are
  unchanged (this also applies to any other nginx error log you collect).
- Lines that arrive **with a syslog header** are a separate case (see *Optional: syslog*): once
  Wazuh has extracted a program name, decoders without one are not tried, so that path has its
  own `npm-syslog` decoder and base rules `101717` / `101718`.

**Decoded fields** (indexed as `data.<name>`): `srcip`, `status`, `url`, `npm.method`,
`npm.scheme`, `npm.host`, `npm.upstream` (NPM's `Sent-to`), `npm.upstream_status`, `npm.cache`,
`npm.bytes`, `npm.user_agent`, `npm.referer`; on error lines `npm.host`, `npm.method`, `url`,
`npm.upstream` (and `npm.log_level` on the syslog path).

Because the client address is the canonical `srcip`, IP-IOC rules (for example the companion
[wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc) pack) and `same_source_ip`
frequency rules work on NPM traffic, and GeoIP enrichment applies.

## Alert rules

| Rule | Level | Event | MITRE |
|------|------|-------|-------|
| 101700 | 0 | NPM access line (base, file path; chains off stock 31200) | |
| 101717 | 0 | NPM access line (base, optional syslog path) | |
| 101701 | 3 | client error 4xx | |
| 101703 | 3 | access denied 401 / 403 | |
| 101702 | 5 | server error 5xx | |
| 101704 | 5 | upstream unavailable 502 / 503 / 504 | |
| 101705 | 2 | uptime-monitor check (Uptime-Kuma, UptimeRobot, Gatus, Pingdom, ...) with a 4xx/5xx — de-rated | |
| 101706 | 6 | probe for a sensitive / exploit path (`.env`, `.git/`, `wp-login.php`, `phpmyadmin`, traversal, `${jndi:` ...) | T1595.003 |
| 101707 | 6 | JNDI / lookup injection string anywhere in the request (e.g. User-Agent) | T1190 |
| 101708 | 8 | 5+ attack-path probes from one source in 120 s (vulnerability scan) | T1595.003 |
| 101709 | 6 | 20+ client errors on **different** URLs from one source in 60 s (content discovery) | T1595.003 |
| 101710 | 8 | 15+ 401/403 from one source in 120 s (possible brute force) | T1110 |
| 101711 | 7 | 10+ 502/503/504 for one host in 120 s (upstream outage) | |
| 101718 | 0 | NPM error-log line (base, optional syslog path) | |
| 101712 | 3 | error log: upstream unreachable / timed out / no live upstreams (child of stock 31301) | |
| 101713 | 3 | certificate probe result (base, `ok`) | |
| 101714 | 8 | certificate **expiring** (< 14 days) or **name mismatch** | |
| 101715 | 10 | certificate **critical** (< 3 days) or **expired** | |
| 101716 | 5 | certificate probe failed | |

Levels follow a triage gate of **L10** (≥10 reaches analyst triage). Internet-facing proxies are
scanned around the clock, and single-page apps with an expired session can emit dozens of 401s in
a second, so **no web detection reaches the gate on its own**: single probes are L6, composites
L6–L8. Only an imminent or actual certificate expiry (`101715`, near-zero false positives,
outage within days) is L10. Successful requests stay at L0 and are not stored as alerts.

Evaluation details that the rules rely on (verified with `wazuh-logtest` on 4.14.5):

- Sibling rules are tried highest level first. The attack-path / JNDI rules (L6) beat the
  4xx/5xx rules, so a spoofed monitor User-Agent cannot de-rate a probe.
- A frequency rule only counts events whose final rule was the counted ID. Monitor checks
  (`101705`) are therefore excluded from every composite on purpose, the scan composite counts
  4xx other than 401/403, and attack paths have their own composite (`101708`, counting `101706`;
  header-only JNDI strings `101707` stay single alerts).

Stock rules that already cover NPM error lines and are **not** duplicated here: `31315` (web
authentication failed — NPM access-list basic auth), `31316` (multiple web auth failures, L10),
`31301`–`31303` (nginx error/warn/crit).

**Rule IDs used:** `101700–101718`. Check for collisions with your existing custom rules before
installing:

```bash
docker exec wazuh.manager sh -c "grep -rlE 'rule id=\"1017(0[0-9]|1[0-8])\"' \
  /var/ossec/etc/rules/ | grep -v '/npm_rules.xml$'"   # expect no output
```
(Any file listed already uses one of these IDs — renumber one side.)

## Install / deploy

### 1. Install the decoders and rules on the manager (Docker)
```bash
docker cp npm_decoders.xml wazuh.manager:/var/ossec/etc/decoders/
docker cp npm_rules.xml    wazuh.manager:/var/ossec/etc/rules/
docker exec wazuh.manager chown wazuh:wazuh \
  /var/ossec/etc/decoders/npm_decoders.xml /var/ossec/etc/rules/npm_rules.xml
docker exec wazuh.manager /var/ossec/bin/wazuh-analysisd -t   # expect no errors
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```
(Bare-metal manager: copy to the same paths and run `/var/ossec/bin/wazuh-control restart`.)

### 2. Collect NPM's logs with the agent on the NPM host

Find NPM's data directory: the host path mounted at `/data` in the NPM container
(`docker inspect <npm container> --format '{{ range .Mounts }}{{ .Source }} -> {{ .Destination }}{{ "\n" }}{{ end }}'`).
Logs are in `<npm data dir>/logs/`. Add to the agent's `ossec.conf` (inside `<ossec_config>`), or
to a centralized `agent.conf` group (inside `<agent_config>`), replacing `/opt/npm/data`:

```xml
<!-- Nginx Proxy Manager: access logs (proxy hosts, redirection / 404 hosts, default + fallback) -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/npm/data/logs/*_access.log</location>
</localfile>
<!-- Nginx Proxy Manager: error logs -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/npm/data/logs/*_error.log</location>
</localfile>
```
Restart the agent. Wildcards pick up proxy hosts added later; rotated `.gz` files are ignored.
To collect proxy hosts only, use `proxy-host-*_access.log` / `proxy-host-*_error.log` instead.
Default/fallback logs are where scanners hitting your IP directly land, so they are worth keeping.

### 3. Optional: syslog instead of the agent

Use this only where no agent can run. Relay each log line over RFC 3164 syslog with program name
(tag) **`npm-proxy`** (or `npm`). Do **not** use a tag containing `nginx` or `apache` (such as
`nginx-npm`): the stock web-accesslog decoder claims those program names first and the lines
would never reach these decoders. Example with rsyslog on the NPM host:

```
module(load="imfile")
input(type="imfile" File="/opt/npm/data/logs/*_access.log" Tag="npm-proxy:" Ruleset="npm")
input(type="imfile" File="/opt/npm/data/logs/*_error.log"  Tag="npm-proxy:" Ruleset="npm")
ruleset(name="npm") {
  action(type="omfwd" Target="<WAZUH MANAGER IP>" Port="514" Protocol="udp"
         Template="RSYSLOG_TraditionalForwardFormat")
}
```
The manager must accept syslog from that host (a `<remote><connection>syslog</connection>` block
with your `<allowed-ips>`). Relays that escape double quotes (`\"`) are handled. On this path the
stock nginx error rules do not apply (error lines decode as `npm-syslog`); `101712` still fires.

### 4. Optional: certificate expiry poller

Run it on the NPM host (the agent forwards the output) or on any host that can reach NPM's TLS
port. It only ever connects to `--target`; each hostname just sets the SNI value. Certificates are
read without verification on purpose, so expired or mismatched ones are still reported.

```bash
sudo install -m 755 poller/npm_certs.py /usr/local/bin/npm_certs.py
# optional static list (one hostname per line):
sudo install -m 644 poller/npm-hosts.example /etc/npm-certs.hosts && sudoedit /etc/npm-certs.hosts
```
Hostname sources (any combination):

| Option | Source |
|--------|--------|
| `--hosts-file FILE` | one hostname per line |
| `--npm-conf GLOB` | `server_name` lines of NPM's generated configs, e.g. `'/opt/npm/data/nginx/proxy_host/*.conf'` (every proxy host, even without traffic) |
| `--npm-logs GLOB` | host field of NPM access logs, e.g. `'/opt/npm/data/logs/proxy-host-*_access.log'` |

Wildcard names and IP addresses are skipped; at most `--max-hosts` (500) are probed. Other options:
`--target HOST:PORT` (NPM's HTTPS listener, default `127.0.0.1:443`), `--out FILE` (default
`/var/log/npm-certs.json`, appended), `--warn-days 14`, `--crit-days 3`, `--timeout 10`.

Cron (daily):
```cron
20 6 * * *  /usr/bin/python3 /usr/local/bin/npm_certs.py --npm-conf '/opt/npm/data/nginx/proxy_host/*.conf' --hosts-file /etc/npm-certs.hosts --target 127.0.0.1:443 --out /var/log/npm-certs.json >/dev/null 2>>/var/log/npm-certs.err
```
Tell the agent (or the manager, if the poller runs there) to read the feed:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/npm-certs.json</location>
</localfile>
```
Each run writes one line per host:
`{"integration":"npm-certs","npm_cert":{"host":"app.example.com","target":"127.0.0.1:443","status":"ok","days_left":56,"issuer":"Let's Encrypt","not_after":"2027-03-01T00:00:00Z","san":"app.example.com"}}`.
`status` is `ok`, `expiring`, `critical`, `expired`, `name_mismatch` (dates fine but no SAN covers
the host) or `probe_error` (with `error`). Rotate the file with logrotate `copytruncate`.

Unit tests (no network): `python3 -m unittest discover -s poller/tests`.

### 5. Import the dashboard
```bash
docker cp wazuh_npm_dashboard.ndjson wazuh.dashboard:/tmp/
docker exec wazuh.dashboard curl -sk -u <ADMIN>:<INDEXER_PASSWORD> \
  -X POST "https://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" --form file=@/tmp/wazuh_npm_dashboard.ndjson
```
Regenerate after editing panels: `python3 gen_npm_dashboard.py` (stdlib only). New fields
(`data.npm.*`, `data.npm_cert.*`) appear in panels after the `wazuh-alerts-*` index pattern's field
list is refreshed once they have been indexed.

## Notes & tuning

- **Validate decoders:** paste a line from your `proxy-host-N_access.log` into `wazuh-logtest`;
  it should show `npm.host`, `srcip`, `status` and end at `101700` (2xx) or a higher rule.
- **Real client IPs:** NPM logs the address it sees. If NPM sits behind another proxy, CDN or a
  Docker userland proxy, `[Client ...]` may be that hop; configure NPM / Docker so the real client
  address reaches nginx, otherwise per-source rules see one IP for everyone.
- **Probe paths (`101706`):** if you host WordPress or phpMyAdmin behind NPM, remove the
  `wp-login.php` / `xmlrpc.php` / `phpmyadmin` alternatives from the rule's `<url>` pattern.
- **Uptime monitors (`101705`):** add your monitor's User-Agent to the pattern. The de-rate only
  touches 4xx/5xx status rules; probes and JNDI strings are never de-rated.
- **Thresholds:** brute force `101710` 15/120 s, scan `101709` 20/60 s, probe burst `101708`
  5/120 s, outage `101711` 10/120 s per host. On an internal-only proxy you can raise
  `101708`/`101710` to L10; on a busy public one, raise the frequencies instead.
- **Certificate thresholds:** `--warn-days` / `--crit-days` on the poller; the rules key on the
  reported `status`, not on the numbers. An `expiring` or `name_mismatch` host re-alerts every run.
- **Duplicate signals:** a failing upstream produces a 502 access line (`101704`, L5) and an error
  line (`101712`, L3) per request; drop the error-log `<localfile>` if you only want one.

## Disclaimer

Provided as-is, with no warranty. Review and tune alert levels and suppression to your own
environment before relying on them.
