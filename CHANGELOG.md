# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-26

- Initial public release for Nginx Proxy Manager.
- Decoders for NPM's `proxy` and `standard` access-log formats (canonical `srcip`, `status`,
  `url`; `npm.method`, `npm.scheme`, `npm.host`, `npm.upstream`, `npm.upstream_status`,
  `npm.cache`, `npm.bytes`, `npm.user_agent`, `npm.referer`), collected by a Wazuh agent from
  NPM's log files; extra host / request / upstream fields on nginx error-log lines; an optional
  syslog path (program name `npm-proxy`).
- Rules `101700–101718`: 4xx (L3), 401/403 (L3), 5xx (L5), 502/503/504 (L5), uptime-monitor
  de-rate (L2), attack / probe paths (L6), JNDI lookup strings (L6), probe burst (L8), content
  discovery scan (L6), 401/403 brute force (L8), upstream outage (L7), error-log upstream failure
  (L3), certificate expiring / name mismatch (L8), critical / expired (L10), probe error (L5).
- Certificate expiry poller (`poller/npm_certs.py`, stdlib only): hostnames from a file, NPM's
  generated configs and/or access logs; configurable SNI target, thresholds and output file;
  JSON lines for a `<localfile>` json block. Includes unit tests and an example hostname list.
- "Nginx Proxy Manager - Web Threats" dashboard and its generator.
