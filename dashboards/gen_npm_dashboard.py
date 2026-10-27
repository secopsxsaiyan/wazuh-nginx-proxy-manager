#!/usr/bin/env python3
"""Generate the 'Nginx Proxy Manager - Web Threats' dashboard NDJSON (stdlib only).

Same helpers / OSD 2.16 saved-object shapes as the other packs' generators. Every panel is scoped to
this pack's rule IDs (npm_rules.xml, 101700-101718).

NOTE: only alerts are indexed. Successful requests (101700/101717, L0) and de-rated uptime-monitor
checks (101705, L2) stay below the default alert threshold (L3) and therefore never reach
wazuh-alerts-*; the status / client / host panels show the 4xx/5xx and detection subset, which is
what matters for triage. Attack-path, brute-force, scan, outage and certificate panels are
forward-looking on a quiet proxy and populate when the event first occurs (rule paths are validated
with wazuh-logtest). Client IPs are the canonical srcip, so the GeoLocation column populates for
routable clients when GeoIP is enabled."""
import json
ALERTS = "wazuh-alerts-*"
OSD = "2.16.0"
objects = []

def ss(query=""):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})

def viz(vid, title, vistype, aggs, params, query=""):
    # Tables need bucket aggs with schema "bucket" to split rows; "segment"/"group"
    # (right for pie/xy) make a table show only the metric count. Force "bucket".
    if vistype == "table":
        for _a in aggs:
            if _a.get("type") in ("terms", "date_histogram", "histogram") \
                    and _a.get("schema") in ("segment", "group"):
                _a["schema"] = "bucket"
    objects.append({"id": vid, "type": "visualization", "attributes": {
        "title": title, "visState": json.dumps({"title": title, "type": vistype, "aggs": aggs, "params": params}),
        "uiStateJSON": "{}", "description": "", "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": ss(query)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": ALERTS}]})
    return vid

def dash(did, title, panels, desc=""):
    pj, refs = [], []
    for i, v in enumerate(panels):
        pi = str(i)
        pj.append({"version": OSD, "gridData": {"x": (i % 2) * 24, "y": (i // 2) * 15, "w": 24, "h": 15, "i": pi},
                   "panelIndex": pi, "embeddableConfig": {}, "panelRefName": "panel_" + pi})
        refs.append({"name": "panel_" + pi, "type": "visualization", "id": v})
    objects.append({"id": did, "type": "dashboard", "attributes": {
        "title": title, "hits": 0, "description": desc, "panelsJSON": json.dumps(pj),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}), "version": 1, "timeRestore": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
        "references": refs})

def count(i="1"): return {"id": i, "enabled": True, "type": "count", "schema": "metric", "params": {}}
def terms(i, f, n=10, schema="segment"): return {"id": i, "enabled": True, "type": "terms", "schema": schema,
    "params": {"field": f, "orderBy": "1", "order": "desc", "size": n, "otherBucket": False,
               "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing"}}
def datehist(i): return {"id": i, "enabled": True, "type": "date_histogram", "schema": "segment",
    "params": {"field": "@timestamp", "useNormalizedEsInterval": True, "interval": "auto",
               "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}
def p_table(): return {"perPage": 12, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "sort": {"columnIndex": None, "direction": None}, "showTotal": True, "totalFunc": "sum", "percentageCol": ""}
def p_pie(): return {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}
def p_metric(sub): return {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {
    "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
    "colorsRange": [{"from": 0, "to": 1000000}], "labels": {"show": True}, "invertColors": False,
    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": sub, "fontSize": 40}}}
def p_area():
    return {"type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {},
            "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
            "style": {}, "scale": {"type": "linear", "mode": "normal"},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "events"}}],
        "seriesParams": [{"show": True, "type": "area", "mode": "stacked", "data": {"label": "Count", "id": "1"},
            "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True,
            "interpolate": "linear"}], "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {}, "thresholdLine": {"show": False, "value": 10, "width": 1,
            "style": "full", "color": "#E7664C"}}

# ---- query scopes (rule IDs from npm_rules.xml; data.* paths are the indexed alert fields) ----
ACCESS   = "rule.id:(101701 or 101702 or 101703 or 101704 or 101706 or 101707 or 101708 or 101709 or 101710 or 101711)"
ERRORS   = "rule.id:(101701 or 101702 or 101703 or 101704)"           # 4xx / 5xx (non-monitor)
SERVER   = "rule.id:(101702 or 101704 or 101711 or 101712)"           # 5xx, outages, upstream errors
ATTACK   = "rule.id:(101706 or 101707 or 101708)"                     # probe paths / JNDI / probe bursts
COMPOS   = "rule.id:(101708 or 101709 or 101710)"                     # scan + brute-force composites
BRUTE    = "rule.id:(101703 or 101710)"                               # 401/403 + brute force
OUTAGE   = "rule.id:(101711 or 101712)"
CERT     = "rule.id:(101713 or 101714 or 101715 or 101716)"
CERTBAD  = "rule.id:(101714 or 101715 or 101716)"
NOTABLE  = "rule.id:(101706 or 101707 or 101708 or 101709 or 101710 or 101711 or 101714 or 101715 or 101716)"

# Row 1 - headline KPIs
viz("npm-kpi-attacks", "Attack / scan / brute-force alerts", "metric",
    [count("1")], p_metric("probe paths, JNDI, scans, 401/403 bursts"), query="rule.id:(101706 or 101707 or 101708 or 101709 or 101710)")
viz("npm-kpi-ops", "Upstream outages & certificate problems", "metric",
    [count("1")], p_metric("5xx bursts, expiring / expired certs, probe errors"), query="rule.id:(101711 or 101714 or 101715 or 101716)")
# Row 2 - trend + status mix
viz("npm-timeline", "Requests by status over time (4xx / 5xx / detections)", "area",
    [count("1"), datehist("2"), terms("3", "data.status", 10, schema="group")], p_area(), query=ACCESS)
viz("npm-status", "Status codes (alerting requests)", "pie",
    [count("1"), terms("2", "data.status", 12)], p_pie(), query=ACCESS)
# Row 3 - who / where
viz("npm-clients", "Top clients (canonical srcip - feeds IP-IOC rules + GeoIP)", "table",
    [count("1"), terms("2", "data.srcip", 20), terms("3", "GeoLocation.country_name", 1)], p_table(), query=ACCESS)
viz("npm-hosts", "Top proxy hosts by 4xx / 5xx", "table",
    [count("1"), terms("2", "data.npm.host", 20), terms("3", "data.status", 3)], p_table(), query=ERRORS)
# Row 4 - attacks
viz("npm-attack-paths", "Attack / probe paths (sensitive files, admin panels, traversal, JNDI)", "table",
    [count("1"), terms("2", "data.url", 20), terms("3", "data.srcip", 3)], p_table(), query=ATTACK)
viz("npm-composites", "Scan & brute-force alerts by source", "table",
    [count("1"), terms("2", "data.srcip", 15), terms("3", "rule.description", 3)], p_table(), query=COMPOS)
# Row 5 - auth + user agents
viz("npm-auth", "401 / 403 by host and client", "table",
    [count("1"), terms("2", "data.npm.host", 10), terms("3", "data.srcip", 5)], p_table(), query=BRUTE)
viz("npm-agents", "User agents behind attack paths and scans", "table",
    [count("1"), terms("2", "data.npm.user_agent", 15)], p_table(), query="rule.id:(101706 or 101707 or 101708 or 101709)")
# Row 6 - availability
viz("npm-5xx", "Server errors by host and upstream", "table",
    [count("1"), terms("2", "data.npm.host", 15), terms("3", "data.npm.upstream", 3), terms("4", "data.status", 3)],
    p_table(), query=SERVER)
viz("npm-outages", "Upstream outages (5xx bursts + error-log upstream failures)", "area",
    [count("1"), datehist("2"), terms("3", "data.npm.host", 8, schema="group")], p_area(), query=OUTAGE)
# Row 7 - certificates
viz("npm-certs", "TLS certificate expiry (latest probes)", "table",
    [count("1"), terms("2", "data.npm_cert.host", 50), terms("3", "data.npm_cert.status", 1),
     terms("4", "data.npm_cert.days_left", 1), terms("5", "data.npm_cert.not_after", 1)], p_table(), query=CERT)
viz("npm-cert-problems", "Certificate problems (expiring / critical / expired / mismatch / probe error)", "table",
    [count("1"), terms("2", "rule.description", 20), terms("3", "rule.level", 1)], p_table(), query=CERTBAD)
# Row 8 - notable
viz("npm-notable", "Notable NPM alerts (L>=6)", "table",
    [count("1"), terms("2", "rule.description", 15), terms("3", "rule.level", 1)], p_table(), query=NOTABLE)
viz("npm-methods", "Methods on attack paths and errors", "pie",
    [count("1"), terms("2", "data.npm.method", 10)], p_pie(), query=ACCESS)

dash("npm-web-threats", "Nginx Proxy Manager - Web Threats",
     ["npm-kpi-attacks", "npm-kpi-ops", "npm-timeline", "npm-status",
      "npm-clients", "npm-hosts", "npm-attack-paths", "npm-composites",
      "npm-auth", "npm-agents", "npm-5xx", "npm-outages",
      "npm-certs", "npm-cert-problems", "npm-notable", "npm-methods"],
     "Nginx Proxy Manager access/error logs and TLS certificate probes: 4xx/5xx by status, client "
     "(canonical srcip -> IP-IOC + GeoIP) and proxy host; probes for sensitive files, admin panels, "
     "path traversal and JNDI lookups; content-discovery scans and 401/403 brute force; upstream "
     "outages; certificate expiry. Successful requests and uptime-monitor checks are below the alert "
     "threshold and not shown. Several panels are forward-looking and populate when the event first "
     "occurs.")

with open("wazuh_npm_dashboard.ndjson", "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
print("wrote", len(objects), "objects (1 dashboard,", len(objects) - 1, "visualizations)")
