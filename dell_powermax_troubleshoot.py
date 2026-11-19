import base64
import json
import platform
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ------------------------------- USER INPUTS (edit only these) -------------------------------
HOST = "your_host_ip"
USERNAME = r"your_username"  # keep the r prefix so a backslash (local\user) is not treated as an escape
PASSWORD = r"your_password"
PORTS = "your_port"  # Unisphere REST port, typically 8443. A single port or several, comma-separated.
# ---------------------------------------------------------------------------------------------

VERIFY_SSL = False
SCHEME = "https"
TIMEOUT = 20
API_VERSION = "103"  # last-resort fallback only, used if GET /version can't be reached/parsed at all
MAX_RECORDS = 10  # cap on records shown per endpoint (display trimming of raw list responses)
MAX_DEPENDENT_CALLS = 5  # cap on how many ids a list -> detail dependent call will try/take
MAX_PRINT = 500_000

# PowerMax/Unisphere REST uses plain HTTP Basic Auth on every call - confirmed from Dell's own shipping
# PyU4V client (rest_requests.py): no login/logout call, no session cookie, no CSRF token, unlike Unity XT.
# Content-Type is added per-call in call() only for methods that actually carry a body (POST) - the
# official doc's GET header table does not list Content-Type at all.
HEADERS = {"Accept": "application/json"}
SECRET_HEADERS = ("authorization",)
SUMMARY = []
CALLS = [0]


def say(line=""):
    SUMMARY.append(line)


def safe(label, fn, *args, **kwargs):
    """Run one step; on any error note it in the summary and carry on, so the script always runs to the end."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        say("  [%s] step failed, continuing: %s: %s" % (label, type(e).__name__, e))
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects, so the credentials are only ever sent to the configured host."""

    def redirect_request(self, *args, **kwargs):
        return None


def build_opener():
    ctx = ssl.create_default_context()
    if not VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())


def q(path):
    """URL-encode a path+query that may contain literal characters such as the audit log's `>`/`<`."""
    if "?" not in path:
        return urllib.parse.quote(path, safe="/")
    base, query = path.split("?", 1)
    return urllib.parse.quote(base, safe="/") + "?" + urllib.parse.quote(query, safe="/?&=,:()@")


def trim_lists(obj, cap):
    """Recursively cap every list at `cap` items, regardless of which field name a given PowerMax endpoint
    happens to nest its records under (symmetrixId, resultList.result, ...). Applied right after the
    response is parsed, so this IS the data the script keeps and works with from here on - not just a
    display trim - and the full (capped) result can be printed as-is with nothing left unshown."""
    if isinstance(obj, list):
        return [trim_lists(x, cap) for x in obj[:cap]]
    if isinstance(obj, dict):
        return {k: trim_lists(v, cap) for k, v in obj.items()}
    return obj


def call(opener, base, path, method="GET", basic=None, body=None, show_body=True):
    """Send one request, write its details to the log and return dict(status, headers, body, json, error)."""
    hdrs = dict(HEADERS)
    if method == "POST":
        hdrs["Content-Type"] = "application/json"
    if basic:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % basic).encode("utf-8")).decode("ascii")
    data = b"" if method == "POST" else None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    out = {"status": None, "headers": {}, "body": "", "json": None, "error": None, "elapsed": 0.0}
    start = time.time()
    try:
        req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
        resp = opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception as e:
        resp = None
        out["error"] = "%s: %s" % (type(e).__name__, e)
    if resp is not None:
        try:
            out["status"] = resp.getcode()
            out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            out["body"] = resp.read(2_000_000).decode("utf-8", "replace")
            parsed = json.loads(out["body"]) if out["body"] else None
            # PowerMax has no documented way to ask the array for fewer than its default page (maxPageSize,
            # typically 1000) on the initial list/metrics call - only a separate follow-up Iterator/page
            # call can narrow a range. So cap to MAX_RECORDS right here instead: this becomes the data the
            # rest of the script keeps and works with, and the full (already-capped) result can be printed
            # as-is with nothing left unshown.
            out["json"] = trim_lists(parsed, MAX_RECORDS) if parsed is not None else None
        except json.JSONDecodeError:
            pass
        except Exception as e:
            out["error"] = "%s: %s" % (type(e).__name__, e)
    out["elapsed"] = time.time() - start
    safe("log", log_call, method, base + path, hdrs, body, out, show_body)
    return out


def log_call(method, url, hdrs, body, out, show_body):
    CALLS[0] += 1
    print("-" * 100)
    print("[CALL %d] %s %s" % (CALLS[0], method, url))
    shown = ["%s: %s" % (k, "<redacted>" if k.lower() in SECRET_HEADERS else v) for k, v in hdrs.items()]
    print("Request headers: %s" % ", ".join(shown))
    if body is not None:
        print("Request body: %s" % json.dumps(body))
    if out["status"] is None:
        print("Response: NO RESPONSE (%s) after %.2f s" % (out["error"], out["elapsed"]))
        return
    meta = ["HTTP %s" % out["status"], "%d characters" % len(out["body"]), "%.2f s" % out["elapsed"]]
    if out["error"]:
        meta.append("read error: %s" % out["error"])
    print("Response: %s" % " | ".join(meta))
    if not show_body:
        print("Response body: not shown")
        return
    text = json.dumps(out["json"], indent=2, ensure_ascii=False) if out["json"] is not None else out["body"]
    if len(text) > MAX_PRINT:
        text = text[:MAX_PRINT] + "\n... (truncated, %d more characters)" % (len(text) - MAX_PRINT)
    print("Response body:\n%s" % text)


def host_name():
    """HOST without a scheme, path or port, in case a URL was pasted."""
    import re

    host = re.sub(r"^[A-Za-z]+://", "", str(HOST).strip()).split("/")[0]
    return host.split(":")[0] if host.count(":") == 1 else host


def port_list():
    """Parse the PORTS USER INPUT - a single port or several, comma-separated - into a list of ints."""
    ports = []
    for part in str(PORTS).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except ValueError:
            print("  ignoring invalid port %r (not a number)" % part)
    return ports


def short(r):
    return "NO RESPONSE (%s)" % r["error"] if r["status"] is None else "HTTP %s" % r["status"]


def is_empty(j):
    """Whether a response body should be treated as having no usable data for the dependent-call logic."""
    if j is None:
        return True
    if isinstance(j, list):
        return len(j) == 0
    if isinstance(j, dict):
        if "count" in j:
            try:
                return int(j.get("count") or 0) == 0
            except (TypeError, ValueError):
                pass
        return len(j) == 0
    return False


def list_ids(json_obj, key=None, item_id_keys=None, nested_path=None):
    """Extract a list of ids from a PowerMax list-style response, whatever shape it comes back in:
    a flat `{key: [...]}` array of ids (symmetrixId, directorId, storageGroupId, ...), a paginated
    `{"resultList": {"result": [...]}}` envelope (volume, audit log), or a list of dicts where the id
    is one of several possible field names (item_id_keys)."""
    if nested_path:
        obj = json_obj
        for p in nested_path:
            obj = obj.get(p) if isinstance(obj, dict) else None
        items = obj if isinstance(obj, list) else []
    else:
        items = json_obj.get(key) if isinstance(json_obj, dict) else None
        items = items if isinstance(items, list) else []

    ids = []
    for it in items:
        if isinstance(it, dict):
            picked = None
            for k in (item_id_keys or []):
                if k in it:
                    picked = it[k]
                    break
            if picked is None and len(it) == 1:
                picked = next(iter(it.values()))
            if picked is not None:
                ids.append(picked)
        elif it is not None:
            ids.append(it)
    return ids


def pmax_call(opener, base, creds, res, path, method="GET", body=None, label=None, show_body=True):
    res["endpoints_total"] += 1
    r = call(opener, base, q(path), method=method, basic=creds, body=body, show_body=show_body)
    if r["status"] != 200:
        res["endpoints_failed"].append(label or path)
    return r


def vpath(template, *args):
    """Build a `version -> path` function from a template whose first %s is the version segment,
    e.g. vpath("/%s/system/symmetrix/%s/health", array_id) -> lambda v: "/<v>/system/symmetrix/<array_id>/health".
    Used so every versioned call site can be tried against each API version PowerMax reports as supported."""
    return lambda v: template % ((v,) + args)


def versioned_call(opener, base, creds, res, build_path, method="GET", body=None, label=None, show_body=True):
    """Try build_path(v) for each API version Unisphere reported as supported (newest first, from
    discover_api_versions), stopping at the first HTTP 200. Counts/reports the endpoint once either way,
    not once per version probed, so trying 3 versions doesn't look like 3 failed endpoints in the summary."""
    versions = res.get("api_versions") or [API_VERSION]
    tried = []
    r = None
    for v in versions:
        r = call(opener, base, q(build_path(v)), method=method, basic=creds, body=body, show_body=show_body)
        tried.append(v)
        if r["status"] == 200:
            r["version_used"] = v
            r["versions_tried"] = tried
            res["endpoints_total"] += 1
            return r
        if r["status"] is None:
            break  # connection/timeout-level failure - same for every version, no point retrying the others
    r["versions_tried"] = tried
    res["endpoints_total"] += 1
    r["version_used"] = None
    res["endpoints_failed"].append(label or build_path(versions[0]))
    return r


def first_working(opener, base, creds, res, ids, path_fn, label):
    """Array-id discovery only: try each id in turn and stop at the first one that actually has data -
    here we just need one working array to operate on, not a sample of records."""
    last = None
    for _id in ids[:MAX_DEPENDENT_CALLS]:
        build_path = path_fn(_id)
        r = versioned_call(opener, base, creds, res, build_path, label="%s (id=%s)" % (label, _id))
        has_data = r["status"] == 200 and not is_empty(r["json"])
        say("  [PowerMax] GET %-70s (%s, id=%s) -> %s%s"
            % (build_path(r["version_used"] or r["versions_tried"][0]), label, _id, short(r),
               ", has data - stopping here" if has_data else ""))
        last = (_id, r)
        if has_data:
            return last
    return last


def all_working(opener, base, creds, res, ids, path_fn, label, cap=MAX_DEPENDENT_CALLS):
    """All list -> detail dependent calls: pull up to `cap` detail records, not just the first one, so
    every distinct id the list turned up gets its own sample - naturally falls back to fewer if fewer
    than `cap` ids exist."""
    out = []
    for _id in ids[:cap]:
        build_path = path_fn(_id)
        r = versioned_call(opener, base, creds, res, build_path, label="%s (id=%s)" % (label, _id))
        say("  [PowerMax] GET %-70s (%s, id=%s) -> %s"
            % (build_path(r["version_used"] or r["versions_tried"][0]), label, _id, short(r)))
        out.append((_id, r))
    return out


def pick_best(results):
    """From an all_working() result list, pick the single id to reuse for a later downstream call
    (e.g. the storage group id reused by Performance/Data Protection): the first id with non-empty
    data, else just the first id tried, else None if nothing was tried at all."""
    if not results:
        return None
    for _id, r in results:
        if r["status"] == 200 and not is_empty(r["json"]):
            return _id
    return results[0][0]


# ------------------------------------------- endpoint groups -------------------------------------------

def discover_api_versions(opener, base, creds, res):
    """GET /version (itself unversioned) to learn which API versions this Unisphere actually supports,
    newest first, so every later versioned_call() tries the latest first and falls back on failure
    instead of assuming a single hardcoded version."""
    r = pmax_call(opener, base, creds, res, "/version", label="API version discovery")
    versions = None
    if isinstance(r["json"], dict):
        raw = r["json"].get("supported_api_versions")
        if isinstance(raw, list) and raw:
            try:
                versions = sorted({str(v) for v in raw}, key=lambda s: int(s), reverse=True)
            except (TypeError, ValueError):
                versions = [str(v) for v in raw]
    if not versions:
        versions = [API_VERSION]
        say("  [PowerMax] could not discover supported API versions (%s) - falling back to %s"
            % (short(r), API_VERSION))
    else:
        unisphere_version = r["json"].get("version", "?") if isinstance(r["json"], dict) else "?"
        say("  [PowerMax] Unisphere %s reports supported API versions: %s" % (unisphere_version, ", ".join(versions)))
    res["api_versions"] = versions
    return versions


def discover_array_id(opener, base, creds, res):
    build_path = vpath("/%s/sloprovisioning/symmetrix")
    r = versioned_call(opener, base, creds, res, build_path, label="symmetrix list")
    ids = list_ids(r["json"], "symmetrixId")
    say("  [PowerMax] GET %s -> %s, %d array id(s) found"
        % (build_path(r["version_used"] or r["versions_tried"][0]), short(r), len(ids)))
    if not ids:
        return None
    picked = first_working(
        opener, base, creds, res, ids,
        lambda aid: vpath("/%s/system/symmetrix/%s/health", aid),
        "array health (validating array id)")
    return picked[0] if picked else ids[0]


def health_hardware(opener, base, creds, res, array_id):
    say("  -- Health & Hardware --")
    versioned_call(opener, base, creds, res, vpath("/%s/system/symmetrix/%s/health", array_id), label="array health")

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/system/symmetrix/%s/health/health_check", array_id), label="health check list")
    health_check_ids = list_ids(r["json"], "health_check_id")
    say("  [PowerMax] %d health check id(s) found" % len(health_check_ids))
    all_working(
        opener, base, creds, res, health_check_ids,
        lambda h: vpath("/%s/system/symmetrix/%s/health/health_check/%s", array_id, h),
        "health check detail")

    r = versioned_call(
        opener, base, creds, res, vpath("/%s/system/symmetrix/%s/director", array_id), label="director list")
    dir_ids = list_ids(r["json"], "directorId")
    say("  [PowerMax] %d director id(s) found" % len(dir_ids))
    dir_results = all_working(
        opener, base, creds, res, dir_ids,
        lambda d: vpath("/%s/system/symmetrix/%s/director/%s", array_id, d),
        "director detail")
    dir_id = pick_best(dir_results)

    if not dir_id:
        say("  [PowerMax] no director id available - skipping port detail calls")
        return

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/system/symmetrix/%s/director/%s/port", array_id, dir_id), label="director port list")
    port_ids = list_ids(r["json"], "symmetrixPortKey", item_id_keys=["portId"])
    say("  [PowerMax] %d port id(s) found on director %s" % (len(port_ids), dir_id))
    all_working(
        opener, base, creds, res, port_ids,
        lambda p: vpath("/%s/system/symmetrix/%s/director/%s/port/%s", array_id, dir_id, p),
        "director port detail")


def capacity_planning(opener, base, creds, res, array_id):
    say("  -- Capacity Planning --")
    versioned_call(
        opener, base, creds, res,
        vpath("/%s/sloprovisioning/symmetrix/%s", array_id), label="symmetrix (array) detail")

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/sloprovisioning/symmetrix/%s/srp", array_id), label="srp list")
    srp_ids = list_ids(r["json"], "srpId")
    say("  [PowerMax] %d SRP id(s) found" % len(srp_ids))
    all_working(
        opener, base, creds, res, srp_ids,
        lambda s: vpath("/%s/sloprovisioning/symmetrix/%s/srp/%s", array_id, s), "SRP detail")

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/sloprovisioning/symmetrix/%s/storagegroup", array_id), label="storage group list")
    sg_ids = list_ids(r["json"], "storageGroupId")
    say("  [PowerMax] %d storage group id(s) found" % len(sg_ids))
    sg_results = all_working(
        opener, base, creds, res, sg_ids,
        lambda s: vpath("/%s/sloprovisioning/symmetrix/%s/storagegroup/%s", array_id, s),
        "storage group detail")
    res["sg_id"] = pick_best(sg_results)

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/sloprovisioning/symmetrix/%s/volume", array_id), label="volume list")
    volume_ids = list_ids(r["json"], nested_path=("resultList", "result"), item_id_keys=["volumeId"])
    say("  [PowerMax] %d volume id(s) found" % len(volume_ids))
    all_working(
        opener, base, creds, res, volume_ids,
        lambda v: vpath("/%s/sloprovisioning/symmetrix/%s/volume/%s", array_id, v), "volume detail")

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/system/symmetrix/%s/disk", array_id), label="disk list")
    disk_ids = list_ids(r["json"], "disk_ids")
    say("  [PowerMax] %d disk id(s) found" % len(disk_ids))
    all_working(
        opener, base, creds, res, disk_ids,
        lambda d: vpath("/%s/system/symmetrix/%s/disk/%s", array_id, d), "disk detail")


def performance(opener, base, creds, res, array_id):
    say("  -- Performance --")
    pmax_call(
        opener, base, creds, res,
        "/performance/Array/registration/%s" % array_id, label="array performance registration status")

    pmax_call(
        opener, base, creds, res,
        "/performance/Array/registrationdetails/%s" % array_id, label="array performance registration details")

    r = pmax_call(opener, base, creds, res, "/performance/Array/keys", label="array performance keys")
    last_ts = None
    arr_info = r["json"].get("arrayInfo") if isinstance(r["json"], dict) else None
    if isinstance(arr_info, list):
        for entry in arr_info:
            if isinstance(entry, dict) and str(entry.get("symmetrixId")) == str(array_id):
                last_ts = entry.get("lastAvailableDate")
                break
    say("  [PowerMax] last available performance timestamp for %s: %s" % (array_id, last_ts))

    r = pmax_call(
        opener, base, creds, res,
        "/performance/Array/help/%s/Array/metrics/Kpi" % array_id, label="array metric catalog (Kpi)")
    metric_names = list_ids(r["json"], "metricName") or ["PercentCacheWP"]

    if last_ts:
        body = {
            "symmetrixId": array_id, "startDate": last_ts, "endDate": last_ts,
            "dataFormat": "Average", "metrics": metric_names,
        }
        pmax_call(opener, base, creds, res, "/performance/Array/metrics", method="POST", body=body,
                 label="array metrics (POST)")
    else:
        say("  [PowerMax] skipping array metrics POST - no last-available timestamp discovered")

    sg_id = res.get("sg_id")
    if sg_id and last_ts:
        body = {
            "symmetrixId": array_id, "storageGroupId": sg_id,
            "startDate": last_ts, "endDate": last_ts,
            "dataFormat": "Average", "metrics": ["UnreducibleData"],
        }
        pmax_call(opener, base, creds, res, "/performance/StorageGroup/metrics", method="POST", body=body,
                 label="storage group metrics - UnreducibleData (POST)")
    else:
        say("  [PowerMax] skipping storage group metrics POST - no storage group id or timestamp available")

    pmax_call(
        opener, base, creds, res, "/performance/daystofull", method="POST",
        body={"symmetrixId": array_id, "category": "Array"}, label="days to full (POST)")

    r = pmax_call(
        opener, base, creds, res,
        "/performance/threshold/categories", label="threshold categories")
    cats = list_ids(r["json"], "endpoint")
    cat = cats[0] if cats else "Array"
    pmax_call(
        opener, base, creds, res,
        "/performance/threshold/list/%s/%s" % (array_id, cat), label="threshold settings for %s" % cat)


def alerts(opener, base, creds, res, array_id):
    say("  -- Alerts --")
    versioned_call(opener, base, creds, res, vpath("/%s/system/alert_summary"), label="alert summary")

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/system/alert?array=%s", array_id), label="alert list (unfiltered)")
    alert_ids = list_ids(r["json"], "alertId")
    say("  [PowerMax] %d alert id(s) found" % len(alert_ids))
    all_working(
        opener, base, creds, res, alert_ids,
        lambda a: vpath("/%s/system/alert/%s", a), "alert detail", cap=MAX_RECORDS)


def audit_logs(opener, base, creds, res, array_id):
    say("  -- Audit Logs --")
    now_s = int(time.time())
    start_s = now_s - 7 * 24 * 3600  # 7-day lookback to maximize the chance of finding real records
    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/system/symmetrix/%s/audit_log_record?entry_date=>%d&entry_date=<%d", array_id, start_s, now_s),
        label="audit log list (last 7 days)")
    record_ids = list_ids(r["json"], "record_id")
    say("  [PowerMax] %d audit log record id(s) found" % len(record_ids))
    all_working(
        opener, base, creds, res, record_ids,
        lambda rid: vpath("/%s/system/symmetrix/%s/audit_log_record/%s", array_id, rid),
        "audit log record detail", cap=MAX_RECORDS)


def data_protection(opener, base, creds, res, array_id):
    say("  -- Data Protection / Disaster Recovery --")
    sg_id = res.get("sg_id")
    if sg_id:
        r = versioned_call(
            opener, base, creds, res,
            vpath("/%s/replication/symmetrix/%s/storagegroup/%s/snapshot", array_id, sg_id),
            label="storage group snapshot list")
        snap_names = list_ids(r["json"], "name")
        say("  [PowerMax] %d snapshot name(s) found for storage group %s" % (len(snap_names), sg_id))
        all_working(
            opener, base, creds, res, snap_names,
            lambda n: vpath("/%s/replication/symmetrix/%s/storagegroup/%s/snapshot/%s/snapid",
                            array_id, sg_id, n),
            "snapshot snapid detail")
    else:
        say("  [PowerMax] no storage group id available - skipping snapshot calls")

    r = versioned_call(
        opener, base, creds, res,
        vpath("/%s/replication/symmetrix/%s/rdf_group", array_id), label="rdf group list")
    rdfg_ids = list_ids(r["json"], "rdfGroupID", item_id_keys=["rdfgNumber", "rdfGroupNumber", "number"])
    say("  [PowerMax] %d RDF group id(s) found" % len(rdfg_ids))
    all_working(
        opener, base, creds, res, rdfg_ids,
        lambda g: vpath("/%s/replication/symmetrix/%s/rdf_group/%s", array_id, g), "rdf group detail")


# ------------------------------------------------- run -------------------------------------------------

def new_result():
    return {"array_id": None, "sg_id": None, "api_versions": None, "endpoints_total": 0, "endpoints_failed": []}


def check_port(opener, port, creds, results):
    # Unisphere's REST app is mounted under /univmax/restapi - every path in the official doc
    # (e.g. /103/sloprovisioning/symmetrix) is relative to that, not to the bare host:port.
    base = "%s://%s:%d/univmax/restapi" % (SCHEME, host_name(), int(port))
    say("\n=== %s ===" % base)
    res = results[port] = new_result()

    safe("discover api versions", discover_api_versions, opener, base, creds, res)

    array_id = safe("discover array id", discover_array_id, opener, base, creds, res)
    if not array_id:
        say("  [PowerMax] no working array id found on this port - skipping remaining endpoints")
        return
    res["array_id"] = array_id
    say("  [PowerMax] using array id %s for all subsequent calls" % array_id)

    safe("Health & Hardware", health_hardware, opener, base, creds, res, array_id)
    safe("Capacity Planning", capacity_planning, opener, base, creds, res, array_id)
    safe("Performance", performance, opener, base, creds, res, array_id)
    safe("Alerts", alerts, opener, base, creds, res, array_id)
    safe("Audit Logs", audit_logs, opener, base, creds, res, array_id)
    safe("Data Protection / DR", data_protection, opener, base, creds, res, array_id)


def verdict(results):
    lines = []
    for port, res in results.items():
        if not res.get("array_id"):
            lines.append("port %d: could not discover/validate an array id - no endpoints were queried." % port)
            continue
        total, failed = res["endpoints_total"], res["endpoints_failed"]
        if not failed:
            lines.append("port %d: array %s, all %d endpoint calls returned HTTP 200." % (port, res["array_id"], total))
        else:
            lines.append(
                "port %d: array %s, %d/%d endpoint calls did not return HTTP 200: %s"
                % (port, res["array_id"], len(failed), total, ", ".join(failed)))
    return "\n".join(lines) if lines else "No ports were checked."


def print_summary(results):
    print("\n" + "=" * 100 + "\nSUMMARY\n" + "=" * 100)
    for line in SUMMARY:
        print(line)
    print("\n=== VERDICT ===")
    print(safe("verdict", verdict, results) or "Could not work out a verdict - please send the full output.")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    unchanged = [
        n for n, v in (("HOST", HOST), ("USERNAME", USERNAME), ("PASSWORD", PASSWORD), ("PORTS", PORTS))
        if str(v).startswith("your_")
    ]
    if unchanged:
        print("Edit the USER INPUTS at the top of the script first (still placeholder: %s)." % ", ".join(unchanged))
        return 1
    print("Run at %s UTC, Python %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), platform.python_version()))
    ports = port_list()
    if not ports:
        print("No valid ports parsed from PORTS=%r - edit the USER INPUTS at the top of the script." % PORTS)
        return 1
    print("Host %s, ports %s. API call details first, summary and verdict at the end." % (host_name(), ports))
    user = str(USERNAME)
    say("Username as sent: %r (length %d)" % (user, len(user)))

    opener, creds, results = build_opener(), (user, str(PASSWORD)), {}
    for port in ports:
        safe("port %s" % port, check_port, opener, port, creds, results)
    safe("summary", print_summary, results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("Unexpected error, please send this output: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
