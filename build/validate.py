#!/usr/bin/env python3
"""VCIO CA Framework — release validator.
Fails the build on the defect classes that JSON-only baselines ship:
inert scopes, dangling GUIDs, encoding drift, exclusion-group reuse,
missing break-glass exclusions. Exit code 0 = clean, 1 = findings.
"""
import json, os, sys, glob, re

ROOT = os.path.join(os.path.dirname(__file__), "..")
findings = []
def fail(f, msg): findings.append(f"{os.path.relpath(f, ROOT)}: {msg}")

WELL_KNOWN_APPS = {
    "All", "None", "Office365", "MicrosoftAdminPortals", "AllAgentIdResources",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013", "0000000a-0000-0000-c000-000000000000",
    "d4ebce55-015a-49b5-a083-c84d1797ae8c", "2793995e-0a7d-40d7-bd35-6968ba142197",
    "00000002-0000-0ff1-ce00-000000000000", "00000003-0000-0ff1-ce00-000000000000",
    "REPLACE-WITH-APP-ID",
}
VALID_STATES = {"enabled", "disabled", "enabledForReportingButNotEnforced"}
BUILTIN_STRENGTHS = {"00000000-0000-0000-0000-000000000002",
                     "00000000-0000-0000-0000-000000000003",
                     "00000000-0000-0000-0000-000000000004"}

def APP_PLACEHOLDER_CHECK(apps):
    vals = (apps.get("includeApplications") or []) + (apps.get("excludeApplications") or [])
    return "REPLACE-WITH-APP-ID" in vals

def load(path):
    raw = open(path, "rb").read()
    if raw[:3] == b"\xef\xbb\xbf":
        fail(path, "UTF-8 BOM present — files must be UTF-8 without BOM")
        raw = raw[3:]
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        fail(path, "UTF-16 encoding — files must be UTF-8")
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        fail(path, f"JSON parse error: {e}")
        return None

# --- collect groups and named locations ---
groups = {}
for f in glob.glob(os.path.join(ROOT, "Config/Groups/*.json")):
    g = load(f)
    if g: groups[g["id"]] = g["displayName"]
locations = {}
for f in glob.glob(os.path.join(ROOT, "Config/NamedLocations/*.json")):
    n = load(f)
    if n: locations[n["id"]] = n["displayName"]

bg_id = next((i for i, n in groups.items() if n == "SG-CA-BreakGlass"), None)
if not bg_id:
    findings.append("SG-CA-BreakGlass group missing from Config/Groups")

# --- migration table consistency ---
mt = load(os.path.join(ROOT, "Config/MigrationTable.json"))
if mt:
    mt_ids = {o["Id"] for o in mt["Objects"]}
    for gid_, name in groups.items():
        if gid_ not in mt_ids:
            findings.append(f"MigrationTable missing group: {name}")

# --- policies ---
excl_usage = {}
policy_files = (glob.glob(os.path.join(ROOT, "Config/ConditionalAccess/*.json"))
                + glob.glob(os.path.join(ROOT, "Config-Overlay-P2/ConditionalAccess/*.json"))
                + glob.glob(os.path.join(ROOT, "Templates/ConditionalAccess/*.json"))
                + glob.glob(os.path.join(ROOT, "Transition/ConditionalAccess/*.json")))
seen_numbers = {}
for f in sorted(policy_files):
    p = load(f)
    if not p: continue
    name = p.get("displayName", "")
    is_template = "Templates" in f or "Transition" in f  # variants share numbers/groups with counterparts

    # filename <-> displayName
    if os.path.basename(f) != name + ".json":
        fail(f, f"filename does not match displayName '{name}'")
    m = re.match(r"^CA(\d{3})-VCIO-", name)
    if not m:
        fail(f, "displayName does not match CAnnn-VCIO-* convention")
    else:
        n = m.group(1)
        if n in seen_numbers and not is_template:
            fail(f, f"duplicate policy number CA{n} (also {seen_numbers[n]})")
        seen_numbers[n] = name

    if p.get("state") not in VALID_STATES:
        fail(f, f"invalid state '{p.get('state')}'")

    cond = p.get("conditions", {})
    apps = cond.get("applications", {}) or {}
    users = cond.get("users", {}) or {}

    # THE CA104 CLASS: inert application scope
    inc_apps = apps.get("includeApplications", [])
    inc_actions = apps.get("includeUserActions", [])
    if inc_apps == ["None"] and not inc_actions:
        has_agent_scope = bool(cond.get("agents") or cond.get("clientApplications")
                               or cond.get("agentIdRiskLevels"))
        if not has_agent_scope:
            fail(f, "INERT POLICY: includeApplications=['None'] with no user action or agent scope")
    if not inc_apps and not inc_actions:
        fail(f, "no application or user-action scope at all")

    # user scope must exist
    has_user_scope = (users.get("includeUsers") or users.get("includeGroups")
                      or users.get("includeRoles") or users.get("includeGuestsOrExternalUsers"))
    if not has_user_scope:
        fail(f, "no user scope (includeUsers/Groups/Roles/Guests all empty)")

    # must do something
    g = p.get("grantControls")
    s = p.get("sessionControls")
    active_session = s and any(v for k, v in s.items() if not k.startswith("@") and v)
    if not g and not active_session:
        fail(f, "policy has neither grant controls nor active session controls")
    if g and not g.get("builtInControls") and not g.get("authenticationStrength"):
        fail(f, "grantControls present but empty (no builtInControls, no authenticationStrength)")
    if g and g.get("authenticationStrength"):
        if g["authenticationStrength"]["id"] not in BUILTIN_STRENGTHS:
            fail(f, f"unknown authentication strength id {g['authenticationStrength']['id']}")

    # GUID wiring: groups
    for key in ("includeGroups", "excludeGroups"):
        for gid_ in users.get(key, []) or []:
            if gid_ not in groups:
                fail(f, f"{key} references unknown group {gid_}")
            if (key == "excludeGroups" and gid_ in groups
                    and groups[gid_].startswith("SG-CA-Excl-") and not is_template):
                excl_usage.setdefault(gid_, []).append(name)

    # GUID wiring: locations
    loc = cond.get("locations")
    if loc:
        for key in ("includeLocations", "excludeLocations"):
            for lid in loc.get(key, []) or []:
                if lid not in locations and lid not in ("All", "AllTrusted"):
                    fail(f, f"{key} references unknown named location {lid}")

    # app IDs sane
    guid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    for key in ("includeApplications", "excludeApplications"):
        for a in apps.get(key, []) or []:
            if a not in WELL_KNOWN_APPS and not guid_re.match(a):
                fail(f, f"{key} contains unrecognized app reference '{a}'")
    if not is_template and APP_PLACEHOLDER_CHECK(apps):
        fail(f, "placeholder app id present outside Templates/")

    # break-glass excluded from every user-scoped, non-agent policy
    is_agent = bool(cond.get("agents") or cond.get("clientApplications") or cond.get("agentIdRiskLevels")) \
               or users.get("includeUsers") == ["None"]
    if bg_id and not is_agent and bg_id not in (users.get("excludeGroups") or []):
        fail(f, "break-glass group not excluded")

# exclusion group reuse (the chaining defect)
for gid_, used_by in excl_usage.items():
    if len(used_by) > 1:
        findings.append(f"exclusion group {groups[gid_]} reused by multiple policies: {used_by}")
# every Excl group used exactly once
for gid_, gname in groups.items():
    if gname.startswith("SG-CA-Excl-") and gid_ not in excl_usage:
        findings.append(f"orphaned exclusion group: {gname}")

print(f"Checked {len(policy_files)} policies, {len(groups)} groups, {len(locations)} named locations.")
if findings:
    print(f"\n{len(findings)} FINDINGS:")
    for x in findings: print("  -", x)
    sys.exit(1)
print("CLEAN — release gate passed.")
