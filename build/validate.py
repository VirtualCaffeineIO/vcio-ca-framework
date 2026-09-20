#!/usr/bin/env python3
"""VCIO CA Framework — release validator.
Fails the build on the defect classes that JSON-only baselines ship:
inert scopes, dangling GUIDs, encoding drift, exclusion-group reuse,
missing break-glass exclusions. Exit code 0 = clean, 1 = findings.

This is the RELEASE validator: it runs in CI against the repo tree.
Tools/Test-VcioCaBaseline.ps1 is the operator's DRIFT validator and runs
against a tenant export with the deployment manifest. They have different
jobs, but the structural rules below are implemented in both, and CI runs
both against this tree so they cannot disagree.

Neither validator gates on a policy COUNT. Each checks that every required
policy identity is present by displayName pattern and that the structural
relationships hold. The tree count is printed for information only.
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

# C5 — the one device-filter string any standard policy may carry.
FILTER_COMPLIANT = 'device.isCompliant -eq True'

# Required policy identities, by folder, as displayName patterns. Presence is
# checked; the count is not.
def _each(*nums):
    return [rf"^CA{x}-VCIO-" for x in nums]

REQUIRED = {
    "Config/ConditionalAccess": _each(
        "000", "001", "002", "003", "004", "005", "006", "007",
        "100", "101", "102", "103",
        "200", "201", "202", "203", "204",
        "300", "301",
        "400", "401", "402", "403",
        "500", "501",
        "600", "601", "602"),
    "Config-Overlay-P2/ConditionalAccess": _each(
        "700", "701", "702", "703", "704", "705"),
    "Templates/ConditionalAccess": [
        r"^CA500-VCIO-ServiceAccounts-IPFence-SYSTEMNAME$",
        r"^CA501-VCIO-ServiceAccounts-RestrictApps-SYSTEMNAME$",
    ] + _each("800", "801", "802", "803"),
    # A10 — the four transition variants pair with the four standard policies
    # that exclude SG-CA-Transition-Hybrid. A missing pair is a coverage hole.
    "Transition/ConditionalAccess": [
        r"^CA200-VCIO-.*-TRANSITION$", r"^CA204-VCIO-.*-TRANSITION$",
        r"^CA300-VCIO-.*-TRANSITION$", r"^CA301-VCIO-.*-TRANSITION$",
    ],
}
# Standard policies that must exclude the transition group, and the transition
# variants that must include it (A10).
TRANSITION_EXCLUDERS = {"200", "204", "300", "301"}


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
# Core objects import into the tenant. Template-scope objects live under
# Templates/ so the shipped SYSTEMNAME templates have resolvable references;
# they are never bulk-imported and never in the MigrationTable.
groups, core_groups = {}, {}
for f in glob.glob(os.path.join(ROOT, "Config/Groups/*.json")):
    g = load(f)
    if g: groups[g["id"]] = g["displayName"]; core_groups[g["id"]] = g["displayName"]
for f in glob.glob(os.path.join(ROOT, "Templates/Groups/*.json")):
    g = load(f)
    if g: groups[g["id"]] = g["displayName"]
locations = {}
for f in (glob.glob(os.path.join(ROOT, "Config/NamedLocations/*.json"))
          + glob.glob(os.path.join(ROOT, "Templates/NamedLocations/*.json"))):
    n = load(f)
    if n: locations[n["id"]] = n["displayName"]

def group_id(name):
    return next((i for i, n in groups.items() if n == name), None)

bg_id = group_id("SG-CA-BreakGlass")
if not bg_id:
    findings.append("SG-CA-BreakGlass group missing from Config/Groups")
sa_id = group_id("SG-CA-ServiceAccounts")
transition_id = group_id("SG-CA-Transition-Hybrid")
if not transition_id:
    findings.append("SG-CA-Transition-Hybrid group missing from Config/Groups (A10)")
priv_id = group_id("SG-CA-Privileged")
if not priv_id:
    findings.append("SG-CA-Privileged group missing from Config/Groups (A8)")

# --- migration table consistency (core groups only) ---
mt = load(os.path.join(ROOT, "Config/MigrationTable.json"))
if mt:
    mt_ids = {o["Id"] for o in mt["Objects"]}
    for gid_, name in core_groups.items():
        if gid_ not in mt_ids:
            findings.append(f"MigrationTable missing group: {name}")
    for gid_ in mt_ids - set(core_groups):
        findings.append(f"MigrationTable references a group not in Config/Groups: {gid_}")

# --- policies ---
excl_usage = {}
group_usage = {}
policy_dirs = ["Config/ConditionalAccess", "Config-Overlay-P2/ConditionalAccess",
               "Templates/ConditionalAccess", "Transition/ConditionalAccess"]
policy_files = [f for d in policy_dirs
                for f in glob.glob(os.path.join(ROOT, d, "*.json"))]
seen_numbers = {}
present = {d: [] for d in policy_dirs}

for f in sorted(policy_files):
    p = load(f)
    if not p: continue
    name = p.get("displayName", "")
    rel = os.path.relpath(f, ROOT).replace(os.sep, "/")
    folder = os.path.dirname(rel)
    present.setdefault(folder, []).append(name)
    is_template_dir = "Templates/" in rel
    is_transition = "Transition/" in rel
    # Variants and templates share policy numbers with their counterparts.
    shares_number = is_template_dir or is_transition

    # A shipped template still carries its placeholder; anything else under a
    # template number is an INSTANCE and gets the full structural treatment.
    is_shipped_template = is_template_dir and (name.endswith("-APPNAME")
                                               or name.endswith("-SYSTEMNAME"))
    is_instance = is_template_dir and not is_shipped_template

    # filename <-> displayName
    if os.path.basename(f) != name + ".json":
        fail(f, f"filename does not match displayName '{name}'")
    m = re.match(r"^CA(\d{3})-VCIO-", name)
    if not m:
        fail(f, "displayName does not match CAnnn-VCIO-* convention")
        continue
    n = m.group(1)
    if n in seen_numbers and not shares_number:
        fail(f, f"duplicate policy number CA{n} (also {seen_numbers[n]})")
    if not shares_number:
        seen_numbers[n] = name

    if p.get("state") not in VALID_STATES:
        fail(f, f"invalid state '{p.get('state')}'")

    cond = p.get("conditions", {})
    apps = cond.get("applications", {}) or {}
    users = cond.get("users", {}) or {}
    inc_users = users.get("includeUsers") or []
    inc_groups = users.get("includeGroups") or []
    exc_groups = users.get("excludeGroups") or []

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
    has_user_scope = (inc_users or inc_groups or users.get("includeRoles")
                      or users.get("includeGuestsOrExternalUsers"))
    if not has_user_scope:
        fail(f, "no user scope (includeUsers/Groups/Roles/Guests all empty)")

    # --- C3: agent scope. includeUsers=['None'] means "no human is in scope",
    # so the principals must come from an agent block that actually names some.
    # A non-null block with empty collections is still inert, and
    # agentIdRiskLevels is a CONDITION, not a scope.
    if inc_users == ["None"]:
        ca = cond.get("clientApplications") or {}
        ag = cond.get("agents") or {}
        agent_scope = (ag.get("includeAgentUsers")
                       or ca.get("includeAgentIdServicePrincipals")
                       or ca.get("includeServicePrincipals"))
        if not agent_scope:
            fail(f, "C3 INERT AGENT SCOPE: includeUsers=['None'] with no non-empty "
                    "agents.includeAgentUsers, clientApplications."
                    "includeAgentIdServicePrincipals or includeServicePrincipals "
                    "(agentIdRiskLevels alone is not scope)")

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

    # --- C4: redundancy. compliantDevice OR mfa adds nothing for a population
    # already inside CA002's MFA scope — MFA alone satisfies it. Approximation
    # of "inside CA002's scope": targets All users or a member group, is not
    # scoped to guests only, and is not itself a service-account policy.
    if g and g.get("operator") == "OR":
        if set(g.get("builtInControls") or []) == {"compliantDevice", "mfa"}:
            guests_only = bool(users.get("includeGuestsOrExternalUsers")) and not (
                inc_users or inc_groups)
            sa_scoped = sa_id in inc_groups
            if not guests_only and not sa_scoped:
                fail(f, "C4 REDUNDANT: grant [compliantDevice, mfa] with operator OR "
                        "over a population already inside CA002's MFA scope — MFA "
                        "alone satisfies it, so the policy enforces nothing new")

    # --- C5: device filters. One string, one meaning. Ownership is not a
    # security state. Transition/ is the only place another filter may appear.
    devs = cond.get("devices") or {}
    dfilter = devs.get("deviceFilter") or {}
    rule = dfilter.get("rule")
    if rule and not is_transition and rule != FILTER_COMPLIANT:
        fail(f, f"C5 FILTER DRIFT: device filter is {rule!r}; every standard "
                f"policy must use exactly {FILTER_COMPLIANT!r}")

    # GUID wiring: groups
    for key in ("includeGroups", "excludeGroups"):
        for gid_ in users.get(key, []) or []:
            if gid_ not in groups:
                fail(f, f"{key} references unknown group {gid_}")
                continue
            group_usage.setdefault(gid_, []).append(name)
            if (key == "excludeGroups" and groups[gid_].startswith("SG-CA-Excl-")
                    and (not shares_number or is_instance)):
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
    if not is_template_dir and APP_PLACEHOLDER_CHECK(apps):
        fail(f, "placeholder app id present outside Templates/")

    # break-glass excluded from every user-scoped, non-agent policy
    is_agent = bool(cond.get("agents") or cond.get("clientApplications")
                    or cond.get("agentIdRiskLevels")) or inc_users == ["None"]
    if bg_id and not is_agent and bg_id not in exc_groups:
        fail(f, "break-glass group not excluded")

    # --- A10 pairing. The standard four exclude the transition group; the
    # transition variants include it. Get this backwards and a user is either
    # covered twice or not at all.
    if transition_id:
        if n in TRANSITION_EXCLUDERS and not shares_number:
            if transition_id not in exc_groups:
                fail(f, f"A10: CA{n} must exclude SG-CA-Transition-Hybrid — "
                        f"without it a transition user is covered by both the "
                        f"standard policy and its variant")
        if is_transition and transition_id not in inc_groups:
            fail(f, "A10: transition variant must include SG-CA-Transition-Hybrid, "
                    "not SG-CA-Users")

    # --- A9: a template INSTANCE must own its scope. Reusing another policy's
    # exclusion group is the chaining defect; sharing a per-system group would
    # silently widen a fence.
    if is_instance:
        owned = [gid_ for gid_ in list(inc_groups) + list(exc_groups)
                 if gid_ in groups and (groups[gid_].startswith("SG-CA-Excl-CA")
                                        or groups[gid_].startswith("SG-CA-SA-"))]
        if not owned:
            fail(f, "A9: template instance references no instance-scoped group "
                    "(expected its own SG-CA-Excl-CA<nnn>-<NAME>)")

# --- required identities present ---
for folder, patterns in REQUIRED.items():
    names = present.get(folder, [])
    for pat in patterns:
        if not any(re.match(pat, x) for x in names):
            findings.append(f"{folder}: no policy matching required identity /{pat}/")

# exclusion group reuse (the chaining defect)
for gid_, used_by in excl_usage.items():
    if len(used_by) > 1:
        findings.append(f"exclusion group {groups[gid_]} reused by multiple policies: {used_by}")
# every Excl group used at least once
for gid_, gname in groups.items():
    if gname.startswith("SG-CA-Excl-") and gid_ not in excl_usage:
        findings.append(f"orphaned exclusion group: {gname}")
# no orphan scope groups either — an unused group is a group nobody reviews
for gid_, gname in groups.items():
    if not gname.startswith("SG-CA-Excl-") and gid_ not in group_usage:
        if gname != "SG-CA-BreakGlass":   # excluded everywhere, included nowhere
            findings.append(f"orphaned group: {gname} is referenced by no policy")

print(f"Checked {len(policy_files)} policies, {len(core_groups)} core groups "
      f"(+{len(groups) - len(core_groups)} template-scope), "
      f"{len(locations)} named locations.")
if findings:
    print(f"\n{len(findings)} FINDINGS:")
    for x in findings: print("  -", x)
    sys.exit(1)
print("CLEAN — release gate passed.")
