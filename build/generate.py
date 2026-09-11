#!/usr/bin/env python3
"""VCIO CA Framework — policy generator.
Generates IntuneManagement-compatible JSON from the policy spec.
Deterministic GUIDs (uuid5) so rebuilds are stable. UTF-8, no BOM, LF.
"""
import json, uuid, os, re, sys

NS = uuid.UUID("6f1c8f6e-2b1a-4c1e-9e7b-vcio0000ca00".replace("vcio0000ca00", "0a1b2c3d4e5f"))
ROOT = os.path.join(os.path.dirname(__file__), "..")
VERSION = "2026.9.1"
STAMP = "2026-07-09T00:00:00.0000000Z"

def gid(name: str) -> str:
    return str(uuid.uuid5(NS, name))

# ---------- well-known IDs ----------
O365 = "Office365"
PORTALS = "MicrosoftAdminPortals"
AZRM = "797f4846-ba00-4fd7-ba43-dac1f8f63013"          # Windows Azure Service Management API
INTUNE = "0000000a-0000-0000-c000-000000000000"
INTUNE_ENROLL = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
MYAPPS = "2793995e-0a7d-40d7-bd35-6968ba142197"
EXO = "00000002-0000-0ff1-ce00-000000000000"
SPO = "00000003-0000-0ff1-ce00-000000000000"
APP_PLACEHOLDER = "REPLACE-WITH-APP-ID"

AUTHSTR_MFA = ("00000000-0000-0000-0000-000000000002", "Multifactor authentication")
AUTHSTR_PR = ("00000000-0000-0000-0000-000000000004", "Phishing-resistant MFA")

# Admin roles (built-in role template IDs — identical in every tenant).
# Sourced from the 2026.6 community list; review item for Aaron.
ADMIN_ROLES = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader
    "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
    "d2562ede-74db-457e-a7b6-544e236ebb61",  # AI Administrator
    "db506228-d27e-4b7d-95e5-295956d6615f",  # Agent ID Administrator
    "6b942400-691f-4bf0-9d12-d8a254a2baf5",  # Agent Registry Administrator
    "e93e3737-fa85-474a-aee4-7d3fb86510f3",  # Entra ID Backup Administrator
    "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",  # Windows 365 Administrator
    "1707125e-0aa2-4d4d-8655-a7c786c76a25",  # Microsoft 365 Backup Administrator
    "69091246-20e8-4a56-aa4d-066075b2a7a8",  # Teams Administrator
    "11451d60-acb2-45eb-a7d6-43d0f0125c13",  # Windows Update Deployment Administrator
]

# Directory Synchronization Accounts — the Entra Connect sync account's role.
# Template ID verified 2026-09-11 against
# https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#all-roles
DIRSYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32"

GUEST_ALL = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
GUEST_NO_SP = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser"

# A1 — one filter, one meaning. Ownership is not a security state: a
# corporate-owned device that has fallen out of compliance is not managed.
# Every standard-policy device filter is exactly this string (validator rule C5).
FILTER_COMPLIANT = 'device.isCompliant -eq True'
# A10 — the transition filter admits hybrid-joined devices as well, and lives
# only in Transition/. ServerAd is the trustType value for a hybrid Entra join.
FILTER_TRANSITION = 'device.isCompliant -eq True -or device.trustType -eq "ServerAd"'

# ---------- core groups ----------
# scope "core"     -> Config/Groups/, listed in the MigrationTable, bulk-imported.
# scope "template" -> Templates/Groups/, NEVER bulk-imported and never in the
#                     MigrationTable. They exist so the shipped SYSTEMNAME
#                     templates have resolvable references for the validators;
#                     a real deployment gets a per-system instance instead
#                     (build/generate.py --instance).
GROUPS = {}
def group(name, desc, scope="core"):
    GROUPS[name] = {"id": gid("group:" + name), "description": desc, "scope": scope}
    return GROUPS[name]["id"]

BG = group("SG-CA-BreakGlass", "Break-glass emergency access accounts. Excluded from all VCIO CA policies. FIDO2-credentialed, sign-in alerting mandatory, quarterly access test.")
USERS = group("SG-CA-Users", "DEPLOYMENT PARAMETER: replace membership with the customer's dynamic all-employees rule. Persona group for the 200s/300s policies.")
SA = group("SG-CA-ServiceAccounts", "User-shaped service accounts (transition state). IP-fenced by CA500 (Mode Shared) or by a per-system CA500 instance (Mode Per-System); excluded from CA002 interactive MFA by design. Entra Connect sync accounts are NEVER members — CA002 exempts them by role (A4). Access-reviewed.")
# A8 — privilege that built-in role targeting cannot see: custom directory roles,
# AU-scoped assignments, and Azure RBAC control-plane holders.
PRIV = group("SG-CA-Privileged", "Custom-role, AU-scoped and Azure RBAC privileged holders not covered by built-in role targeting. Reconciled by Tools/Compare-VcioPrivilegedScope.ps1. Ships empty.")
# A10 — the hybrid stop-gap population. Emptying this group IS the transition
# exit: a removed user falls back under the four standard policies on the next
# sign-in. Exit order and verification: Tools/Invoke-VcioTransitionExit.ps1.
TRANSITION = group("SG-CA-Transition-Hybrid", "DEPLOYMENT PARAMETER (worksheet item 16): users whose devices are still hybrid-joined only. Members are excluded from standard CA200/CA204/CA300/CA301 and covered by the Transition/ variants instead. Ships empty, has a dated EXIT in the deployment manifest, and is emptied by Tools/Invoke-VcioTransitionExit.ps1.")
# A11 — placeholder scope objects for the SYSTEMNAME templates (never imported).
SA_SYSTEM = group("SG-CA-SA-SYSTEMNAME", "TEMPLATE PLACEHOLDER — per-system service-account group for fencing Mode Per-System. Instantiate with build/generate.py --instance 500 SYSTEMNAME. Every member is also a member of SG-CA-ServiceAccounts (which carries the CA002 exemption). Never bulk-imported.", scope="template")

def excl(nnn, policy_name):
    return group(f"SG-CA-Excl-CA{nnn}", f"Exclusion group for {policy_name}. Ships empty. Named owner, quarterly access review, alert on membership change required.")

# ---------- named locations ----------
NL_COUNTRIES = gid("nl:VCIO-NL-AllowedCountries")
NL_SA_IPS = gid("nl:VCIO-NL-ServiceAccountIPs")
NL_EGRESS = gid("nl:VCIO-NL-TrustedEgress")
# Template-scope placeholder (Templates/NamedLocations/, never bulk-imported).
NL_SA_SYSTEM = gid("nl:VCIO-NL-SA-SYSTEMNAME")

# ---------- JSON assembly helpers ----------
def users_block(include_users=None, include_groups=None, exclude_groups=None,
                include_roles=None, exclude_roles=None, guests=None):
    return {
        "@odata.type": "#microsoft.graph.conditionalAccessUsers",
        "includeUsers@odata.type": "#Collection(String)",
        "includeUsers": include_users or [],
        "excludeUsers@odata.type": "#Collection(String)",
        "excludeUsers": [],
        "includeGroups@odata.type": "#Collection(String)",
        "includeGroups": include_groups or [],
        "excludeGroups@odata.type": "#Collection(String)",
        "excludeGroups": exclude_groups or [],
        "includeRoles@odata.type": "#Collection(String)",
        "includeRoles": include_roles or [],
        "excludeRoles@odata.type": "#Collection(String)",
        "excludeRoles": exclude_roles or [],
        "includeGuestsOrExternalUsers": (
            {"guestOrExternalUserTypes": guests,
             "externalTenants": {"@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
                                  "membershipKind": "all"}} if guests else None),
        "excludeGuestsOrExternalUsers": None,
    }

def apps_block(include=None, exclude=None, user_actions=None):
    return {
        "@odata.type": "#microsoft.graph.conditionalAccessApplications",
        "includeApplications@odata.type": "#Collection(String)",
        "includeApplications": include or [],
        "excludeApplications@odata.type": "#Collection(String)",
        "excludeApplications": exclude or [],
        "includeUserActions@odata.type": "#Collection(String)",
        "includeUserActions": user_actions or [],
        "includeAuthenticationContextClassReferences@odata.type": "#Collection(String)",
        "includeAuthenticationContextClassReferences": [],
        "applicationFilter": None,
    }

def platforms_block(include, exclude=None):
    return {
        "@odata.type": "#microsoft.graph.conditionalAccessPlatforms",
        "includePlatforms@odata.type": "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
        "includePlatforms": include,
        "excludePlatforms@odata.type": "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
        "excludePlatforms": exclude or [],
    }

def locations_block(include, exclude=None):
    return {
        "@odata.type": "#microsoft.graph.conditionalAccessLocations",
        "includeLocations@odata.type": "#Collection(String)",
        "includeLocations": include,
        "excludeLocations@odata.type": "#Collection(String)",
        "excludeLocations": exclude or [],
    }

def devices_filter(mode, rule):
    return {
        "@odata.type": "#microsoft.graph.conditionalAccessDevices",
        "includeDeviceStates@odata.type": "#Collection(String)", "includeDeviceStates": [],
        "excludeDeviceStates@odata.type": "#Collection(String)", "excludeDeviceStates": [],
        "includeDevices@odata.type": "#Collection(String)", "includeDevices": [],
        "excludeDevices@odata.type": "#Collection(String)", "excludeDevices": [],
        "deviceFilter": {"@odata.type": "#microsoft.graph.conditionalAccessFilter",
                          "mode@odata.type": "#microsoft.graph.filterMode",
                          "mode": mode, "rule": rule},
    }

def auth_strength(sid, name):
    return {
        "id": sid, "displayName": name, "policyType": "builtIn",
        "createdDateTime": "2021-12-01T08:00:00Z", "modifiedDateTime": "2021-12-01T08:00:00Z",
        "requirementsSatisfied": "mfa",
    }

def grant(operator="OR", builtin=None, strength=None):
    g = {
        "@odata.type": "#microsoft.graph.conditionalAccessGrantControls",
        "operator": operator,
        "builtInControls@odata.type": "#Collection(microsoft.graph.conditionalAccessGrantControl)",
        "builtInControls": builtin or [],
        "customAuthenticationFactors@odata.type": "#Collection(String)",
        "customAuthenticationFactors": [],
        "termsOfUse@odata.type": "#Collection(String)", "termsOfUse": [],
        "authenticationStrength": auth_strength(*strength) if strength else None,
    }
    return g

def session(sif_hours=None, sif_everytime=False, pb_never=False, aer=False, token_protection=False):
    s = {
        "@odata.type": "#microsoft.graph.conditionalAccessSessionControls",
        "disableResilienceDefaults": None, "cloudAppSecurity": None,
        "signInFrequency": None, "persistentBrowser": None,
        "continuousAccessEvaluation": None, "secureSignInSession": None,
        "applicationEnforcedRestrictions": None,
    }
    if sif_hours:
        s["signInFrequency"] = {"value": sif_hours, "type": "hours",
                                 "authenticationType": "primaryAndSecondaryAuthentication",
                                 "frequencyInterval": "timeBased", "isEnabled": True}
    if sif_everytime:
        s["signInFrequency"] = {"value": None, "type": None,
                                 "authenticationType": "primaryAndSecondaryAuthentication",
                                 "frequencyInterval": "everyTime", "isEnabled": True}
    if pb_never:
        s["persistentBrowser"] = {"mode": "never", "isEnabled": True}
    if aer:
        s["applicationEnforcedRestrictions"] = {
            "@odata.type": "#microsoft.graph.applicationEnforcedRestrictionsSessionControl",
            "isEnabled": True}
    if token_protection:
        s["secureSignInSession"] = {"isEnabled": True}
    return s

REPORT = "enabledForReportingButNotEnforced"

def policy(nnn, name, *, users, apps, client_apps=("all",), platforms=None, locations=None,
           devices=None, grant_ctl=None, session_ctl=None, user_risk=None, signin_risk=None,
           agent_risk=None, auth_flows=None, agents=None, client_applications=None,
           state=REPORT, exclude_bg=True, own_excl=True):
    display = f"CA{nnn}-VCIO-{name}"
    ex = list(users.get("excludeGroups") or [])
    if exclude_bg and BG not in ex and (users.get("includeUsers") != ["None"]):
        ex.append(BG)
    if own_excl and (users.get("includeUsers") != ["None"]):
        ex.append(excl(nnn, display))
    users["excludeGroups"] = ex
    pid = gid("policy:" + display)
    cond = {
        "@odata.type": "#microsoft.graph.conditionalAccessConditionSet",
        "userRiskLevels@odata.type": "#Collection(microsoft.graph.riskLevel)",
        "userRiskLevels": user_risk or [],
        "signInRiskLevels@odata.type": "#Collection(microsoft.graph.riskLevel)",
        "signInRiskLevels": signin_risk or [],
        "clientAppTypes@odata.type": "#Collection(microsoft.graph.conditionalAccessClientApp)",
        "clientAppTypes": list(client_apps),
        "platforms": platforms, "locations": locations, "times": None,
        "deviceStates": None, "devices": devices,
        "clientApplications": client_applications, "agents": agents,
        "applications": apps, "users": users,
    }
    if agent_risk:
        cond["agentIdRiskLevels@odata.type"] = "#microsoft.graph.conditionalAccessAgentIdRiskLevels"
        cond["agentIdRiskLevels"] = agent_risk
    if auth_flows:
        cond["authenticationFlows"] = {"@odata.type": "#microsoft.graph.conditionalAccessAuthenticationFlows",
                                        "transferMethods": auth_flows}
    return display, {
        "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
        "id": pid,
        "templateId": None,
        "displayName": display,
        "createdDateTime": STAMP, "modifiedDateTime": STAMP,
        "state@odata.type": "#microsoft.graph.conditionalAccessPolicyState",
        "state": state,
        "deletedDateTime": None, "partialEnablementStrategy": None,
        "conditions": cond,
        "grantControls": grant_ctl,
        "sessionControls": session_ctl,
    }

POLICIES = []
def add(target, *args, **kw):
    POLICIES.append((target,) + policy(*args, **kw))

C = "Config/ConditionalAccess"
T = "Templates/ConditionalAccess"

# ===================== 000s Foundation =====================
add(C, "000", "Global-BlockLegacyAuth",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    client_apps=("exchangeActiveSync", "other"), grant_ctl=grant(builtin=["block"]))
# A3 — split. One exception population per flow: Teams Rooms / IoT / console
# devices legitimately need device code flow and go in SG-CA-Excl-CA001; nothing
# legitimate needs authentication transfer, so SG-CA-Excl-CA007 stays empty.
# A shared exclusion group would have handed the device-code exceptions a free
# auth-transfer bypass.
add(C, "001", "Global-BlockDeviceCodeFlow",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    auth_flows="deviceCodeFlow", grant_ctl=grant(builtin=["block"]))
# A4 — the Entra Connect sync account cannot do interactive MFA and must not be
# parked in SG-CA-ServiceAccounts to get around CA002 (that group is the shared
# IP-fence scope; the sync account's egress is the Connect server's, a different
# scope). Exempt it by role instead, which is self-maintaining. Optional fencing
# for it is the dedicated CA500-...-DirSync instance on SG-CA-SA-DirSync.
add(C, "002", "Global-MFA",
    users=users_block(include_users=["All"], exclude_groups=[SA],
                      exclude_roles=[DIRSYNC_ROLE]),
    apps=apps_block(["All"]), grant_ctl=grant(builtin=["mfa"]))
add(C, "003", "Global-MFA-DeviceRegisterJoin",
    users=users_block(include_users=["All"]),
    apps=apps_block(user_actions=["urn:user:registerdevice"]), grant_ctl=grant(builtin=["mfa"]))
add(C, "004", "Global-ProtectSecurityInfoRegistration",
    users=users_block(include_users=["All"]),
    apps=apps_block(user_actions=["urn:user:registersecurityinfo"]), grant_ctl=grant(builtin=["mfa"]))
add(C, "005", "Global-BlockUnknownPlatforms",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    platforms=platforms_block(["all"], ["android", "iOS", "windows", "macOS"]),
    grant_ctl=grant(builtin=["block"]))
add(C, "006", "Global-GeoFence",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    locations=locations_block(["All"], [NL_COUNTRIES]), grant_ctl=grant(builtin=["block"]))
add(C, "007", "Global-BlockAuthTransfer",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    auth_flows="authenticationTransfer", grant_ctl=grant(builtin=["block"]))

# ===================== 100s Privileged / Tier 0 =====================
# A8 — role targeting sees built-in directory roles only. Custom roles,
# AU-scoped assignments and Azure RBAC control-plane holders are privileged and
# invisible to it, so the 100s target the roles AND the reconciled group.
add(C, "100", "Privileged-PhishingResistantMFA",
    users=users_block(include_roles=ADMIN_ROLES, include_groups=[PRIV]),
    apps=apps_block(["All"]), grant_ctl=grant(strength=AUTHSTR_PR))
add(C, "101", "Privileged-CompliantDevice",
    users=users_block(include_roles=ADMIN_ROLES, include_groups=[PRIV]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    grant_ctl=grant(builtin=["compliantDevice"]))
add(C, "102", "Privileged-SessionHygiene",
    users=users_block(include_roles=ADMIN_ROLES, include_groups=[PRIV]),
    apps=apps_block(["All"]),
    grant_ctl=None, session_ctl=session(sif_hours=8, pb_never=True))
add(C, "103", "Tier0-ControlPlane-AllUsers",
    users=users_block(include_users=["All"]),
    apps=apps_block([AZRM, PORTALS]),
    grant_ctl=grant(operator="AND", builtin=["compliantDevice"], strength=AUTHSTR_PR))

# ===================== 200s Managed users =====================
add(C, "200", "Users-Windows-CompliantDevice",
    users=users_block(include_groups=[USERS], exclude_groups=[TRANSITION]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    platforms=platforms_block(["windows"]), client_apps=("mobileAppsAndDesktopClients",),
    grant_ctl=grant(builtin=["compliantDevice"]))
add(C, "201", "Users-macOS-CompliantDevice",
    users=users_block(include_groups=[USERS]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    platforms=platforms_block(["macOS"]), client_apps=("mobileAppsAndDesktopClients",),
    grant_ctl=grant(builtin=["compliantDevice"]))
# A2 — no device filter. The old exclude-filter carved enrolled-and-compliant
# devices out of the policy entirely, so an enrolled device that FELL OUT of
# compliance was reached by nothing here. The OR grant covers the whole
# population instead: a compliant device passes on compliance, an unmanaged
# device passes on APP, and an enrolled non-compliant device is blocked unless
# some other effective APP assignment reaches it — the shipped filters
# (app.deviceManagementType -eq "Unmanaged") do not, though a customer-added
# assignment might. F1 tests exactly that case.
add(C, "202", "Users-Mobile-AppProtection",
    users=users_block(include_groups=[USERS]), apps=apps_block([O365]),
    platforms=platforms_block(["android", "iOS"]),
    client_apps=("browser", "mobileAppsAndDesktopClients"),
    grant_ctl=grant(operator="OR", builtin=["compliantDevice", "compliantApplication"]))
add(C, "203", "Users-MFA-IntuneEnrollment",
    users=users_block(include_groups=[USERS]), apps=apps_block([INTUNE_ENROLL]),
    grant_ctl=grant(builtin=["mfa"]), session_ctl=session(sif_everytime=True))
add(C, "204", "Users-SessionHygiene-Unmanaged",
    users=users_block(include_groups=[USERS], exclude_groups=[TRANSITION]),
    apps=apps_block(["All"]),
    devices=devices_filter("exclude", FILTER_COMPLIANT),
    session_ctl=session(sif_hours=12, pb_never=True))

# ===================== 300s BYOD contained path =====================
# CA300 leans on app-enforced restrictions, which only Exchange Online and
# SharePoint Online honour and which must be switched on service-side first:
# Docs/app-enforced-restrictions.md.
add(C, "300", "BYOD-BrowserSessionControls",
    users=users_block(include_groups=[USERS], exclude_groups=[TRANSITION]),
    apps=apps_block([O365]),
    client_apps=("browser",), devices=devices_filter("exclude", FILTER_COMPLIANT),
    session_ctl=session(aer=True))
add(C, "301", "BYOD-Windows-RequireAppProtection",
    users=users_block(include_groups=[USERS], exclude_groups=[TRANSITION]),
    apps=apps_block([O365]),
    platforms=platforms_block(["windows"]), client_apps=("browser",),
    devices=devices_filter("exclude", FILTER_COMPLIANT),
    grant_ctl=grant(builtin=["compliantApplication"]))

# ===================== 400s Externals =====================
add(C, "400", "Guests-MFA",
    users=users_block(guests=GUEST_ALL), apps=apps_block(["All"]),
    grant_ctl=grant(builtin=["mfa"]))
add(C, "401", "Guests-DefaultDenyApps",
    users=users_block(guests=GUEST_NO_SP),
    apps=apps_block(["All"], exclude=[O365, MYAPPS]), grant_ctl=grant(builtin=["block"]))
add(C, "402", "Guests-SessionHygiene",
    users=users_block(guests=GUEST_ALL), apps=apps_block(["All"]),
    session_ctl=session(sif_hours=12, pb_never=True))
# A5 — serviceProvider excluded. A GDAP partner technician reaching the admin
# portals is the delivery model, not an intrusion; blocking it here breaks the
# engagement and pushes the customer toward a standing local admin account,
# which is worse. Service providers stay governed by CA400 (MFA, home-tenant
# enforced), CA402 (session hygiene), CA103 (Tier 0 control plane) and their
# home tenant's own controls. See Docs/partner-access.md.
add(C, "403", "Guests-BlockAdminPortals",
    users=users_block(guests=GUEST_NO_SP), apps=apps_block([PORTALS]),
    grant_ctl=grant(builtin=["block"]))

# ===================== 500s Non-interactive =====================
add(C, "500", "ServiceAccounts-IPFence",
    users=users_block(include_groups=[SA]), apps=apps_block(["All"]),
    locations=locations_block(["All"], [NL_SA_IPS]), grant_ctl=grant(builtin=["block"]))
add(C, "501", "ServiceAccounts-RestrictApps",
    users=users_block(include_groups=[SA]),
    apps=apps_block(["All"]),  # deployer adds excludeApplications per assigned app
    grant_ctl=grant(builtin=["block"]))

# ===================== 600s Agents =====================
add(C, "600", "Agents-DefaultDeny",
    users=users_block(include_users=["None"]), apps=apps_block(["AllAgentIdResources"]),
    client_applications={
        "@odata.type": "#microsoft.graph.conditionalAccessClientApplications",
        "includeServicePrincipals": [], "excludeServicePrincipals": [],
        "includeAgentIdServicePrincipals": ["All"]},
    grant_ctl=grant(builtin=["block"]), exclude_bg=False, own_excl=False)
# A7 — agentIdRiskLevels is a condition, not a scope. Without an agent
# principal scope this policy had includeUsers=['None'] and nothing else, which
# is the inert shape the validator exists to catch (rule C3). Same scope block
# as CA600; target resources stay All.
add(C, "601", "Agents-BlockHighRisk",
    users=users_block(include_users=["None"]), apps=apps_block(["All"]),
    client_applications={
        "@odata.type": "#microsoft.graph.conditionalAccessClientApplications",
        "includeServicePrincipals": [], "excludeServicePrincipals": [],
        "includeAgentIdServicePrincipals": ["All"]},
    agent_risk="high", grant_ctl=grant(builtin=["block"]), exclude_bg=False, own_excl=False)
add(C, "602", "Agents-CompliantDevice-AgentUsers",
    users=users_block(include_users=["None"]), apps=apps_block(["All"]),
    agents={"@odata.type": "#microsoft.graph.conditionalAccessAgents",
            "includeAgentUsers": ["All"], "excludeAgentUsers": [], "agentFilter": None},
    grant_ctl=grant(builtin=["compliantDevice"]), exclude_bg=False, own_excl=False)

# ===================== 700s P2 overlay =====================
OV = "Config-Overlay-P2/ConditionalAccess"
# A6 — CA700/CA701 are blocks, not interactive challenges: a service account
# cannot be inconvenienced by one, and a compromised service account is exactly
# what high risk is for. The SA exclusion here was protecting the attacker.
# CA702/CA703 keep it because they demand MFA and a password change, which a
# non-interactive account cannot perform.
add(OV, "700", "Risk-BlockHighUserRisk",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    user_risk=["high"], grant_ctl=grant(builtin=["block"]))
add(OV, "701", "Risk-BlockHighSignInRisk",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    signin_risk=["high"], grant_ctl=grant(builtin=["block"]))
add(OV, "702", "Risk-MFA-MediumSignInRisk",
    users=users_block(include_users=["All"], exclude_groups=[SA]), apps=apps_block(["All"]),
    signin_risk=["medium"], grant_ctl=grant(builtin=["mfa"]),
    session_ctl=session(sif_everytime=True))
add(OV, "703", "Risk-PasswordChange-MediumUserRisk",
    users=users_block(include_users=["All"], exclude_groups=[SA]), apps=apps_block(["All"]),
    user_risk=["medium"], grant_ctl=grant(operator="AND", builtin=["mfa", "passwordChange"]),
    session_ctl=session(sif_everytime=True))
add(OV, "704", "Agents-BlockRiskyAgentUsers",
    users=users_block(include_users=["None"]), apps=apps_block(["All"]),
    agents={"@odata.type": "#microsoft.graph.conditionalAccessAgents",
            "includeAgentUsers": ["All"], "excludeAgentUsers": [], "agentFilter": None},
    agent_risk="medium,high", grant_ctl=grant(builtin=["block"]), exclude_bg=False, own_excl=False)
add(OV, "705", "Privileged-TokenProtection",
    users=users_block(include_roles=ADMIN_ROLES), apps=apps_block([EXO, SPO]),
    platforms=platforms_block(["windows"]), client_apps=("mobileAppsAndDesktopClients",),
    session_ctl=session(token_protection=True))

# ===================== Transition variants (hybrid stop-gap) =====================
# A10. These are NOT a parallel deployment you choose between — they are the
# hybrid population's coverage while it exists. Every variant includes
# SG-CA-Transition-Hybrid instead of SG-CA-Users, and the four standard
# policies exclude that same group, so exactly one of each pair reaches a
# given user and no user is covered twice or not at all.
#
# The exit is structural: empty the group and the removed users fall back under
# the standard policies on their next sign-in, at which point the transition
# policies are inert. The order matters and is enforced by
# Tools/Invoke-VcioTransitionExit.ps1 — verify SG-CA-Users membership and that
# the four standard policies are enabled, remove members, confirm a
# post-removal sign-in per user, and only then disable these. Disabling them
# while the group still has members removes protection outright, because the
# standard policies' exclusions are still active.
#
# The exit DATE is not in this JSON. Graph documents conditionalAccessPolicy
# description as "Not used" and nothing proves it survives an import/export
# round trip, so the date lives in the deployment manifest (Deploy/manifest.
# example.json) and is enforced by validator rule C2 plus the exit script.
TR = "Transition/ConditionalAccess"
add(TR, "200", "Users-Windows-CompliantOrHybrid-TRANSITION",
    users=users_block(include_groups=[TRANSITION], exclude_groups=[gid("group:SG-CA-Excl-CA200")]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    platforms=platforms_block(["windows"]), client_apps=("mobileAppsAndDesktopClients",),
    grant_ctl=grant(builtin=["compliantDevice", "domainJoinedDevice"]), own_excl=False)
add(TR, "204", "Users-SessionHygiene-Unmanaged-TRANSITION",
    users=users_block(include_groups=[TRANSITION], exclude_groups=[gid("group:SG-CA-Excl-CA204")]),
    apps=apps_block(["All"]),
    devices=devices_filter("exclude", FILTER_TRANSITION),
    session_ctl=session(sif_hours=12, pb_never=True), own_excl=False)
add(TR, "300", "BYOD-BrowserSessionControls-TRANSITION",
    users=users_block(include_groups=[TRANSITION], exclude_groups=[gid("group:SG-CA-Excl-CA300")]),
    apps=apps_block([O365]),
    client_apps=("browser",), devices=devices_filter("exclude", FILTER_TRANSITION),
    session_ctl=session(aer=True), own_excl=False)
add(TR, "301", "BYOD-Windows-RequireAppProtection-TRANSITION",
    users=users_block(include_groups=[TRANSITION], exclude_groups=[gid("group:SG-CA-Excl-CA301")]),
    apps=apps_block([O365]),
    platforms=platforms_block(["windows"]), client_apps=("browser",),
    devices=devices_filter("exclude", FILTER_TRANSITION),
    grant_ctl=grant(builtin=["compliantApplication"]), own_excl=False)
# (No macOS transition variant — hybrid join does not exist on macOS. CA201 has
#  no transition pair and no SG-CA-Transition-Hybrid exclusion for that reason.)

# ===================== 800s Extension templates =====================
add(T, "800", "Ext-Restricted-APPNAME",
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    grant_ctl=grant(builtin=["compliantDevice"]), own_excl=False)
# A9 — the old CA801 "Step-Up" (compliantDevice OR mfa) was redundant against
# CA002 for every user inside CA002's scope: MFA alone already satisfied it, so
# the template added a posture tier that enforced nothing new. The 801 slot is
# deliberately reused for the posture that was actually missing — a Tier 0
# app-level control matching CA103's shape. Retiring an old instance is a
# documented step, not a rename: Docs/upgrade.md.
add(T, "801", "Ext-Tier0-APPNAME",
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    grant_ctl=grant(operator="AND", builtin=["compliantDevice"], strength=AUTHSTR_PR),
    own_excl=False)
add(T, "802", "Ext-Fenced-APPNAME",
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    locations=locations_block(["All"], [NL_EGRESS]),
    devices=devices_filter("exclude", FILTER_COMPLIANT),
    grant_ctl=grant(builtin=["block"]), own_excl=False)
add(T, "803", "Ext-MobileMAM-APPNAME",
    # Mobile access to the named app from personal devices only inside a
    # containerized (APP-protected) client. PREREQ: the app must support Intune
    # APP (SDK-integrated or wrapped) AND be added to the VCIO-APP baselines'
    # targeted apps (or its own APP policy if settings differ).
    # A2 — same OR-grant model as CA202; no device filter.
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    platforms=platforms_block(["android", "iOS"]),
    client_apps=("browser", "mobileAppsAndDesktopClients"),
    grant_ctl=grant(operator="OR", builtin=["compliantDevice", "compliantApplication"]),
    own_excl=False)

# A11 — Mode Per-System service-account fencing. One CA500/CA501 pair per
# system, each on its own SG-CA-SA-<SYSTEM> group and its own
# VCIO-NL-SA-<SYSTEM> location, so the backup account's egress is the backup
# server's and nothing else. Every member is ALSO in SG-CA-ServiceAccounts,
# which is what carries the CA002 exemption. In this mode the shared CA500 and
# CA501 are set to disabled — not report-only — so the shared location can
# never be imposed on a per-system account. Instantiate with:
#   build/generate.py --instance 500 BACKUP
#   build/generate.py --instance 501 BACKUP
add(T, "500", "ServiceAccounts-IPFence-SYSTEMNAME",
    users=users_block(include_groups=[SA_SYSTEM]), apps=apps_block(["All"]),
    locations=locations_block(["All"], [NL_SA_SYSTEM]),
    grant_ctl=grant(builtin=["block"]), own_excl=False)
add(T, "501", "ServiceAccounts-RestrictApps-SYSTEMNAME",
    users=users_block(include_groups=[SA_SYSTEM]),
    apps=apps_block(["All"]),  # deployer adds excludeApplications per assigned app
    grant_ctl=grant(builtin=["block"]), own_excl=False)

# ===================== companion App Protection policies =====================
# Settings aligned to Microsoft's App Protection Data Protection Framework Level 2
# (enterprise enhanced). Documented in Docs/deployment-parameters.md.
IOS_APPS = ["com.microsoft.office.outlook", "com.microsoft.skype.teams",
            "com.microsoft.office.word", "com.microsoft.office.excel",
            "com.microsoft.office.powerpoint", "com.microsoft.skydrive",
            "com.microsoft.msedge", "com.microsoft.onenote"]
ANDROID_APPS = ["com.microsoft.office.outlook", "com.microsoft.teams",
                "com.microsoft.office.word", "com.microsoft.office.excel",
                "com.microsoft.office.powerpoint", "com.microsoft.skydrive",
                "com.microsoft.emmx", "com.microsoft.office.onenote"]

APP_COMMON = {
    "periodOfflineBeforeAccessCheck": "PT12H",
    "periodOnlineBeforeAccessCheck": "PT30M",
    "periodOfflineBeforeWipeIsEnforced": "P90D",
    "allowedInboundDataTransferSources": "allApps",
    "allowedOutboundDataTransferDestinations": "managedApps",
    "allowedOutboundClipboardSharingLevel": "managedAppsWithPasteIn",
    "organizationalCredentialsRequired": False,
    "dataBackupBlocked": True,
    "deviceComplianceRequired": False,
    "managedBrowserToOpenLinksRequired": True,
    "managedBrowser": "microsoftEdge",
    "saveAsBlocked": True,
    "allowedDataStorageLocations": ["oneDriveForBusiness", "sharePoint"],
    "contactSyncBlocked": False,
    "printBlocked": True,
    "fingerprintBlocked": False,
    "disableAppPinIfDevicePinIsSet": True,
    "maximumPinRetries": 5,
    "simplePinBlocked": True,
    "minimumPinLength": 6,
    "pinCharacterSet": "numeric",
    "pinRequired": True,
    "periodBeforePinReset": "PT0S",
    "appActionIfUnableToAuthenticateUser": "block",
    "isAssigned": False,
}

def app_protection(odata_type, name, description, extra, apps, id_type, id_key):
    p = {"@odata.type": odata_type,
         "id": gid("app:" + name),
         "displayName": name,
         "description": description,
         "createdDateTime": STAMP, "lastModifiedDateTime": STAMP,
         "version": None, "roleScopeTagIds": ["0"]}
    p.update(APP_COMMON)
    p.update(extra)
    p["apps"] = [{"id": f"{a}.{'ios' if 'ios' in id_type else ('windows' if 'windows' in id_type else 'android')}",
                  "mobileAppIdentifier": {"@odata.type": id_type, id_key: a}} for a in apps]
    return p

# Managed-app assignment filters — iOS/Android APP policies assign to All Users
# and target ONLY unmanaged devices via these filters, so enrolled/MDM devices
# never get double-managed by MAM. Created via Graph by the prereqs script.
# NO Windows filter: Windows managed-app filters DO exist (Microsoft lists Windows
# for app-protection-policy filters), but the Windows MAM policy does not need one.
# Microsoft does not support Windows MAM on a same-tenant MDM-enrolled device — such
# a device never receives the APP policy — so an unfiltered Windows MAM assignment
# already applies to unmanaged Windows only. (The lab BadRequest was a wrong platform
# value in an earlier script, not proof the platform is unsupported.)
ASSIGNMENT_FILTERS = [
    {"displayName": "VCIO-FLT-iOS-UnmanagedDevices",
     "platform": "iOSMobileApplicationManagement"},
    {"displayName": "VCIO-FLT-Android-UnmanagedDevices",
     "platform": "androidMobileApplicationManagement"},
]
ASSIGNMENT_FILTERS = [
    {**f,
     "id": gid("filter:" + f["displayName"]),
     "description": "VCIO CA Framework: limits App Protection assignment to unmanaged devices. Assign APP policies to All Users with this filter (include mode).",
     "rule": 'app.deviceManagementType -eq "Unmanaged"',
     "assignmentFilterManagementType": "apps",
     "roleScopeTags": ["0"]}
    for f in ASSIGNMENT_FILTERS
]

APP_ASSIGN_NOTE = "Assign to All Users with the platform's VCIO-FLT-*-UnmanagedDevices filter (include) before its ring enables."

APP_POLICIES = [
    app_protection("#microsoft.graph.iosManagedAppProtection",
        "VCIO-APP-iOS-Baseline",
        f"VCIO CA Framework companion MAM baseline (DPF Level 2). Required by CA202. {APP_ASSIGN_NOTE}",
        {"appDataEncryptionType": "whenDeviceLocked",
         "faceIdBlocked": False,
         "thirdPartyKeyboardsBlocked": False},
        IOS_APPS, "#microsoft.graph.iosMobileAppIdentifier", "bundleId"),
    app_protection("#microsoft.graph.androidManagedAppProtection",
        "VCIO-APP-Android-Baseline",
        f"VCIO CA Framework companion MAM baseline (DPF Level 2). Required by CA202. {APP_ASSIGN_NOTE}",
        {"encryptAppData": True,
         "screenCaptureBlocked": False,
         "disableAppEncryptionIfDeviceEncryptionIsEnabled": False,
         "minimumRequiredPatchVersion": "0000-00-00"},
        ANDROID_APPS, "#microsoft.graph.androidMobileAppIdentifier", "packageId"),
]

WINDOWS_APP_POLICY = {
    "@odata.type": "#microsoft.graph.windowsManagedAppProtection",
    "id": gid("app:VCIO-APP-Windows-Edge-Baseline"),
    "displayName": "VCIO-APP-Windows-Edge-Baseline",
    "description": "VCIO CA Framework companion Windows MAM (Edge) policy. Required by CA301. Assign to All Users, NO filter (Windows has no managed-app filters; MDM-enrolled devices yield to MDM, and CA301 targets unmanaged only).",
    "createdDateTime": STAMP, "lastModifiedDateTime": STAMP,
    "version": None, "roleScopeTagIds": ["0"],
    # NOTE: windowsManagedAppProtection has its own property names and enums —
    # NOT the iOS/Android ones. Outbound/clipboard accept only allApps|none.
    "periodOfflineBeforeAccessCheck": "PT12H",
    "periodOfflineBeforeWipeIsEnforced": "P90D",
    "allowedInboundDataTransferSources": "allApps",
    "allowedOutboundClipboardTransferLevel": "none",
    "allowedOutboundDataTransferDestinations": "none",
    "appActionIfUnableToAuthenticateUser": "block",
    "printBlocked": True,
    "isAssigned": False,
    "apps": [{"id": "com.microsoft.edge.windows",
               "mobileAppIdentifier": {"@odata.type": "#microsoft.graph.windowsAppIdentifier",
                                        "windowsAppId": "com.microsoft.edge"}}],
}

# ===================== named locations =====================
def country_location(nid, name, countries):
    return {
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "id": nid, "displayName": name,
        "createdDateTime": STAMP, "modifiedDateTime": STAMP, "deletedDateTime": None,
        "countriesAndRegions@odata.type": "#Collection(String)",
        "countriesAndRegions": countries,
        "includeUnknownCountriesAndRegions": False,
        "countryLookupMethod@odata.type": "#microsoft.graph.countryLookupMethodType",
        "countryLookupMethod": "clientIpAddress",
    }

def ip_location(nid, name, cidrs, trusted=False):
    return {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "id": nid, "displayName": name,
        "createdDateTime": STAMP, "modifiedDateTime": STAMP, "deletedDateTime": None,
        "isTrusted": trusted,
        "ipRanges@odata.type": "#Collection(microsoft.graph.ipRange)",
        "ipRanges": [{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": c} for c in cidrs],
    }

NAMED_LOCATIONS = [
    country_location(NL_COUNTRIES, "VCIO-NL-AllowedCountries", ["US"]),   # DEPLOYMENT PARAMETER
    ip_location(NL_SA_IPS, "VCIO-NL-ServiceAccountIPs", ["203.0.113.0/24"]),  # PARAMETER (RFC5737 placeholder)
    ip_location(NL_EGRESS, "VCIO-NL-TrustedEgress", ["203.0.113.0/24"]),      # PARAMETER (RFC5737 placeholder)
]
# Template-scope: Templates/NamedLocations/, never bulk-imported. Exists so the
# CA500 SYSTEMNAME template has a resolvable reference in the repo tree.
TEMPLATE_NAMED_LOCATIONS = [
    ip_location(NL_SA_SYSTEM, "VCIO-NL-SA-SYSTEMNAME", ["203.0.113.0/24"]),
]

# ===================== write everything =====================
def write(path, obj):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")

def group_object(name, gid_, description):
    return {
        "id": gid_, "displayName": name, "description": description,
        "createdDateTime": STAMP, "renewedDateTime": STAMP,
        "deletedDateTime": None, "classification": None, "expirationDateTime": None,
        "groupTypes": [], "infoCatalogs": [], "isAssignableToRole": None,
        "mail": None, "mailEnabled": False,
        "mailNickname": gid_.split("-")[0],
        "membershipRule": None, "membershipRuleProcessingState": None,
        "proxyAddresses": [], "resourceBehaviorOptions": [], "resourceProvisioningOptions": [],
        "securityEnabled": True, "theme": None, "visibility": None, "uniqueName": None,
        "onPremisesProvisioningErrors": [], "serviceProvisioningErrors": [],
    }

# Placeholder SOURCE tenant GUID. Deliberately not all-zeros (IntuneManagement
# treats a zero TenantId as an absent/invalid table) and deliberately not any
# real tenant, so the tool sees a cross-tenant import and remaps every group ID.
SOURCE_TENANT = "a11a11a1-vci0-0000-0000-000000000001".replace("vci0", "b2c3")


def write_tree():
    count = 0
    for target, display, pol in POLICIES:
        write(f"{target}/{display}.json", pol)
        count += 1

    core = {n: m for n, m in GROUPS.items() if m["scope"] == "core"}
    for name, meta in GROUPS.items():
        folder = "Config/Groups" if meta["scope"] == "core" else "Templates/Groups"
        write(f"{folder}/{name}.json", group_object(name, meta["id"], meta["description"]))

    for nl in NAMED_LOCATIONS:
        write(f"Config/NamedLocations/{nl['displayName']}.json", nl)
    for nl in TEMPLATE_NAMED_LOCATIONS:
        write(f"Templates/NamedLocations/{nl['displayName']}.json", nl)

    for ap in APP_POLICIES + [WINDOWS_APP_POLICY]:
        write(f"Config/AppProtection/{ap['displayName']}.json", ap)
    for flt in ASSIGNMENT_FILTERS:
        write(f"Config/AssignmentFilters/{flt['displayName']}.json", flt)

    # Template-scope groups are NOT in the migration table — Templates/ is never
    # bulk-imported, and an instance carries its own table (see --instance).
    migration = {
        "TenantId": SOURCE_TENANT,
        "Objects": [{"DisplayName": n, "Id": m["id"], "Type": "Group"} for n, m in core.items()],
    }
    write("Config/MigrationTable.json", migration)
    # Overlay imports as a separate IntuneManagement run — it needs its own copy
    # of the migration table to remap group references.
    write("Config-Overlay-P2/MigrationTable.json", migration)

    print(f"Generated {count} policies, {len(core)} core groups "
          f"(+{len(GROUPS) - len(core)} template-scope), "
          f"{len(NAMED_LOCATIONS)} named locations.")
    print(f"Version {VERSION}")


# ===================== template instantiation (A9/A11) =====================
# Instantiating a template is a CREATE, never a rename. Each instance gets its
# own displayName, its own policy GUID, and its own exclusion group that no
# other policy references — the structural rule the validators enforce. The
# 500/501 pair additionally gets a per-system scope group and named location.
#
#   build/generate.py --instance 801 Salesforce
#   build/generate.py --instance 500 BACKUP
#
# Output lands in Deploy/instances/ (gitignored) so the repo tree never grows an
# instance, and the MigrationTable there accumulates across runs so a set of
# instances imports as one IntuneManagement batch.
INSTANCE_PLACEHOLDER = {"500": "SYSTEMNAME", "501": "SYSTEMNAME",
                        "800": "APPNAME", "801": "APPNAME",
                        "802": "APPNAME", "803": "APPNAME"}


def instantiate(nnn, name, outdir):
    if nnn not in INSTANCE_PLACEHOLDER:
        sys.exit(f"CA{nnn} is not an instantiable template. "
                 f"Choose one of: {', '.join(sorted(INSTANCE_PLACEHOLDER))}")
    placeholder = INSTANCE_PLACEHOLDER[nnn]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9-]*$", name):
        sys.exit("Instance name must be alphanumeric with hyphens (it becomes part "
                 "of a displayName and a group name).")
    if name.upper() == placeholder:
        sys.exit(f"'{name}' is the placeholder itself, not an instance name.")

    src = next((pol for target, display, pol in POLICIES
                if target == T and display.startswith(f"CA{nnn}-VCIO-")), None)
    if src is None:
        sys.exit(f"No shipped template for CA{nnn}.")

    pol = json.loads(json.dumps(src))          # deep copy; templates stay untouched
    display = pol["displayName"].replace(placeholder, name)
    pol["displayName"] = display
    pol["id"] = gid("policy:" + display)

    objects, groups_out, locations_out = [], [], []

    def new_group(gname, desc):
        gid_ = gid("group:" + gname)
        groups_out.append(group_object(gname, gid_, desc))
        objects.append({"DisplayName": gname, "Id": gid_, "Type": "Group"})
        return gid_

    users = pol["conditions"]["users"]

    # Every instance carries its own exclusion group. Reusing another policy's
    # is the chaining defect the framework exists to prevent.
    excl_name = f"SG-CA-Excl-CA{nnn}-{name}"
    users["excludeGroups"] = list(users.get("excludeGroups") or []) + [
        new_group(excl_name,
                  f"Exclusion group for {display}. Ships empty. Named owner, "
                  f"quarterly access review, alert on membership change required.")]

    if nnn in ("500", "501"):
        scope_name = f"SG-CA-SA-{name}"
        scope_id = gid("group:" + scope_name)
        if scope_name not in {o["DisplayName"] for o in objects}:
            groups_out.append(group_object(
                scope_name, scope_id,
                f"Per-system service accounts for {name} (fencing Mode Per-System). "
                f"Every member is ALSO a member of SG-CA-ServiceAccounts, which "
                f"carries the CA002 exemption. Fenced by CA500-VCIO-"
                f"ServiceAccounts-IPFence-{name} to VCIO-NL-SA-{name} only."))
            objects.append({"DisplayName": scope_name, "Id": scope_id, "Type": "Group"})
        users["includeGroups"] = [scope_id if g == GROUPS["SG-CA-SA-SYSTEMNAME"]["id"]
                                  else g for g in users.get("includeGroups") or []]

    if nnn == "500":
        loc_name = f"VCIO-NL-SA-{name}"
        loc_id = gid("nl:" + loc_name)
        locations_out.append(ip_location(loc_id, loc_name, ["203.0.113.0/24"]))
        loc = pol["conditions"]["locations"]
        loc["excludeLocations"] = [loc_id if l == NL_SA_SYSTEM else l
                                   for l in loc.get("excludeLocations") or []]

    def out(rel, obj):
        full = os.path.join(ROOT, outdir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"  wrote {os.path.normpath(os.path.join(outdir, rel))}")

    out(f"ConditionalAccess/{display}.json", pol)
    for g in groups_out:
        out(f"Groups/{g['displayName']}.json", g)
    for nl in locations_out:
        out(f"NamedLocations/{nl['displayName']}.json", nl)

    # Append to the instance MigrationTable, keeping earlier instances.
    mt_path = os.path.join(ROOT, outdir, "MigrationTable.json")
    existing = []
    if os.path.exists(mt_path):
        with open(mt_path, encoding="utf-8") as f:
            existing = json.load(f).get("Objects", [])
    seen = {o["Id"] for o in existing}
    existing += [o for o in objects if o["Id"] not in seen]
    out("MigrationTable.json", {"TenantId": SOURCE_TENANT, "Objects": existing})

    print(f"\nInstantiated {display}.")
    print("Next: set the target app id / IP ranges, then import this folder with "
          "IntuneManagement (Replace Dependency IDs checked).")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--instance":
        if len(args) < 3:
            sys.exit("usage: generate.py --instance <nnn> <NAME> [--out DIR]")
        outdir = "Deploy/instances"
        if "--out" in args:
            outdir = args[args.index("--out") + 1]
        instantiate(args[1], args[2], outdir)
    elif args:
        sys.exit(f"unknown arguments: {' '.join(args)}")
    else:
        write_tree()
