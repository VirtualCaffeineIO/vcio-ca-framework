#!/usr/bin/env python3
"""VCIO CA Framework — policy generator.
Generates IntuneManagement-compatible JSON from the policy spec.
Deterministic GUIDs (uuid5) so rebuilds are stable. UTF-8, no BOM, LF.
"""
import json, uuid, os, sys

NS = uuid.UUID("6f1c8f6e-2b1a-4c1e-9e7b-vcio0000ca00".replace("vcio0000ca00", "0a1b2c3d4e5f"))
ROOT = os.path.join(os.path.dirname(__file__), "..")
VERSION = "2026.7.1"
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

GUEST_ALL = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
GUEST_NO_SP = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser"

FILTER_MANAGED_OR = 'device.deviceOwnership -eq "Company" -or device.isCompliant -eq True'
FILTER_MANAGED_AND = 'device.isCompliant -eq True -and device.deviceOwnership -eq "Company"'

# ---------- core groups ----------
GROUPS = {}
def group(name, desc):
    GROUPS[name] = {"id": gid("group:" + name), "description": desc}
    return GROUPS[name]["id"]

BG = group("SG-CA-BreakGlass", "Break-glass emergency access accounts. Excluded from all VCIO CA policies. FIDO2-credentialed, sign-in alerting mandatory, quarterly access test.")
USERS = group("SG-CA-Users", "DEPLOYMENT PARAMETER: replace membership with the customer's dynamic all-employees rule. Persona group for the 200s/300s policies.")
SA = group("SG-CA-ServiceAccounts", "User-shaped service accounts (transition state). IP-fenced by CA500; excluded from CA002 interactive MFA by design. Access-reviewed.")

def excl(nnn, policy_name):
    return group(f"SG-CA-Excl-CA{nnn}", f"Exclusion group for {policy_name}. Ships empty. Named owner, quarterly access review, alert on membership change required.")

# ---------- named locations ----------
NL_COUNTRIES = gid("nl:VCIO-NL-AllowedCountries")
NL_SA_IPS = gid("nl:VCIO-NL-ServiceAccountIPs")
NL_EGRESS = gid("nl:VCIO-NL-TrustedEgress")

# ---------- JSON assembly helpers ----------
def users_block(include_users=None, include_groups=None, exclude_groups=None,
                include_roles=None, guests=None):
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
        "excludeRoles": [],
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
add(C, "001", "Global-BlockDeviceCodeFlow-AuthTransfer",
    users=users_block(include_users=["All"]), apps=apps_block(["All"]),
    auth_flows="deviceCodeFlow,authenticationTransfer", grant_ctl=grant(builtin=["block"]))
add(C, "002", "Global-MFA",
    users=users_block(include_users=["All"], exclude_groups=[SA]),
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

# ===================== 100s Privileged / Tier 0 =====================
add(C, "100", "Privileged-PhishingResistantMFA",
    users=users_block(include_roles=ADMIN_ROLES), apps=apps_block(["All"]),
    grant_ctl=grant(strength=AUTHSTR_PR))
add(C, "101", "Privileged-CompliantDevice",
    users=users_block(include_roles=ADMIN_ROLES),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    grant_ctl=grant(builtin=["compliantDevice"]))
add(C, "102", "Privileged-SessionHygiene",
    users=users_block(include_roles=ADMIN_ROLES), apps=apps_block(["All"]),
    grant_ctl=None, session_ctl=session(sif_hours=8, pb_never=True))
add(C, "103", "Tier0-ControlPlane-AllUsers",
    users=users_block(include_users=["All"]),
    apps=apps_block([AZRM, PORTALS]),
    grant_ctl=grant(operator="AND", builtin=["compliantDevice"], strength=AUTHSTR_PR))

# ===================== 200s Managed users =====================
add(C, "200", "Users-Windows-CompliantDevice",
    users=users_block(include_groups=[USERS]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    platforms=platforms_block(["windows"]), client_apps=("mobileAppsAndDesktopClients",),
    grant_ctl=grant(builtin=["compliantDevice"]))
add(C, "201", "Users-macOS-CompliantDevice",
    users=users_block(include_groups=[USERS]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    platforms=platforms_block(["macOS"]), client_apps=("mobileAppsAndDesktopClients",),
    grant_ctl=grant(builtin=["compliantDevice"]))
add(C, "202", "Users-Mobile-AppProtection",
    users=users_block(include_groups=[USERS]), apps=apps_block([O365]),
    platforms=platforms_block(["android", "iOS"]),
    client_apps=("browser", "mobileAppsAndDesktopClients"),
    devices=devices_filter("exclude", FILTER_MANAGED_AND),
    grant_ctl=grant(builtin=["compliantApplication"]))
add(C, "203", "Users-MFA-IntuneEnrollment",
    users=users_block(include_groups=[USERS]), apps=apps_block([INTUNE_ENROLL]),
    grant_ctl=grant(builtin=["mfa"]), session_ctl=session(sif_everytime=True))
add(C, "204", "Users-SessionHygiene-Unmanaged",
    users=users_block(include_groups=[USERS]), apps=apps_block(["All"]),
    devices=devices_filter("exclude", FILTER_MANAGED_OR),
    session_ctl=session(sif_hours=12, pb_never=True))

# ===================== 300s BYOD contained path =====================
add(C, "300", "BYOD-BrowserSessionControls",
    users=users_block(include_groups=[USERS]), apps=apps_block([O365]),
    client_apps=("browser",), devices=devices_filter("exclude", FILTER_MANAGED_OR),
    session_ctl=session(aer=True))
add(C, "301", "BYOD-Windows-RequireAppProtection",
    users=users_block(include_groups=[USERS]), apps=apps_block([O365]),
    platforms=platforms_block(["windows"]), client_apps=("browser",),
    devices=devices_filter("exclude", FILTER_MANAGED_OR),
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
add(C, "403", "Guests-BlockAdminPortals",
    users=users_block(guests=GUEST_ALL), apps=apps_block([PORTALS]),
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
add(C, "601", "Agents-BlockHighRisk",
    users=users_block(include_users=["None"]), apps=apps_block(["All"]),
    agent_risk="high", grant_ctl=grant(builtin=["block"]), exclude_bg=False, own_excl=False)
add(C, "602", "Agents-CompliantDevice-AgentUsers",
    users=users_block(include_users=["None"]), apps=apps_block(["All"]),
    agents={"@odata.type": "#microsoft.graph.conditionalAccessAgents",
            "includeAgentUsers": ["All"], "excludeAgentUsers": [], "agentFilter": None},
    grant_ctl=grant(builtin=["compliantDevice"]), exclude_bg=False, own_excl=False)

# ===================== 700s P2 overlay =====================
OV = "Config-Overlay-P2/ConditionalAccess"
add(OV, "700", "Risk-BlockHighUserRisk",
    users=users_block(include_users=["All"], exclude_groups=[SA]), apps=apps_block(["All"]),
    user_risk=["high"], grant_ctl=grant(builtin=["block"]))
add(OV, "701", "Risk-BlockHighSignInRisk",
    users=users_block(include_users=["All"], exclude_groups=[SA]), apps=apps_block(["All"]),
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
# Deploy INSTEAD OF CA200/CA201 where hybrid join is a recognized stop-gap.
# Same exclusion group as the counterpart (only one of the pair is ever live).
# Record an exit date in the parameters worksheet.
TR = "Transition/ConditionalAccess"
add(TR, "200", "Users-Windows-CompliantOrHybrid-TRANSITION",
    users=users_block(include_groups=[USERS], exclude_groups=[gid("group:SG-CA-Excl-CA200")]),
    apps=apps_block(["All"], exclude=[INTUNE, INTUNE_ENROLL]),
    platforms=platforms_block(["windows"]), client_apps=("mobileAppsAndDesktopClients",),
    grant_ctl=grant(builtin=["compliantDevice", "domainJoinedDevice"]), own_excl=False)
# (No macOS transition variant — hybrid join does not exist on macOS.)

# ===================== 800s Extension templates =====================
add(T, "800", "Ext-Restricted-APPNAME",
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    grant_ctl=grant(builtin=["compliantDevice"]), own_excl=False)
add(T, "801", "Ext-StepUp-APPNAME",
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    grant_ctl=grant(operator="OR", builtin=["compliantDevice", "mfa"]), own_excl=False)
add(T, "802", "Ext-Fenced-APPNAME",
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    locations=locations_block(["All"], [NL_EGRESS]),
    devices=devices_filter("exclude", FILTER_MANAGED_OR),
    grant_ctl=grant(builtin=["block"]), own_excl=False)
add(T, "803", "Ext-MobileMAM-APPNAME",
    # Mobile access to the named app from personal devices only inside a
    # containerized (APP-protected) client. PREREQ: the app must support Intune
    # APP (SDK-integrated or wrapped) AND be added to the VCIO-APP baselines'
    # targeted apps (or its own APP policy if settings differ).
    users=users_block(include_groups=[USERS]), apps=apps_block([APP_PLACEHOLDER]),
    platforms=platforms_block(["android", "iOS"]),
    client_apps=("browser", "mobileAppsAndDesktopClients"),
    devices=devices_filter("exclude", FILTER_MANAGED_AND),
    grant_ctl=grant(builtin=["compliantApplication"]), own_excl=False)

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

# ===================== write everything =====================
def write(path, obj):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")

count = 0
for target, display, pol in POLICIES:
    write(f"{target}/{display}.json", pol)
    count += 1

for name, meta in GROUPS.items():
    write(f"Config/Groups/{name}.json", {
        "id": meta["id"], "displayName": name, "description": meta["description"],
        "createdDateTime": STAMP, "renewedDateTime": STAMP,
        "deletedDateTime": None, "classification": None, "expirationDateTime": None,
        "groupTypes": [], "infoCatalogs": [], "isAssignableToRole": None,
        "mail": None, "mailEnabled": False,
        "mailNickname": meta["id"].split("-")[0],
        "membershipRule": None, "membershipRuleProcessingState": None,
        "proxyAddresses": [], "resourceBehaviorOptions": [], "resourceProvisioningOptions": [],
        "securityEnabled": True, "theme": None, "visibility": None, "uniqueName": None,
        "onPremisesProvisioningErrors": [], "serviceProvisioningErrors": [],
    })

for nl in NAMED_LOCATIONS:
    write(f"Config/NamedLocations/{nl['displayName']}.json", nl)

for ap in APP_POLICIES + [WINDOWS_APP_POLICY]:
    write(f"Config/AppProtection/{ap['displayName']}.json", ap)

for flt in ASSIGNMENT_FILTERS:
    write(f"Config/AssignmentFilters/{flt['displayName']}.json", flt)

migration = {
    # Placeholder SOURCE tenant GUID. Deliberately not all-zeros (IntuneManagement
    # treats a zero TenantId as an absent/invalid table) and deliberately not any
    # real tenant, so the tool sees a cross-tenant import and remaps every group ID.
    "TenantId": "a11a11a1-vci0-0000-0000-000000000001".replace("vci0", "b2c3"),
    "Objects": [{"DisplayName": n, "Id": m["id"], "Type": "Group"} for n, m in GROUPS.items()],
}
write("Config/MigrationTable.json", migration)
# Overlay imports as a separate IntuneManagement run — it needs its own copy
# of the migration table to remap group references.
write("Config-Overlay-P2/MigrationTable.json", migration)

print(f"Generated {count} policies, {len(GROUPS)} groups, {len(NAMED_LOCATIONS)} named locations.")
print(f"Version {VERSION}")
