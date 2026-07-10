# Changelog

Date-based versioning: `YYYY.M.R` (year, month, release-in-month).

## 2026.7.1 — 2026-07-09 (initial release)

**Lab-validated:** full import via IntuneManagement into a live tenant — 27 core + 6 overlay policies, 32 groups (created by dependency resolution), 3 named locations, agent-condition policies (CA600–602, CA704) and token protection (CA705) accepted by Graph; structural canaries verified in the portal (CA103 AND-grant with phishing-resistant strength + compliant device; CA203 every-time sign-in frequency); prereqs post-import gate green.

### Contents
* 27 core policies (Entra ID P1), 6 overlay policies (P2), 4 per-app extension templates (Restricted / Step-Up / Fenced / MAM-Mobile), 1 hybrid transition variant.
* 32 groups — break-glass, users persona, service accounts, one exclusion group per policy — with governance requirements embedded in group descriptions.
* 3 named locations, all deployment parameters (RFC 5737 placeholder IPs match nothing real).
* Companion App Protection baseline (iOS, Android, Windows/Edge) aligned to Microsoft Data Protection Framework Level 2, plus iOS/Android unmanaged-device managed-app assignment filters (no Windows filter — managed-app filters do not exist for Windows; Windows MAM assigns unfiltered by MDM-coexistence design).
* Prereqs script (`-Fix`, stage auto-detection, Graph SDK self-install): security defaults, break-glass verification, Intune Enrollment SP, TAP enablement, assignment filters, and App Protection creation via Graph — including the Windows MAM type, which IntuneManagement cannot import.
* Release validators (Python + PowerShell): inert scopes, GUID wiring, exclusion-group reuse, break-glass exclusions, encoding, placeholder escapes.
* Docs: implementation guide (A–E walkthrough with expected outputs), deployment parameters worksheet, operating runbook (four-ring enablement), onboarding (TAP / Autopilot hierarchy).

### Field notes from lab validation
* IntuneManagement imports iOS/Android App Protection but not `windowsManagedAppProtection` — prereqs script creates it via Graph.
* Managed-app assignment filters exist for iOS/Android only; `windowsMobileApplicationManagement` filter creation is rejected by Graph.
* Groups are dependency objects in IntuneManagement — no "Groups" import row; created during CA import via Replace Dependency IDs.
* Embedded sign-in windows and passwordless-only admin accounts don't mix — registration interrupts must be cleared in a real browser first (documented in the implementation guide).
