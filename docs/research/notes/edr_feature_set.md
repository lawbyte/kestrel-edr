# Commercial EDR/XDR Feature Set for Organizations Protecting Windows Endpoints (2025-2026): Feature Scope for a New EDR Product

Research date: 2026-10-20. Vendors in scope: CrowdStrike Falcon Insight, Microsoft Defender for Endpoint (P1/P2/Business), SentinelOne Singularity, Sophos Intercept X / Sophos Endpoint, Elastic Security (Elastic Defend), Huntress Managed EDR, Bitdefender GravityZone, Wazuh (open source).

Note on sources: vendor pricing and marketing pages are primary sources for what the vendor *claims*. Several third-party summaries (cybervigilance.uk, casrai.org, costbench.com, trustedtechteam.com) are secondary sources and are flagged where used. Where a fetch of a primary doc failed, that is noted in Gaps.

---

## Q1. Core endpoint features across leading vendors (inventory, deployment, policies, prevention modes, alerts/incidents, process tree, hunting, timeline, response actions, rollback, IOCs, exclusions, vuln/software inventory, device control, firewall, web protection, app control)

### Takeaway
Gartner's baseline for an endpoint protection platform is malware and fileless-attack prevention, attack surface reduction (device control, host firewall), and behavioral detection/blocking. Integrated EDR (telemetry, custom detections, investigation, remediation), vulnerability/risk reporting, and MDR wrappers are the "common features of top products." Every leading vendor ships host isolation, process kill/remediation, file quarantine/retrieval, a remote shell, IOC allow/block lists, and MITRE ATT&CK-mapped alerts with a process tree. SentinelOne (VSS-based) and Sophos (CryptoGuard) differentiate with ransomware **rollback**. Device control and firewall management have moved down into the cheapest bundles: CrowdStrike Falcon Go and Microsoft P1 both include them.

### Cited Findings

**Market baseline (Gartner EPP definition)**
- Gartner 2025 MQ for EPP lists three mandatory features: "Protection against malware and file-less attacks using endpoint real-time scanning and anti-malware techniques"; "Endpoint attack surface reduction capabilities, such as device control, host firewall"; and "Detection and blocking of endpoint threats using behavioral analysis of endpoint, application and end-user activity." — [Spotlight AR summary of Gartner MQ EPP 2025 market definition](https://research.oz.spotlightar.com/reports/magic-quadrant-endpoint-protection-platforms-2025/market-definition) (secondary reproduction of the Gartner text)
- Gartner 2024 "common features of top products": management/reporting of OS security controls (host firewall, device control, endpoint encryption); endpoint vulnerability assessment and risk reporting based on inventory, configuration, patch and policy data; "Integrated endpoint detection and response (EDR) functionality" (telemetry collection, detection customization, investigation, remediation); and partner/vendor service wrappers such as MDR and co-managed monitoring. — [Spotlight AR summary of Gartner MQ EPP 2024 market definition](https://research.oz.spotlightar.com/reports/magic-quadrant-endpoint-protection-platforms-2024/market-definition)
- The 2025 Gartner MQ for EPP is dated 14 July 2025. SentinelOne was named a Leader for the 5th consecutive year, and Sophos says it was one of 15 vendors evaluated. — [SentinelOne/BusinessWire](https://www.businesswire.com/news/home/20250715681086/en/SentinelOne-Named-a-Leader-in-2025-Gartner-Magic-Quadrant-for-Endpoint-Protection-Platforms-for-5th-consecutive-year); [Sophos blog](https://sophos.com/en-us/blog/sweet-16-sophos-named-a-leader-again-in-the-2025-gartner-magic-quadrant-for-endpoint-protection-platforms)
- The 2026 Gartner MQ for EPP is dated 26 May 2026. SentinelOne (6th year), Sophos (17th consecutive report), and CrowdStrike each claim Leader placement. — [SentinelOne press](https://www.sentinelone.com/press/sentinelone-named-a-leader-in-the-gartner-magic-quadrant-for-endpoint-protection-platforms-for-6th-consecutive-year/); [Sophos press release May 2026](https://www.sophos.com/en-us/press/press-releases/2026/05/sophos-named-a-leader-in-the-2026-gartner-magic-quadrant-for-endpoint-protection-platforms); [CrowdStrike industry validation page](https://www.crowdstrike.com/en-au/why-crowdstrike/crowdstrike-industry-validation/)
- In its 2026 MQ announcement, SentinelOne highlighted lateral movement mitigation, expanded DNS telemetry, in-process memory threat detection, and acquisitions for AI-usage control (Prompt Security). These signal where the "advanced" tier is heading. — [SentinelOne press](https://www.sentinelone.com/press/sentinelone-named-a-leader-in-the-gartner-magic-quadrant-for-endpoint-protection-platforms-for-6th-consecutive-year/)

**Microsoft Defender for Endpoint / Defender for Business**
- Feature split by plan. **MDB**: ASR, NGP, EDR ("optimized"), automated investigation and remediation (AIR), automatic attack disruption, threat analytics, core vulnerability management, monthly security summary, simplified firewall/AV config. **P1**: ASR, NGP, APIs, centralized management only (no EDR, AIR, or vuln mgmt). **P2**: all of the above plus advanced hunting with 30 days of data and 6-month retention, and Microsoft Threat Experts. All three include APIs, multitenant management, and Lighthouse for CSPs. Servers need extra licenses. MDB is capped at 300 users. — [Microsoft Learn: MDB overview](https://learn.microsoft.com/defender-business/mdb-overview)
- Device response actions: manage tags, initiate automated investigation, live response session, collect investigation package (autoruns, processes, connections, event logs), AV scan, restrict app execution (allows only Microsoft-signed code via a code integrity policy), isolate device (full or *selective* with exclusions), contain device (blocks other onboarded devices from talking to it), consult threat expert, and an Action Center with history. P1 only gets AV scan, isolate, stop-and-quarantine file, and file indicators. MDB lacks "stop and quarantine file." Isolation auto-lifts after 7 days. Full-tunnel VPNs can break isolated-device cloud connectivity. — [Microsoft Learn: Take response actions on a device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- Live response (P2 only). Basic commands: `dir`, `getfile`, `processes`, `connections`, `persistence`, `registry`, `scheduledtasks`, `services`, etc. Advanced commands: `run` (library PowerShell scripts), `putfile`, `remediate` (file/process/service/registry/scheduled task/startup), `undo`, `analyze`. Signed PowerShell is required by default. Every command is logged per session. Limits: 50 concurrent sessions per tenant, 5 per user, 1 per device, 30-minute idle timeout, 3 GB `getfile`. — [Microsoft Learn: Live response](https://learn.microsoft.com/en-us/defender-endpoint/live-response)
- Indicators (IOCs): types are file hash, IP, URL/domain, and certificate. Actions are Allow, Audit, Warn (user-bypassable), Block execution, and Block and remediate. Hard limit of 15,000 indicators per tenant. Each indicator is scoped to device groups. Microsoft recommends WDAC/AppLocker for blocking applications rather than hash indicators, because hashes change per version. — [Microsoft Learn: Indicators overview](https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview)
- Device control covers removable storage (anything that creates a drive letter), WPD, printers (VID/PID, type), and Bluetooth (pairing/services). Read/write/execute access can be set per device, user group, network location (corporate/VPN), or file type. Audit vs Deny entries are logged to Advanced Hunting (`RemovableStoragePolicyTriggered`). Also available: BitLocker-encrypted-media conditions (preview) and Purview Endpoint DLP. Managed via Intune, the Defender portal, or GPO. Supports Windows 10/11 but not Windows Server. Included in P1, P2, and MDB. — [Microsoft Learn: Device control overview](https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview)
- Windows onboarding methods: local script (up to 10 devices), Intune/MDM, Configuration Manager, Group Policy, VDI scripts, and the Defender deployment tool. Repackaging the installer is unsupported because it triggers tampering alerts. — [Microsoft Learn: Onboard Windows client](https://learn.microsoft.com/en-us/defender-endpoint/onboard-windows-client)

**CrowdStrike Falcon**
- Falcon Go ($59.99/device/yr, max 100 devices), Pro ($99.99), and Enterprise ($184.99) all list NGAV, EDR, Device Control, Firewall Management, Threat Intelligence & Hunting, and Identity Protection. Enterprise adds expert hunting. Falcon Complete (MDR) is contact-sales and includes a Breach Prevention Warranty. — [CrowdStrike pricing](https://www.crowdstrike.com/en-us/pricing/)
- Falcon Insight XDR capabilities: process tree, Real Time Response (remote remediation), Falcon Fusion SOAR, Charlotte AI, attack path visibility with MITRE ATT&CK mapping, cross-domain identity/cloud context, and 10 GB/day free third-party ingest. — [CrowdStrike Falcon Insight XDR page](https://www.crowdstrike.com/en-us/platform/endpoint-security/falcon-insight-xdr/)
- RTR exposes read-only commands (`ls`, `ps`, `cat`, `filehash`, `reg`) separately from admin/remediation commands via distinct API scopes. A dedicated RTR audit API shows who ran what command on which host. — [CrowdStrike developer docs: Falcon MCP RTR module](https://developer.crowdstrike.com/falcon-mcp/modules/rtr/)

**SentinelOne Singularity**
- Tier ladder (secondary source): **Core** = NGAV + 1-click rollback (Windows) + 365 days of threat incident history. **Control** adds device control (USB, Bluetooth/BLE), firewall control, application inventory/vulnerability, and rogue/network discovery. **Complete** adds Storyline, Deep Visibility hunting by MITRE technique, STAR custom detection rules, remote shell, and 14 to 365+ days of EDR data. — [CyberVigilance (SentinelOne partner)](https://www.cybervigilance.uk/post/what-is-the-difference-between-sentinelone-core-control-and-complete)
- Current list prices: Complete $179.99/endpoint/yr with 14-day retention. Commercial $229.99 adds Identity Detection & Response, 90-day retention, and managed threat hunting. Enterprise is contact-sales. "Advanced EPP Controls (Device and Firewall Control, Remote Shell)" appear in the comparison table. — [SentinelOne pricing](https://www.sentinelone.com/pricing)
- How rollback works: the agent acts as a Windows VSS requestor. It snapshots right after install and every 4 hours by default, blocks VSS tampering, and can only restore files captured in a snapshot. Supported on Windows only (Vista / 2008 R2+). — [CyberVigilance: How does SentinelOne rollback work](https://www.cybervigilance.uk/post/sentinelone-how-does-rollback-work)

**Sophos Intercept X / Sophos Endpoint**
- Prevention features: CryptoGuard (detects malicious encryption, blocks the process, reverts encrypted files, plus MBR protection); Adaptive Attack Protection (switches to aggressive protection when an active hands-on-keyboard attacker is detected); 60+ exploit mitigations on by default; web protection and Web Control (including generative-AI acceptable-use categories); peripheral/device control (removable media, Bluetooth, mobile); application control by category; Account Health Check (posture drift, one-click fix); kernel-level tamper protection. — [Sophos Endpoint product page](https://www.sophos.com/en-us/products/endpoint-antivirus)
- Sophos EDR offers Live Discover (query live device data), Live Response (remote shell), and scheduled queries. Data lake retention is 7 days by default, or 30 with XDR, plus up to 90 days on-device (as of the 2021 EDR 4.0 release; may have changed). — [Sophos blog: What's new in Sophos EDR 4.0](https://www.sophos.com/en-us/blog/whats-new-in-sophos-edr-4-0)

**Elastic Security (Elastic Defend)**
- Response console actions: `isolate`/`release`, `kill-process`, `suspend-process`, `processes`, `get-file` (password-protected ZIP, 100 MB), `execute` (shell command), `upload`, `scan`, `memory-dump` (kernel/raw memory on Windows only), `cancel`, and `status`. Each requires a specific Kibana privilege (Host Isolation, Process Operations, File Operations, Execute Operations, Scan Operations). These granular privileges are a good RBAC model to copy. — [Elastic docs: Response actions](https://www.elastic.co/guide/en/security/current/response-actions.html)
- Elastic's subscription page lists malware, ransomware, memory threat, and behavior prevention, host isolation, interactive response console, and tamper protection, but per-tier mapping could not be extracted. — [Elastic subscriptions](https://www.elastic.co/subscriptions)

**Huntress Managed EDR**
- Features: persistent foothold detection (abuse of legitimate apps/autoruns), malicious process behavior analysis, ransomware canaries, external open-port detection, threat response (containment, active remediation, guided recovery), optional managed Microsoft Defender at no extra cost, a 24/7 SOC, and a claimed <1% false positive rate. — [Huntress Managed EDR page](https://www.huntress.com/platform/managed-edr-security-2)
- Host isolation can be applied to one machine or a whole organization, with exemption tags. Analysts always trigger it manually, never automatically. Remediation is often delivered as a one-click button in the dashboard. Process monitoring covers file-based and fileless malware. — [Huntress blog: Myths and misconceptions](https://www.huntress.com/blog/clearing-the-air-huntress-myths-and-misconceptions)
- "Assisted Remediation": a per-host ticket lists remediation steps. The partner approves them and the agent executes them automatically. Introduced in October 2019. — [Huntress press release](https://www.huntress.com/press-release/address-persistent-threats-faster-huntress-introduces-assisted-remediation)

**Bitdefender GravityZone**
- Tiers: Business Security (prevention engine, auto block/quarantine); Business Security Premium (adds EDR root-cause view, risk analytics, analyst-initiated containment); Business Security Enterprise (adds XDR telemetry and threat-hunting queries). Patch management is an add-on at all tiers. — [casrai.org guide (secondary)](https://casrai.org/guides/bitdefender-gravityzone-business-vs-premium)
- Risk Management provides a misconfiguration plus app-vulnerability risk score, adjusted for vulnerabilities exploited in the customer's industry, and "human risk analytics" (password-policy non-compliance, high malware counts). Patch Management covers third-party apps. Full Disk Encryption is an add-on. — [Bitdefender vulnerability management page](https://bitdefender.com/business/gravityzone-platform/vulnerability-management)

**Wazuh (open source)**
- Capabilities: file integrity monitoring (including the Windows registry), malware detection (rootcheck, threat-intel lists, VirusTotal, YARA, AV log collection), Security Configuration Assessment, Active Response (automated actions), log collection, vulnerability detection, command monitoring, container security, system inventory (hardware/software), syscall auditing, agentless monitoring. Compliance guides cover PCI DSS, GDPR, HIPAA, NIST 800-53, and TSC (SOC 2). Cloud monitoring covers AWS, Azure, GCP, GitHub, and Office 365. — [Wazuh docs: Capabilities](https://documentation.wazuh.com/current/user-manual/capabilities/index.html)

### Inferences

**Proposed feature matrix (MVP / Standard / Advanced) with vendor implementations.** Tiering is my synthesis, based on what the cheapest commercial bundles include (MVP) versus mid-tier versus top-tier/add-on.

| # | Feature | Tier | How leaders implement it |
|---|---|---|---|
| 1 | Fleet/asset inventory (hostname, OS build, agent version, last seen, IP, user, health/sensor status, tags) | MVP | All vendors. MDE uses tags plus dynamic device groups. Wazuh's syscollector covers HW/SW inventory. |
| 2 | Agent deployment: signed MSI + GPO + Intune/MDM + SCCM + script; tenant/enrollment token; auto-update with rings | MVP | MDE: local script/GPO/Intune/ConfigMgr/VDI. Huntress: "pre-built scripts". Repackaging the vendor installer is discouraged. |
| 3 | Tamper protection / anti-uninstall (uninstall password/token) | MVP | Sophos kernel-level tamper protection. SentinelOne blocks VSS tampering. MDE tamper protection. |
| 4 | Policies and policy groups (assign by group/tag/OU), inheritance | MVP | MDE device groups (P1+). Sophos/S1 policy per group. |
| 5 | NGAV: signatures + ML + behavioral; on-access and on-demand scan | MVP | Gartner mandatory. All vendors. Wazuh is weak here (YARA/VirusTotal, no real NGAV). |
| 6 | Prevention mode per policy: Detect-only/Audit vs Protect/Block, per engine | MVP | MDE ASR Audit/Block/Warn. S1 Detect vs Protect. Device control Audit vs Deny. |
| 7 | Alert management: severity, status, assignment, MITRE ATT&CK tactic/technique tags, grouping into incidents | MVP | All. CrowdStrike "attack path + ATT&CK mapping". MDE incidents. |
| 8 | Process tree / storyline view per alert | MVP | CrowdStrike process tree. S1 Storyline (Complete tier). Sophos threat graph. Bitdefender root-cause view. |
| 9 | Host isolation (with allow-list for management/VPN/DNS) | MVP | MDE full and selective isolation, auto-release after 7 days. Elastic isolate/release. Huntress manual isolation with exemption tags. |
| 10 | Kill process, quarantine/delete file, restore from quarantine | MVP | MDE stop-and-quarantine (P1). Elastic `kill-process`. |
| 11 | IOC management: hash/IP/domain/URL/cert with Allow/Audit/Warn/Block, scoped to groups, CSV import | MVP | MDE indicators: 5 actions, 15k per-tenant limit. |
| 12 | Exclusions (path, hash, process, cert/signer, per-engine) | MVP | All vendors (no doc fetched in detail; see Gaps). |
| 13 | Ransomware-specific protection (canaries/honeyfiles, mass-encryption detection) | MVP | Huntress canaries. Sophos CryptoGuard. |
| 14 | Device timeline / raw telemetry search (process, file, registry, network, logon, DNS) with 7-30 day retention | Standard | MDE P2 30-day advanced hunting. S1 14-day (Complete). Sophos 7/30-day data lake. |
| 15 | Threat hunting query language + saved/scheduled queries + custom detection rules | Standard | MDE KQL. CrowdStrike Event Search/CQL. S1 Deep Visibility + STAR rules. Sophos Live Discover (osquery SQL). Elastic EQL/ES|QL. |
| 16 | Remote shell / live response with script library, get-file/put-file, full command audit | Standard | MDE live response (P2): signed scripts, per-session command log, concurrency limits. CrowdStrike RTR with read-only vs admin scopes. S1 Remote Shell. Elastic `execute`/`get-file`/`upload`. |
| 17 | Collect investigation/forensic package; memory dump | Standard | MDE investigation package. Elastic `memory-dump`. |
| 18 | Device control (USB storage R/W/X, WPD, Bluetooth, printers; allow by VID/PID/serial; audit vs deny) | Standard (now in entry bundles) | MDE (P1/MDB). CrowdStrike Go+. S1 Control+. Sophos peripheral control. |
| 19 | Host firewall management | Standard | CrowdStrike Go+. S1 Control+. MDB "simplified firewall". |
| 20 | Software inventory + vulnerability (CVE) assessment | Standard | MDE MDB/P2 core vuln mgmt. S1 Control app inventory. Bitdefender risk analytics. Wazuh vulnerability detection. |
| 21 | Web/network protection (malicious URL block, web category filtering) | Standard | Sophos web protection + Web Control (incl. GenAI categories). MDE network protection/web content filtering. |
| 22 | Application control (allow/block by category/publisher; "restrict app execution" emergency mode) | Standard → Advanced | Sophos app control by category. MDE restrict app execution (P2) + WDAC/AppLocker. |
| 23 | Exploit prevention / memory protection | Standard | Sophos 60+ mitigations. S1 in-process memory detection. |
| 24 | Ransomware rollback (VSS snapshot protect + restore) | Advanced (differentiator) | S1 1-click rollback (all tiers, Windows only, VSS every 4h). Sophos CryptoGuard file revert. |
| 25 | Automated investigation & remediation / auto-attack-disruption, SOAR playbooks | Advanced | MDE AIR + automatic attack disruption (MDB/P2). CrowdStrike Fusion SOAR. S1 Hyperautomation. |
| 26 | Identity threat detection (AD/Entra) | Advanced | S1 Commercial IDR. CrowdStrike Identity Protection. |
| 27 | Network discovery of unmanaged/rogue devices | Advanced | S1 Ranger (Control+). |
| 28 | Adaptive/dynamic hardening when an active adversary is detected | Advanced | Sophos Adaptive Attack Protection. Bitdefender PHASR. |
| 29 | AI assistant / agentic triage | Advanced | CrowdStrike Charlotte AI. S1 Purple AI / AI SOC Analyst. Sophos AI Assistant. |
| 30 | Managed service wrapper (MDR / managed hunting) | Advanced/service | Huntress (bundled). Falcon Complete. Sophos MDR. S1 Commercial managed hunting. MS Threat Experts. |
| 31 | Persistence/autoruns monitoring as a first-class view | MVP-friendly differentiator | Huntress persistent footholds. MDE live response `persistence` command. |
| 32 | FIM + Security Configuration Assessment (CIS benchmarks) | Standard (compliance-driven) | Wazuh FIM + SCA. Sophos Account Health Check. |

- **Minimum viable product.** An MVP that matches what MDE P1 and Falcon Go deliver needs NGAV/behavioral prevention, audit/block modes, IOC lists, exclusions, isolation, process kill/quarantine, device control, and firewall management. Shipping without device control or isolation would put a new product below the cheapest incumbent bundles.
- **Telemetry and hunting are the paywall.** Raw-telemetry search/hunting with retention and a remote shell sit behind the EDR tier everywhere (MDE P2 vs P1; S1 Complete vs Control). Vendors treat this as the main upsell.
- **Rollback is a real differentiator on Windows.** It is cheap to implement because it builds on VSS, but it requires protecting VSS from deletion (vssadmin/WMI shadow deletion). Only S1 and Sophos market it prominently.
- **Copy Elastic's privilege model.** Per-action RBAC (separate privileges for isolate, process ops, file ops, execute) is good design practice for live response.

### Gaps
- No primary-doc confirmation of exclusion types per vendor. The Microsoft ASR exclusions page fetch failed.
- Sophos EDR data retention figures date from 2021 and may have changed. The current Sophos XDR data lake retention was not confirmed.
- Elastic per-tier feature mapping could not be extracted from the subscriptions page. The PDF version at elastic.co/pdf/subscriptions-2026-08-04.pdf was not fetched.
- The SentinelOne Core/Control/Complete breakdown comes from a partner blog, not SentinelOne documentation.
- No primary-source detail on CrowdStrike RTR command tiers (Read-only / Active Responder / Admin role names) beyond API scopes.
- Bitdefender device control, firewall, and sandbox were not confirmed from Bitdefender primary pages in this session.

---

## Q2. Management console capabilities (RBAC, multi-tenancy, SSO/MFA, audit log, API, SIEM export, notifications, reporting, compliance mapping incl. MAS TRM and OJK)

### Takeaway
Enterprise buyers expect granular RBAC scoped to device groups, SSO through the corporate IdP (Entra ID/SAML), a full API, multi-tenant management for MSPs, auditable remote actions, and compliance reporting. In Singapore financial services, MAS TRM explicitly calls for endpoint protection, application whitelisting, authorized-media-only, a SOC or MSSP, log retention, and isolate/neutralize capability. In Indonesia, OJK POJK 11/2022 adds in-country data center hosting for banks, which directly affects cloud console/data-residency design.

### Cited Findings
- MDE RBAC model: custom roles with granular capabilities, scoped to device groups (by name, tag, domain) via Entra ID user groups. Microsoft describes a 3-tier SOC model (local Tier 1 triage, regional Tier 2 remediation, global Tier 3 full access). As of 16 Feb 2025, new customers get only Unified RBAC across Defender XDR. Entra Security Administrator maps to full access and Security Reader to read-only. PIM is recommended for Tier 0 assets. — [Microsoft Learn: RBAC](https://learn.microsoft.com/en-us/defender-endpoint/rbac)
- Live response access is RBAC-gated by basic vs advanced commands. Uploading scripts needs "Manage Security Settings." Session command logs show who ran what and when. — [Microsoft Learn: Live response](https://learn.microsoft.com/en-us/defender-endpoint/live-response)
- Multi-tenancy: MDB, P1, and P2 all include Microsoft Defender multitenant management and Microsoft 365 Lighthouse for CSPs. — [Microsoft Learn: MDB overview](https://learn.microsoft.com/defender-business/mdb-overview)
- Huntress sells exclusively through MSPs (end-customer pricing includes the MSP markup), so the MSP multi-tenant console is the core design center. — [Costbench (secondary)](https://costbench.com/software/endpoint-security/huntress/)
- CrowdStrike exposes an RTR audit API ("who used RTR, when, which host, which command") and fine-grained API scopes (RTR READ vs WRITE vs audit READ). — [CrowdStrike developer docs](https://developer.crowdstrike.com/falcon-mcp/modules/rtr/)
- CrowdStrike Falcon Insight includes 10 GB/day of free third-party data ingest and native Fusion SOAR, so the console acts as an integration hub. — [CrowdStrike Falcon Insight XDR](https://www.crowdstrike.com/en-us/platform/endpoint-security/falcon-insight-xdr/)
- Sophos MDR advertises 500+ integrations (endpoint, network, cloud, identity, email) and can operate over Microsoft Defender, CrowdStrike, or SentinelOne telemetry. A FAQ on the same page says "more than 350," so the figures are inconsistent. — [Sophos MDR page](https://www.sophos.com/en-us/products/managed-detection-and-response)
- Wazuh ships compliance mapping/dashboards for PCI DSS, GDPR, HIPAA, NIST 800-53, and TSC (SOC 2). — [Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/index.html)
- MDB/P2 include a "monthly security summary report." — [Microsoft Learn: MDB overview](https://learn.microsoft.com/defender-business/mdb-overview)

**MAS TRM Guidelines (Jan 2021), Singapore: requirements relevant to EDR (primary source)**
- 11.3.3: "Endpoint protection ... should be implemented to protect the FI from malware infection." It names infected removable media as a vector. 11.3.4: anti-malware signatures kept up to date and regular scanning. 11.3.5: proactive monitoring "for anomalies and suspicious activities." 11.3.6: "Security measures, such as application white-listing, should be implemented." — [MAS TRM Guidelines 2021 (PDF)](https://www.mas.gov.sg/-/media/MAS/Regulations-and-Financial-Stability/Regulatory-and-Supervisory-Framework/Risk-Management/TRM-Guidelines-18-January-2021.pdf)
- 11.1.4: "only authorised data storage media, systems and endpoint devices are used to communicate" (maps to device control). — [MAS TRM 2021](https://www.mas.gov.sg/-/media/MAS/Regulations-and-Financial-Stability/Regulatory-and-Supervisory-Framework/Risk-Management/TRM-Guidelines-18-January-2021.pdf)
- 12.2.1: "establish a security operations centre or acquire managed security services." 12.2.2: a process to "collect, process, review and retain system logs." 12.2.4: "consider applying user behavioural analytics." 12.3.1: an incident response plan to "swiftly isolate and neutralise a cyber threat." 9.1.3: user access and user management activities "uniquely identified and logged for audit" (maps to console audit log). 7.4.1-7.4.2: patch management process with testing. — [MAS TRM 2021](https://www.mas.gov.sg/-/media/MAS/Regulations-and-Financial-Stability/Regulatory-and-Supervisory-Framework/Risk-Management/TRM-Guidelines-18-January-2021.pdf)
- Secondary summary: MAS expects significant incidents to be notified within one hour of being assessed as reportable, and 24/7 monitoring for critical systems. — [Presencis CISO guide to MAS TRM (secondary)](https://cdn.presencis.com/regulations/mas-trm/guide/ciso)
- MAS TRM maps to NIST SP 800-53 controls SI-03 (malicious code), SI-04 (system monitoring), AU-02/AU-06 (logging/review), IR-04 (incident handling), RA-05 (vuln scanning), MP-02/05/07 and SC-41 (media/port control), and AC-06 (least privilege). — [Open Security Architecture: MAS TRM control mappings](https://opensecurityarchitecture.org/frameworks/mas-trm/controls)

**OJK (Indonesia), POJK 11/POJK.03/2022 on bank IT**
- The regulation requires banks to: conduct cyber security testing and self-assess cyber security maturity; maintain a unit for cyber resilience/security; report cyber incidents; host electronic systems in a data center and DRC **located in Indonesia** (offshore only with OJK approval); supervise third-party IT providers; and submit electronic reports on IT conditions and incidents. — [Kontan: 11 key provisions of POJK 11/2022](https://keuangan.kontan.co.id/news/ini-11-pokok-pengaturan-pojk-penyelenggaraan-teknologi-informasi-di-bank-umum)

### Inferences
- **MVP console:** RBAC with at least Admin / Analyst / Read-only roles plus device-group scoping; SSO via OIDC/SAML (Entra ID, Okta, Google) with enforced MFA for local accounts; an immutable audit log of every console action and every remote shell command (MAS TRM 9.1.3); a REST API with scoped tokens; SIEM export (syslog/CEF and webhook/JSON); email plus Slack/Teams alert notifications; and a basic dashboard plus scheduled PDF reports.
- **Standard:** custom roles with per-action privileges (Elastic-style); MSP multi-tenancy (parent/child tenants, per-tenant branding/billing) because MSPs are a primary SMB route to market (Huntress, Lighthouse); compliance report templates mapped to ISO 27001 A.8.7 (malware), PCI DSS req. 5, SOC 2/TSC, and MAS TRM 11.3/12.2.
- **APAC-specific:** offer an in-region data residency option (Singapore region; an Indonesia region or on-prem/self-host for OJK-regulated banks, given POJK 11/2022's in-country DC requirement). This is a plausible wedge against US-hosted SaaS. The PDPA/UU PDP cross-border transfer rules in Q3 point the same way.
- **Advanced:** SOAR/playbooks, third-party log ingest, 1-hour incident reporting workflow templates for MAS-regulated FIs.

### Gaps
- Primary vendor docs on SIEM export formats (syslog/CEF/webhook) and Slack/Teams notifications were not fetched in this session. The table above infers these from common practice, not citations.
- The exact OJK provisions on endpoint/malware controls (e.g., SEOJK on IT risk management) and the incident-reporting deadline were not found. The Kontan summary does not give timelines.
- No source found that maps commercial EDR consoles directly to MAS TRM or OJK (most vendors map only to PCI/ISO/NIST).

---

## Q3. End-user-facing agent UI and employee privacy (PDPA Singapore, UU PDP Indonesia, GDPR)

### Takeaway
Commercial EDRs keep the employee-facing UI minimal. It shows protection status, blocked-file and blocked-device toasts that are branded with company IT contact details, and sometimes a user-bypassable "Warn" action. Critical detection notifications cannot be suppressed even when others are. EDR telemetry is employee personal data. In Singapore, collecting it is generally permitted without consent for managing employment and monitoring use of company IT resources, but employees must be notified. Indonesia's UU PDP likely requires a DPIA (systematic monitoring) and possibly a DPO. GDPR guidance says consent is rarely valid, so legitimate interest plus proportionality and transparency apply.

### Cited Findings
- Organizations can brand Windows Security / Defender notifications with company name, phone, email, and help-portal URL (GPO "Enterprise Customization" or the Intune Windows Security experience profile). "Customized notifications" use this contact info, e.g., for Block at First Sight and PUA detections. — [Microsoft Learn: Customize Windows Security contact info](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/windows-defender-security-center/wdsc-customize-contact-information)
- Admins can turn off enhanced notifications, suppress all notifications, suppress reboot notifications, or hide the AV UI entirely. However, "disabling other notifications does not disable critical notifications, such as threat detection and remediation alerts." — [Microsoft Learn: Configure Defender AV notifications](https://learn.microsoft.com/en-us/defender-endpoint/configure-notifications-microsoft-defender-antivirus)
- The MDE "Warn" indicator action shows the user a bypassable warning (requires the "Files or activities are blocked" notification to be enabled). — [Microsoft Learn: Indicators](https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview)
- **Singapore PDPA:** consent is not required for collection that is reasonable for managing or terminating employment, explicitly including "monitoring how the employees use company computer network resources." A lawful basis is still required. — [Baker McKenzie Global Data & Cyber Handbook: Singapore employment](https://resourcehub.bakermckenzie.com/en/resources/global-data-and-cyber-handbook/asia-pacific/singapore/topics/data-processing-in-the-employment-context)
- **PDPA 2020 amendments (in force 1 Feb 2021):** a legitimate interests exception (requires a risk assessment, benefit must outweigh adverse effect, reliance must be disclosed); a business improvement exception; mandatory breach notification to PDPC for breaches of significant scale (indicatively 500+ individuals) or significant harm; maximum fine of 10% of Singapore annual turnover or S$1 million, whichever is higher. — [PwC Singapore PDPA updates Nov 2020](https://www.pwc.com/sg/en/personal-data-protection/assets/pdpa-updates-202011.pdf)
- 2025 practitioner guidance on Singapore employee monitoring covers employees' rights to notice, to object, and to access their data, plus personal communications on employer systems and employee-owned devices (BYOD). — [Allen & Gledhill, Practical Law note 2025](https://www.allenandgledhill.com/sg/publication/articles/31513/practical-law-pre-employment-screening-and-data-protection-law-requirements-and-employee-monitoring-2025)
- **Indonesia UU PDP (Law 27/2022):** consent must be explicit and recorded, and other lawful bases exist (contract, legal obligation, "other lawful interests"). A DPIA is required for high-risk processing including "systematic evaluation, scoring and monitoring," large-scale processing, and new technology. A DPO is required for large-scale systematic monitoring. Breach notification to data subjects and the authority is required within 72 hours. Cross-border transfer is allowed only to equal/better-protection countries, with binding safeguards, or with consent. Criminal fines run IDR 4-6 billion (up to 10x for corporations). The two-year transition ended around October 2024. — [Norton Rose Fulbright: Highlights of Indonesia's PDP Law](https://www.nortonrosefulbright.com/en-il/knowledge/publications/31bce8f0/highlights-of-indonesias-personal-data-protection-law)
- **GDPR (WP29 Opinion 2/2017 on data processing at work):** consent is "highly unlikely to be a legal basis for data processing at work." Legitimate interest is possible where processing is "strictly necessary," subject to proportionality and subsidiarity. Employees must receive effective information about monitoring. Content of electronic communications keeps fundamental-rights protection. Transfers to a security vendor abroad need adequate protection. — [SCL summary of WP29 Opinion 2/2017](https://www.scl.org/6946-data-processing-at-work-updated-guidance/)

### Inferences
- **MVP tray app:** protection status (Protected / Attention / Isolated); last scan and definition/agent version; toast notifications for blocked files, blocked USB devices, isolation, and web blocks, branded with the company's IT contact; a list of the user's own quarantined items (view only by default); and an admin-unlock / uninstall-token prompt.
- **Standard:** a "Request unblock / report false positive" button that opens a ticket in the console with the file hash and justification (approval workflow). Admin-configurable notification verbosity, but critical detections should always notify (mirrors Microsoft's behavior). An "Isolated" banner on the device explaining how to contact IT.
- **Privacy-by-design features to scope** (supports PDPA notification, UU PDP DPIA, GDPR proportionality):
  - a configurable employee-facing monitoring notice/about page listing what the agent collects;
  - telemetry minimization toggles (e.g., do not collect command-line args or URLs for certain paths, hash usernames, disable file-content upload);
  - configurable retention per data type;
  - data residency region choice (Singapore/Indonesia);
  - RBAC that limits who can view user-identifying fields or open remote shells;
  - audit trails of analyst access to employee data;
  - DSAR/export-by-user and delete-by-user tooling;
  - separation of security telemetry from productivity monitoring. Do not ship keystroke or screenshot features, because they push the product into "employee monitoring software" territory and raise proportionality risk under GDPR and UU PDP DPIA requirements.
- BYOD: the 2025 Singapore guidance addresses employee-owned devices. A BYOD/personal-mode policy that collects less may be a differentiator.

### Gaps
- The Sophos/CrowdStrike/SentinelOne end-user tray UI docs could not be retrieved (Sophos docs fetch failed). Vendor-specific "request unblock" workflows are not cited.
- The PDPC's own Advisory Guidelines text on employee monitoring and on notification obligations for employees was not fetched (only secondary summaries).
- UU PDP implementing regulation (RPP) status and the administrative fine amount (some sources cite up to 2% of annual revenue) were not confirmed. The Norton Rose summary does not state a percentage.
- No 2025-2026 EDPB guidance specific to EDR/XDR telemetry was found.

---

## Q4. Mid-market differentiation and what SMB buyers value (Huntress, Sophos MDR, G2, Gartner Peer Insights, MITRE ATT&CK Evaluations 2024/2025)

### Takeaway
In SMB/mid-market, buyers reward ease of administration, ease of deployment, quality of support, and low false positives over raw detection depth. Huntress tops G2's small-business EDR grid on every sub-score by pairing a lightweight agent with a bundled 24/7 human SOC and no tiers or add-ons. MITRE ATT&CK Evaluations 2025 (ER7) are a weaker comparison tool than in prior years. Microsoft, SentinelOne, and Palo Alto withdrew, and vendors self-report "100%" headlines that require reading the sub-step detail.

### Cited Findings
- G2 small-business EDR: Huntress Managed EDR 4.8/5 (905 reviews) with Ease of Admin 9.6, Partner 9.7, Quality of Support 9.7, Ease of Use 9.5, against category averages of 8.8 / 9.0 / 8.7 / 8.7. Sophos Endpoint 4.7 (Ease of Admin 9.3), CrowdStrike Falcon 4.7 (8.9), ESET PROTECT 4.6, ThreatDown 4.6. Category average 4.43 across 133 products. — [G2 EDR small business category](https://g2.com/categories/endpoint-detection-response-edr/small-business)
- G2 review themes (AI-summarized by G2). Strengths: customer support, ease of deployment/setup, real-time detection, continuous monitoring, ransomware protection, lightweight performance, centralized management. Weaknesses: cost (especially add-on modules); learning curve/complex configuration (CrowdStrike, ESET, Sophos, Cortex, WatchGuard); resource usage on older hardware (Sophos, Check Point); false positives (Huntress, ThreatDown); limited Mac support and limited customization/integrations (Huntress). — [G2 EDR small business category](https://g2.com/categories/endpoint-detection-response-edr/small-business)
- Huntress model: one per-endpoint monthly rate, 12-month term, 50-agent minimum, "no tiers, add-ons, or bundles," 24/7 AI-assisted SOC plus threat hunters, investigation/containment/remediation, incident reports, and managed Microsoft Defender AV at no extra cost. — [Huntress EDR pricing page](https://www.huntress.com/pricing/edr)
- Huntress emphasizes human analysts making the final call, says it does not rely mainly on ML/AI (an "Athena" agentic-AI teaser notwithstanding), and claims <1% false positives. — [Huntress blog](https://www.huntress.com/blog/clearing-the-air-huntress-myths-and-misconceptions); [Huntress Managed EDR page](https://www.huntress.com/platform/managed-edr-security-2)
- Sophos MDR: 24/7 analysts, AI resolving 52% of cases end-to-end, an average of 89 seconds from alert to automated response, full incident response with no hourly caps, root cause analysis, a breach protection warranty, and the ability to run on third-party EDR telemetry (Microsoft, CrowdStrike, SentinelOne). Claims 40,000+ MDR organizations. — [Sophos MDR page](https://www.sophos.com/en-us/products/managed-detection-and-response)
- **MITRE ATT&CK Enterprise 2025 (ER7):** 11 participants (Acronis, AhnLab, CrowdStrike, Cyberani, Cybereason, Cynet, ESET, Sophos, Trend Micro, WatchGuard, WithSecure). Microsoft, Palo Alto Networks, and SentinelOne withdrew, citing resource reallocation. Scenarios emulated Scattered Spider (first-ever cloud/AWS infrastructure test and first reconnaissance detection test) and Mustang Panda. Scoring shifted toward protection and toward high-fidelity, actionable alerts to reduce alert fatigue. MITRE does not rank vendors, and a Forrester analyst warned that vendor "100%" claims should be viewed skeptically. — [SecurityWeek](https://www.securityweek.com/mitre-posts-results-of-2025-attck-enterprise-evaluations/)
- Microsoft announced its withdrawal in June 2025, and SentinelOne and Palo Alto confirmed theirs on 12 Sept 2025. Insiders cite test fatigue and weak ROI. MITRE CTO Charles Clancy said "each year's test is designed to be harder than the last." — [National CIO Review](https://www.nationalcioreview.com/articles-insights/extra-bytes/microsoft-sentinelone-and-palo-alto-withdraw-from-mitre-2025-evaluation/); [SentinelOne blog](https://www.sentinelone.com/blog/sentinelone-and-the-mitre-attck-evaluations-enterprise-2025/)
- Sophos ER7 self-reported results: 16/16 steps and 90/90 sub-steps detected, 86 at Technique level. This is footnoted to the "Configuration Change" run, meaning post-first-run tuning was allowed. Scattered Spider spanned Windows, Linux, and AWS (62 sub-steps). Mustang Panda was Windows-only (28 sub-steps). Categories are Technique / Tactic / General / None. — [Sophos blog](https://www.sophos.com/en-us/blog/sophos-achieves-its-best-ever-results-in-the-mitre-attck-enterprise-2025-evaluation)
- ESET self-reported ER7: 100% protection, 66.67% detection score, and "only one incident" in Hermes (Mustang Panda). About two-thirds of participants opt into protection testing. ESET argues detection scores are severity-weighted and that full ATT&CK coverage is not the goal; low alert volume with well-correlated incidents matters more. — [ESET blog](https://eset.com/blog/en/business-topics/endpoint-security-and-xdr/mitre-attck-evaluations-enterprise-2025-security-in-2026/)
- SentinelOne's 2024 (ER6) headline was "100% Detection, Zero Delays and 88% Less Noise" (title only; figures not verified from body). — [SentinelOne blog](https://www.sentinelone.com/blog/sentinelone-and-the-mitre-attck-evaluations-enterprise-2025/)
- CrowdStrike cites SE Labs Enterprise Advanced Security (EDR) Ransomware Test (Oct 2025): 100% detection and protection with zero false positives. — [CrowdStrike Falcon Insight XDR](https://www.crowdstrike.com/en-us/platform/endpoint-security/falcon-insight-xdr/)

### Inferences
- **What wins SMB/mid-market:**
  1. deployment in minutes via script/RMM/Intune with a lightweight agent;
  2. low-noise, pre-triaged incidents in plain language with one-click remediation (the Huntress pattern);
  3. a managed or co-managed SOC option;
  4. flat, simple pricing with no module sprawl;
  5. MSP multi-tenancy plus PSA/RMM integrations;
  6. low resource usage on older hardware.
- Deep hunting languages matter less to SMB buyers than to enterprise SOCs.
- A credible new entrant should treat "alert quality" (correlation into incidents, false-positive rate) as a core metric. MITRE ER7's scoring moved the same way.
- **Using MITRE results:** use them for detection-engineering benchmarking, not as a marketing ranking. Look at Technique-level sub-step counts, configuration changes, protection results, and alert volume/noise. Treat "100%" claims and missing vendors with caution.
- **Interoperability:** managing or co-existing with Microsoft Defender AV (as Huntress and Sophos MDR do) is a pragmatic strategy, given how many organizations already own Defender via M365 Business Premium/E5.

### Gaps
- Gartner Peer Insights ratings for these vendors were not retrieved.
- MITRE's official ER7 results page did not render (JavaScript), so per-vendor numbers are vendor self-reports only.
- No independent 2025-2026 survey quantifying SMB feature priorities beyond G2 sub-scores was found.
- No APAC-specific buyer survey (Singapore/Indonesia SMB EDR preferences) was found.

---

## Q5. Pricing / licensing models per endpoint (context)

### Takeaway
List prices range from roughly US$30/device/year (MDE P1) to about $230/device/year (S1 Commercial), with MDR at about $8-9/endpoint/month (Huntress). Common models: per device per year in tiered bundles (CrowdStrike, SentinelOne, Bitdefender), per user per month bundled into productivity suites (Microsoft), and flat all-inclusive managed pricing sold through MSPs (Huntress).

### Cited Findings
- CrowdStrike: Falcon Go $59.99/device/yr ($7.99/mo; max 100 devices), Pro $99.99/yr ($14.99/mo), Enterprise $184.99/yr ($19.99/mo). Complete MDR is contact-sales. Falcon Flex is a credit-style model allowing annual module swaps. — [CrowdStrike pricing](https://www.crowdstrike.com/en-us/pricing/)
- SentinelOne: Complete $179.99/endpoint/yr, Commercial $229.99/endpoint/yr, Enterprise by quote. — [SentinelOne pricing](https://www.sentinelone.com/pricing)
- Microsoft: Defender for Business standalone $3/user/month; MDE P1 $2.50/device/month; P2 $5.20/device/month (secondary source). MDB is included in M365 Business Premium. M365 Business Standard/E3/E5 rose by $3/user/month from 1 July 2026. — [TrustedTech (secondary)](https://www.trustedtechteam.com/blogs/microsoft-365/microsoft-defender-cost); [Microsoft Learn MDB overview](https://learn.microsoft.com/defender-business/mdb-overview)
- Huntress: per-endpoint monthly rate, 12-month term, volume discounts, 50-agent minimum, no tiers. — [Huntress EDR pricing](https://www.huntress.com/pricing/edr). A third-party site lists about $7.99-$8.99/endpoint/month and is internally inconsistent; sold through MSPs with markup. — [Costbench (secondary, medium confidence)](https://costbench.com/software/endpoint-security/huntress/)
- Bitdefender GravityZone: quoted by endpoint count with volume and multi-year discounts. Servers count as endpoints. Patch management and FDE are add-ons. — [casrai.org (secondary)](https://casrai.org/guides/bitdefender-gravityzone-business-vs-premium); [Bitdefender](https://bitdefender.com/business/gravityzone-platform/vulnerability-management)
- Wazuh is open source (no license fee). Capabilities are per the docs. — [Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/index.html)
- Telemetry retention is a pricing lever: SentinelOne gives 14 days on Complete vs 90 on Commercial; MDE P2 offers 30-day advanced hunting / 6-month retention. — [SentinelOne pricing](https://www.sentinelone.com/pricing); [Microsoft Learn MDB overview](https://learn.microsoft.com/defender-business/mdb-overview)

### Inferences
- **Pricing anchor for a new APAC entrant:** the SMB "good enough" price floor is set by Microsoft bundling (Defender for Business at $3/user/mo, often already paid for via Business Premium). Standalone EDR must justify about $5-15/endpoint/month through simplicity, a managed service, local data residency, or local-language support.
- **Monetization levers:** retention days, remote shell/hunting, device/firewall control modules, MDR, and identity.
- **Tier names:** "Prevent" (MVP: NGAV + device control + isolation), "Detect & Respond" (telemetry + hunting + live response), and "Managed" (SOC) mirror the market ladder (Falcon Go/Pro/Enterprise/Complete; S1 Core/Control/Complete/Commercial).

### Gaps
- No APAC/SGD/IDR-specific pricing was found. Vendor list prices are USD.
- Sophos Intercept X and Elastic per-endpoint prices were not found on fetched pages.
- Microsoft P1/P2 prices come from a reseller blog, not Microsoft's price list.
