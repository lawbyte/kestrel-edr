# EDR/XDR Console and Endpoint Agent UI/UX Patterns (2024-2026)

Scope note: Vendor consoles sit behind logins, so most screen-level detail comes from official docs (Microsoft Learn, Elastic docs, Sophos/Secureworks docs, CrowdStrike tech-hub walkthrough), university IT knowledge bases (for the agent apps), and review aggregators (PeerSpot, G2). Reddit threads did not surface through search, and G2 individual-review pages were not reachable; complaint data comes from PeerSpot and G2 comparison summaries instead.

## 1. Information architecture and navigation of leading consoles

### Takeaway
The leading consoles share one backbone. A left-hand nav groups work into Detect/Respond (incidents and alerts), Investigate/Hunt (search, query, timeline), Assets (endpoints, users), and Configure (policies, exclusions, settings). Every list opens a summary side panel, and a full page is one click further. Navigation clutter and deep side-menus are the most common IA complaint, mostly aimed at CrowdStrike and SentinelOne. Microsoft and Elastic document the most mature incident and alert models.

### Cited Findings
- **Microsoft Defender XDR**: incidents live at "Incidents & alerts > Incidents". The incident page has tabs for Attack story, Alerts, Activities, Assets, Investigations, Evidence and Response, Summary, and Similar incidents. — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents)
- Defender is moving the legacy incident page to a new "incident cases" experience, still in preview. — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents); [Microsoft Learn: Incident queue](https://learn.microsoft.com/en-us/defender-xdr/incident-queue)
- Defender device pages are reached from Assets > Devices, the alert queue, incidents, or global search. Tabs: Overview, Incidents and alerts, Timeline, Security recommendations, Security policies, Effective settings, Software inventory, Discovered vulnerabilities, Missing KBs. — [Microsoft Learn: Device timeline](https://learn.microsoft.com/en-us/defender-endpoint/device-timeline-event-flag)
- **CrowdStrike Falcon**: a third-party guide gives these menu paths: Activity > Detections (filter by severity, timeframe, host), Hosts > Host Management, Threat Intelligence > IOCs, OverWatch > Threat Hunting Reports, Configuration > Prevention Policies. Note that the 2024+ "Next-Gen" console reorganized these into module-based menus, so the paths vary by version. — [InventiveHQ](https://inventivehq.com/knowledge-base/crowdstrike/how-to-investigate-a-security-incident-using-crowdstrike-falcon)
- Falcon Insight XDR walkthrough: a central detections view with a side **inspector** that shows a one-line summary (for example "Phishing via malicious attachment with suspicious Beacon"). The full detection view lists contributing indicators, affected hosts, and users. A three-dot host menu offers remote commands, host search, and pivots to the asset graph or logon info. — [CrowdStrike Tech Hub](https://www.crowdstrike.com/tech-hub/endpoint-security/falcon-insight-xdr-walkthrough/)
- **SentinelOne**: the Singularity Operations Center (GA May 2024) is "a new unified security console" with unified alert triage across event collections, inventory management, a correlation engine, and a contextualized Singularity Graph. Purple AI is embedded across the console. — [SentinelOne press release](https://www.sentinelone.com/press/sentinelone-unveils-future-of-autonomous-security/)
- **Elastic Security**: the Alerts page holds a visualization section, filter controls, and the alerts table. From any alert you can open Timeline, the visual event analyzer, Session View, or Osquery. — [Elastic docs: Manage alerts](https://www.elastic.co/guide/en/security/8.19/alerts-ui-manage.html)
- **Sophos Central**: the Threat Analysis Center (TAC) Dashboard went GA in June 2023 with widgets that click through to pre-filtered Detections in a new tab. Terminology was renamed for clarity ("Device name" became "Entity", "Category" became "Type", "Integrations" became "Category"). — [Sophos Community blog](https://community.sophos.com/intercept-x-endpoint/b/blog/posts/new-sophos-xdr-dashboard)
- **Wazuh**: the MITRE ATT&CK module sits in the "Threat Detection and Response" area of the dashboard home. It has an Intelligence tab (threat groups, IoCs, mitigations, external links) and a Framework tab (tactics and techniques seen on monitored endpoints). — [Wazuh docs 4.12](https://documentation.wazuh.com/4.12/user-manual/ruleset/mitre.html)
- **LimaCharlie** (March 2025 UI update): users can switch between "Classic" and "Modern Theme". In-org IOC search moved from the top bar to the sidebar, the org name and quick-switch control moved to the bottom of the sidebar, Saved Queries became a dropdown in the Query Console, and the in-product dashboards gained detection visualizations (where, what type, how often). — [Security Boulevard / LimaCharlie](https://securityboulevard.com/2025/03/announcing-our-ui-update-and-in-product-dashboards)
- Cisco XDR groups navigation into 7 main categories with 26 subcategories and uses progressive disclosure to guide users deeper only as needed. — [Cisco blog](https://blogs.cisco.com/security/from-frustration-to-clarity-embracing-progressive-disclosure-in-security-design/)
- Role-based default landing views: analysts land on a work queue, hunters on raw telemetry with a query bar, engineers on configuration and integration health, and CISOs on posture and trends. Executive views carry no alert-level detail. — [Fuselab Creative](https://fuselabcreative.com/industries/cybersecurity-ux-design)

### Inferences
- A clean IA for a new EDR could be: **Overview · Incidents · Alerts · Endpoints · Hunt · Response/Actions log · Policies · Exclusions/Allowlist · Settings (Users/RBAC, Integrations, API, Audit)**, with an org switcher at the bottom of the sidebar (the LimaCharlie pattern) and a global search/IOC bar.
- Treat "Incident" (a correlated group, as in Defender) and "Alert" (an atomic detection) as separate objects. Defender, Elastic, and S1's unified alerts all converge on that split.
- Shipping a classic/modern theme toggle during a redesign (LimaCharlie, Sophos TAC) lowers migration friction.

### Gaps
- Could not verify the exact sidebar structure of the CrowdStrike Next-Gen (2024-2026) console or the SentinelOne Singularity Operations Center from public docs. Both sit behind login-only documentation.
- No Huntress portal IA documentation was found. Only workflow-level descriptions exist (see section 2).

## 2. Key screens and their components

### Takeaway
The repeating pattern is **queue → side panel → full page**. Each screen surfaces severity, status, owner, and the next action, and keeps response buttons (isolate, scan, collect, live response) in a persistent action bar on the incident and device pages. Defender and Elastic document the richest triage controls: a priority score, saved filter sets, grouping, bulk actions, and assignment. Huntress stands out by turning the incident into a remediation checklist with an approve-to-run step.

### Cited Findings
**Overview dashboard**
- Sophos TAC dashboard widgets: Total detections, Total detection count (5 views), Top 10 entities, Top 10 users, Sensor location of detection, MITRE TTP, and Recent detections. Each widget has its own filters and time range, and click-throughs are context-aware. — [Sophos Community](https://community.sophos.com/intercept-x-endpoint/b/blog/posts/new-sophos-xdr-dashboard)
- Cisco XDR "Control center" tiles show high-level key metrics rather than granular data, and users can create or edit dashboards. — [Cisco blog](https://blogs.cisco.com/security/from-frustration-to-clarity-embracing-progressive-disclosure-in-security-design/)
- Order the first screen by what the analyst should do next, not by a tally of what happened. — [Fuselab Creative](https://fuselabcreative.com/industries/cybersecurity-ux-design)
- LimaCharlie dashboard: platform usage charts (online sensors, input data, output traffic) with drill-down dropdowns. — [Security Boulevard](https://securityboulevard.com/2025/03/announcing-our-ui-update-and-in-product-dashboards)

**Alerts/incidents queue**
- Defender incident queue:
  - Time selector (default last week; 1d/3d/1w/30d/6mo/custom), with a total count shown next to it.
  - Search by name, ID, or impacted asset, plus a "Most recent incidents and alerts" 24h timeline chart toggle.
  - Customizable, reorderable columns and CSV export (up to 10,000 rows).
  - "Add filter" chips: status, severity, assignment, sources, categories, classification, tags, entities, device groups, OS, automated investigation state. The default filter is status New/In progress with severity High/Medium/Low.
  - Saved "filter sets" and bookmarkable filtered URLs (for example unassigned, high-severity, assigned-to-me).
  - — [Microsoft Learn: Incident queue](https://learn.microsoft.com/en-us/defender-xdr/incident-queue)
- Defender **priority score** 0-100 from Queue Assistant ML. Red >85, orange 15-85, gray <15. Inputs include attack disruption signals, severity, MITRE techniques, asset criticality, alert rarity, and ransomware/nation-state threats. The side panel shows the factors behind the score. — [Microsoft Learn: Incident queue](https://learn.microsoft.com/en-us/defender-xdr/incident-queue)
- Defender side panel: clicking a row (not the name) opens a summary pane with priority assessment, details, recommended actions, and related threats. Up/down arrows step through incidents without closing it. — [Microsoft Learn: Incident queue](https://learn.microsoft.com/en-us/defender-xdr/incident-queue)
- Defender auto-generates incident names from alert attributes (for example "Multi-stage incident on multiple endpoints reported by multiple sources"). — [Microsoft Learn: Incident queue](https://learn.microsoft.com/en-us/defender-xdr/incident-queue)
- Elastic alerts:
  - KQL bar plus a date picker (default 24h).
  - Up to 4 dropdown filter controls (default Status, Severity, User, Host; Status cannot be removed).
  - **Group by up to 3 nested fields**. Each group shows severity and counts of users, hosts, and alerts, and has a group-level "Take actions" bulk menu.
  - Table toolbar with Columns, Sort, Fields, and Full screen.
  - Grid view vs "Event rendered view" (a descriptive event flow), and a Reason column with an expandable reason statement.
  - Statuses Open/Acknowledged/Closed, bulk status changes, and assignees (up to 4 avatars in the column).
  - Row actions: add to case, add exception, tag, assign, isolate host, run Osquery, investigate in Timeline, open the analyzer, add notes.
  - — [Elastic docs: Manage alerts](https://www.elastic.co/guide/en/security/8.19/alerts-ui-manage.html)
- Cisco XDR: color-coded risk score with a hover explanation for new users. Selecting an incident opens a **side drawer** (status, assignees, description, risk breakdown, assets), with a link to the full page. — [Cisco blog](https://blogs.cisco.com/security/from-frustration-to-clarity-embracing-progressive-disclosure-in-security-design/)
- Queue guidance: rank by priority, not timestamp. Show supporting evidence beside each alert, and design explicit false-positive and escalation paths. When a live queue reorders, keep the analyst's place, mark what changed, and give the analyst control over auto-refresh. — [Fuselab Creative](https://fuselabcreative.com/industries/cybersecurity-ux-design)
- Show confidence, business impact, status, ownership, and the expected next action alongside severity. — [Skins Factory](https://www.theskinsfactory.com/uiux-design-questions-answers/why-are-cybersecurity-dashboards-so-hard-to-use)

**Incident detail**
- Defender Attack story tab: an alert page (What happened / Actions taken / Related events, with properties in a right pane) next to an **incident graph** that shows how the attack spread over time. Graph controls:
  - **Play** replays alerts in chronological order.
  - Click an entity to open its pane and take actions (delete a file, isolate a device).
  - Highlight the alerts tied to an entity.
  - **Go hunt** pivots to queries (All Activity, Related Alerts) and a "Link to incident" action.
  - Filters for severity, status, and service source, plus entity-type toggles.
  - — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents)
- Defender **Blast radius** view: from a node, shows the top 8 possible propagation paths to critical targets. Paths are bounded to 7 hops, and the view has an ungroup toggle. — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents)
- Defender Evidence and Response tab: each entity has a verdict (Malicious/Suspicious/Clean) and a remediation status. Pending-approval remediation actions can be approved or rejected inline. — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents)
- Defender Summary tab: MITRE-aligned **kill-chain progress**, an alerts timeline, scope counts (devices, users, mailboxes ordered by risk), an evidence count, and tags/status/severity. Activities tab: a unified timeline of manual and automated actions. — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents)
- Falcon: selecting a detection shows a visual process tree, and a right-side details pane covers execution details, files, and sandbox analysis "in plain terms". SC Media rated the console easy to navigate (2019, Falcon 4.x). — [SC Media review](https://www.scworld.com/product-test/crowdstrike-falcon-4-x)
- Falcon graph view: hosts, users, and indicators as nodes, with a legend. Clicking a process shows the full command line and its parent/child genealogy. "See Event Details" pivots to search with raw and table views, and a search icon copies a field value into the query bar. Network containment works per host or in bulk from the detection. — [CrowdStrike Tech Hub](https://www.crowdstrike.com/tech-hub/endpoint-security/falcon-insight-xdr-walkthrough/)
- Huntress incident reports: severity (Low/High/Critical), affected host, finding class (footholds and persistence), indicators (paths, hashes, command lines), and **two action sections**: what Huntress already ran (auto-remediation or isolation) and "approve-to-run remediations and fully manual steps" for the technician. Isolation is released only after the checklist is complete, and the release records who and when. — [Thread runbook for Huntress](https://docs.getthread.com/skill-library/vendor-runbooks/huntress-edr-incident)
- Huntress offers opt-in auto-remediation for low-severity incidents, so no partner approval is needed for those. — [Huntress changelog](https://feedback.huntress.com/changelog/new-feature-auto-remediation-for-low-severity-incidents)
- SentinelOne STAR/Storyline: correlates activity into an attack history, and offers single-click remediation and **rollback** that reverses unauthorized changes and restores data on Windows. — [Huon IT partner blog](https://info.huonit.com.au/blog/post/elevate-your-security-environment-with-storyline-active-response-star) (partner marketing, low detail)

**Endpoint detail**
- Defender device page:
  - Header: domain, OS, health state.
  - **Response action bar** across the top: Isolate device, Restrict app execution, Run AV scan, Collect investigation package, Initiate Live Response, Initiate automated investigation, Manage tags, Set criticality, Action center.
  - Overview cards: Active alerts, Logged-on users (30 days), Security assessment, Device health.
  - "Effective settings" tab: each setting's actual value and its source (MDE, GPO, Intune, registry).
  - For high-value assets, unavailable actions are grayed out.
  - — [Microsoft Learn: Device timeline](https://learn.microsoft.com/en-us/defender-endpoint/device-timeline-event-flag)
- Falcon host view: sensor health, recent activity (processes, network, registry), containment status, a "Contain Host" button, and RTR (shell commands such as ps, netstat, kill, del). — [InventiveHQ](https://inventivehq.com/knowledge-base/crowdstrike/how-to-investigate-a-security-incident-using-crowdstrike-falcon)

**Hunting/query view**
- Purple AI: a natural-language question box. The generated query is shown "for verification and analyst training", with suggested next queries and one-click quickstart prompts. Investigations auto-save as shareable notebooks. — [SentinelOne blog](https://www.sentinelone.com/blog/transforming-the-soc-with-purple-ai/)
- Falcon custom detection from search: name, severity, optional MITRE tactic and technique, schedule, and notification (email, Teams, Slack). — [CrowdStrike Tech Hub](https://www.crowdstrike.com/tech-hub/endpoint-security/falcon-insight-xdr-walkthrough/)
- Defender "Hunt for related events" from any timeline event opens advanced hunting scoped to the same device and time window. — [Microsoft Learn: Device timeline](https://learn.microsoft.com/en-us/defender-endpoint/device-timeline-event-flag)

**Policy/settings**
- Sophos agent: an admin can sign in locally with the tamper-protection password and override the Central policy for up to 4 hours, after which it auto-reverts. — [Secureworks/Sophos agent docs](https://docs.taegis.secureworks.com/sophos_agent/sophos_agent_app_ui/sophos_endpoint_ui/)
- Mitigation actions (kill, quarantine, remediate, rollback, remote shell) should be assigned to specific roles. This argues for action-level RBAC. — [ITECS](https://itecsonline.com/post/sentinelone-for-msps)

### Inferences
- **Queue:** a table with priority score, severity, title (auto-generated), affected entities, MITRE tactic chips, status, assignee avatar, and last activity. Support grouping (by host, rule, or user), saved views as URL-backed filters, a side drawer with J/K navigation, and bulk status/assign/close-as-FP.
- **Incident page:** a header with severity, status, assignee, and classification controls, plus a sticky action bar. Tabs: Story (graph plus alert narrative), Alerts, Timeline, Evidence (verdict plus remediation status), Assets, Activity log. Add a plain-language summary at the top.
- Borrow the Huntress "Already done / Needs your approval / Manual steps" checklist structure for the remediation section. It suits IT admins who are not SOC experts.
- Show the effective policy with the source of each setting (the Defender pattern) on the endpoint page. It answers "why is this setting on" without a trip to the policy editor.

### Gaps
- No public documentation of an RBAC settings screen layout for any vendor was found.
- No primary documentation of SentinelOne's incident detail layout (Storyline graph, "Threat details" page) was found in 2024-2026 sources.

## 3. Visualization patterns

### Takeaway
Two tree and graph idioms dominate. Process trees run top-down from parent to child with event-category "pills" and the time gap between processes (Elastic Analyzer, Falcon). Entity graphs link users, devices, files, and IPs with legends, filters, and a chronological "play" (Defender incident graph, Falcon graph view). Terminal-styled session trees suit Linux (Elastic Session View). For MITRE, vendors mostly show kill-chain progress bars and tactic chips rather than full matrix heatmaps. Simplify by default and expand on hover or click.

### Cited Findings
- Elastic **Visual Event Analyzer**: child processes sit below their parents, with the elapsed time between them shown.
  - Each process is a cube, and the analyzed event gets a light-blue outline.
  - **Pills** show event categories with counts (for example "x file", "x registry", "x alert").
  - Zoom slider and click-drag pan.
  - Toolbar: legend of node states, data view filter, time filter (defaults to the table's range), and a list panel of all processes in the chain.
  - The process detail panel shows event count, timestamp, path, PID, user/domain, and associated alerts.
  - — [Elastic docs: Visual event analyzer](https://docs-v3-preview.elastic.dev/elastic/docs-builder/docs/3875/solutions/security/investigate/visual-event-analyzer.md)
- Elastic **Session View** (Linux):
  - A terminal-styled process tree ordered by parentage and time.
  - A red line marks the event that caused an alert, and an alert count button sits on parent processes. Gear, file, and network icons distinguish alert types.
  - "Exec user change" badge for privilege escalation, and an "Output" badge that opens captured terminal output with playback controls.
  - In-session search with next/prev, auto-expanding collapsed nodes that match.
  - **Verbose mode off by default**, which hides shell noise and highlights likely user-generated activity. Timestamps are toggleable.
  - — [Elastic docs: Session View](https://www.elastic.co/docs/solutions/security/investigate/session-view)
- Elastic alert visualizations: **Summary, Trend, Counts, and Treemap** views, with selectable group-by fields. — [Elastic docs: Manage alerts](https://www.elastic.co/guide/en/security/8.19/alerts-ui-manage.html)
- Defender incident graph: entity nodes (users, devices, mailboxes, files, IPs), a "Play" chronological replay, entity-type toggles, and severity/status/source filters, with an empty state when everything is filtered out. — [Microsoft Learn: Investigate incidents](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents)
- Defender device timeline: MITRE techniques appear inline (bold, blue icon, linking to ATT&CK). Analysts can **flag events**, filter to flagged events, and click the time bar to show only events before a flag, which builds a clean breach timeline. The process tree opens in a side panel. — [Microsoft Learn: Device timeline](https://learn.microsoft.com/en-us/defender-endpoint/device-timeline-event-flag)
- Defender Summary uses MITRE-aligned kill-chain progress. Sophos uses a "MITRE TTP" dashboard widget. — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents); [Sophos Community](https://community.sophos.com/intercept-x-endpoint/b/blog/posts/new-sophos-xdr-dashboard)
- Cisco XDR investigation maps show only key nodes by default. Hover expands related nodes, and click opens investigation options. — [Cisco blog](https://blogs.cisco.com/security/from-frustration-to-clarity-embracing-progressive-disclosure-in-security-design/)
- Grafana guidance:
  - Use fewer visualization types and reuse one visual pattern.
  - Keep the palette small, and reserve bright colors for meaningful signals.
  - Never rely on color alone. Add position, labels, or icons.
  - Avoid red next to green and red on black.
  - — [Grafana blog](https://grafana.com/blog/3-tips-to-improve-your-grafana-dashboard-design/?pg=blog)
- Choose axis scale and default time ranges deliberately, since a default window can hide a recent spike. — [Fuselab Creative](https://fuselabcreative.com/industries/cybersecurity-ux-design)

### Inferences
- Process tree: a vertical, indented tree (more compact than a free-form graph) with icon per node type, signer/reputation badge, alert marker on offending nodes, count pills for file/registry/network events, collapse of noisy branches by default (the "verbose off" idea), and a right-side detail drawer showing command line, hash, signer, user, and parent chain.
- Use the entity graph only at the incident level (multi-host), with a "Play" timeline scrubber.
- For MITRE, use tactic chips on alerts and a 14-column tactic strip (kill-chain progress) on the incident. Reserve a full matrix heatmap for a separate coverage/analytics page.
- Sparkline KPIs on the overview (alerts over 7 days, endpoints online, mean time to triage), each clickable to a pre-filtered list (the Sophos context-aware click-through).

### Gaps
- No documented source for dark-vs-light theme defaults in these consoles was found. Defender, Elastic, and Falcon all offer dark themes in practice, but this was not verified here.
- No primary 2024-2026 documentation for the CrowdStrike Next-Gen "Incident Workbench" graph was retrieved.

## 4. Common complaints and praise

### Takeaway
Praise centers on simplicity and plain-language guidance (Huntress has the highest G2 ease-of-use scores) and on process-level visibility and autonomous rollback (Falcon, S1). Complaints repeat across vendors: cluttered, hard-to-remember navigation, slow console loads on large queries, weak or rigid reporting and export, complexity for new analysts as AI and XDR features pile on, and exclusion-management toil. Alert fatigue is the industry-level backdrop.

### Cited Findings
- G2 Ease of Use / Ease of Admin: Huntress 9.5 / 9.6 vs SentinelOne 8.9 / 8.9. S1 trade-offs listed: "console performance lags on large queries" and a "learning curve for advanced features". Huntress trade-off: limited reporting customization. — [G2 Huntress vs SentinelOne](https://www.g2.com/compare/huntress-vs-sentinelone-singularity)
- G2: Huntress 9.5 ease of use / 9.6 setup / 9.6 admin vs Defender for Endpoint 8.6 / 8.5 / 8.6. Huntress reviewers cite an "intuitive interface", useful incident reports, and auto-resolution. Defender reviewers cite complexity as a drawback. — [G2 Huntress vs MDE](https://www.g2.com/compare/huntress-managed-edr-vs-microsoft-defender-for-endpoint)
- CrowdStrike complaints (PeerSpot reviews, 2018-2022, so older):
  - "The console is a little cluttered and at times, finding what you're looking for is not intuitive."
  - The dashboard is "spread out in so many ways" that infrequent users forget where things are.
  - "It's a bit slow… should be more responsive."
  - Policy changes wait for agent check-in.
  - Reporting "basic", hard to build custom dashboards, no PDF export.
  - — [PeerSpot: CrowdStrike improvements](https://www.peerspot.com/questions/what-needs-improvement-with-crowdstrike-falcon)
- CrowdStrike: the side tabs and menu options are "the biggest area for enhancement". Report export is hard, and it is difficult to find machines without the agent. Praise: lightweight agent, process granularity, "single pane of glass". — [PeerSpot pros/cons](https://peerspot.com/products/crowdstrike-falcon-pros-and-cons)
- SentinelOne: "the dashboard is complex for new users". Added Purple AI and EDR features "makes it complex for new SOC users". The console is "somewhat laggy and loads slowly at times". Users "have to go in and build new exclusions daily". Praise: autonomous mitigation and ransomware rollback. — [PeerSpot S1 pros/cons](https://www.peerspot.com/products/sentinelone-singularity-complete-pros-and-cons)
- Microsoft acknowledged Defender portal latency (Submission, Quarantine, Threat Explorer, Email Entity, Policy pages) and ran a performance program from March 2025 to a December 2025 target. — [M365 Message Center MC1042925](https://mc.merill.net/message/MC1042925)
- Falcon 4.x (SC Media, 2019): process tree easy to navigate, and the details pane explains events "without heavy technical jargon", understandable by less experienced admins. — [SC Media](https://www.scworld.com/product-test/crowdstrike-falcon-4-x)
- Alert fatigue: Vectra reports 67% of alerts are ignored (cited in a 2025 SOC workshop paper). Tines Voice of the SOC 2023: "too many logs" is the #1 daily challenge and "too many alerts" #3, summed up as "too much data and not enough information". Missing alert context is a barrier to investigation. — [Moore et al., WOSOC 2025](https://tylermoore.utulsa.edu/wosoc25.pdf)
- Why security dashboards are hard to use: equal visual weight on everything, every badge screaming urgency, fragmented context forcing tool-hopping, and friction for experts (inconsistent patterns, slow navigation, no keyboard efficiency). — [Skins Factory](https://www.theskinsfactory.com/uiux-design-questions-answers/why-are-cybersecurity-dashboards-so-hard-to-use)

### Inferences
- Design targets for differentiation:
  1. Fast perceived performance: optimistic UI, skeletons, server-side pagination, and a query cost/progress indicator for hunts.
  2. Shallow navigation with global search and a command palette.
  3. Built-in reporting with PDF/CSV export and a scheduled executive summary.
  4. A "find unmanaged devices" coverage view.
  5. Exclusion management with suggestions ("create exclusion from this alert" with scope preview) to reduce daily toil.
  6. Plain-language summaries everywhere, the Huntress and Falcon details-pane lesson.
- AI features (Purple AI style) should stay optional overlays. Reviewers say they add complexity for new users.

### Gaps
- Reddit r/sysadmin and r/cybersecurity threads were not retrievable via search. Most CrowdStrike PeerSpot complaints are from 2018-2022 and may not reflect the 2024+ Next-Gen console.
- No Sophos Central or Wazuh complaint data was gathered.

## 5. Employee-facing tray/desktop app patterns

### Takeaway
Agent apps range from a full app (Sophos, Windows Security) to a status-only tray icon (CrowdStrike, added October 2024). The common minimum set is:
- a color/icon status indicator (green / yellow / red / gray)
- a block or quarantine toast with plain text
- a short detection history with severity cards
- a Quick/Full scan button
- an admin-only override behind tamper protection
- IT contact info and a way to request review

Destructive or allow actions are gated behind admin rights.

### Cited Findings
- **Sophos Endpoint (Windows)**:
  - Opens from the tray or the Start menu, with tabs Status, Detections, Events, and Settings (Settings appears only after admin sign-in).
  - Status icon: green (no or low alerts), yellow (medium), red (high), gray (unknown). Per-feature status for Malware/PUA, BitLocker, and ZTNA.
  - Scan: Quick (memory, MBR, running processes, startup) or Full, plus a right-click Explorer "Scan".
  - Events: a filterable log showing severity, feature, time, description, and an admin-only action link.
  - Detections: per-type stats (Malware/PUA, Web, Behavior, Ransomware, Controlled Items, Traffic, Exploits).
  - Admin sign-in uses the tamper-protection password and allows a 4-hour policy override that auto-reverts.
  - — [Secureworks/Sophos agent docs](https://docs.taegis.secureworks.com/sophos_agent/sophos_agent_app_ui/sophos_endpoint_ui/)
- **Windows Security, Protection history**:
  - Event cards: red for serious/immediate, yellow for review later. Cards expand for details, and history is kept 2 weeks. Admin rights are needed to view threat details.
  - States and actions:
    - "Threat found, action needed": Quarantine or Allow on device.
    - "Threat quarantined": Remove or Restore.
    - "Threat blocked": Allow.
    - "Remediation incomplete": manual steps.
    - "App blocked (PUA)".
    - "Important service off": turn back on.
  - An "Allowed threats" page lets users undo an allow.
  - — [Microsoft Support: Protection history](https://support.microsoft.com/windows/protection-history-f1e5fd95-09b4-46d1-b8c7-1059a1e09708)
- Defender notifications: admins can turn off "enhanced notifications" (summaries), "Suppress all notifications", or suppress reboot prompts. Critical threat notifications are never suppressed by the enhanced-notification setting. Custom text can be shown when user action is needed, and custom IT contact info is set through the "Customize the Windows Security app for your organization" policy. The entire Defender UI can be hidden. — [Microsoft Learn: Configure notifications](https://learn.microsoft.com/en-us/defender-endpoint/configure-notifications-microsoft-defender-antivirus)
- **CrowdStrike Falcon**:
  - Historically no UI. A **Falcon Sensor Status tray icon** came to Windows on Oct 24, 2024: green check shield = running as expected, grayed-out = not running, X = internal error. Users are told to contact IT.
  - — [University of Michigan ITS](https://michigan.it.umich.edu/news/2024/10/25/new-crowdstrike-falcon-sensor-status-icon-for-windows)
  - On block, a pop-up says: "A file was quarantined because malicious behavior was detected." Review and exception requests go via a help-desk ticket with the app name, justification, a screenshot, and the hostname. No in-app request flow exists.
  - — [UAH OIT KB](https://uah.teamdynamix.com/TDClient/2075/Portal/KB/PrintArticle?ID=137260)
- **ESET Endpoint Security**: "Application statuses" (for example protection paused, Presentation mode, license expired) can be set per status to **Show** (in the local GUI) and/or **Send** (to ESET PROTECT), managed by cloud policy. — [ESET Online Help](https://help.eset.com/ees/latest/en-US/idh_config_disabled_statuses_dialog.html)

### Inferences
- Recommended employee app:
  - **Tray icon** with 3-4 states plus a text label in the tooltip, so meaning does not rest on color alone.
  - **Home**: status hero ("You're protected"), last scan, policy last synced, Quick scan button.
  - **Activity**: blocked and quarantined cards with plain-language explanations.
  - **Request review** button that pre-fills hostname, file name/hash, detection name, and a justification field, and creates a console ticket. This fills the gap CrowdStrike users handle via screenshot plus help-desk email.
  - **Help**: org-branded IT contact.
- Restore/Allow should stay admin-only or approval-gated (the Windows Security and Sophos model). The employee sees "Pending IT review" status instead.
- Make notification verbosity admin-configurable per org (ESET Show/Send, Defender suppression), but never suppress critical block notices.

### Gaps
- No primary docs for a quarantine view in the Sophos endpoint app were found; it shows detections and events only.
- The ESET protection-status screen layout and tray icon colors could not be verified from the retrieved page.

## 6. Design systems, inspiration, and accessibility

### Takeaway
No security vendor publicly documents a design system built on Linear, shadcn, or Tremor. These are inspirations, not verified vendor practice. The concrete, sourced guidance is about accessibility and visual discipline: a small consistent palette, color plus icon/label/position for severity, defined focus order, screen-reader announcements for live queues, keyboard efficiency, and Section 508/VPAT readiness for regulated buyers.

### Cited Findings
- Define focus order and **color-independent severity** before visual design begins. Specify screen-reader announcements for live-updating alerts. Plan for Section 508 conformance and an accurate VPAT for federal and regulated buyers. — [Fuselab Creative](https://fuselabcreative.com/industries/cybersecurity-ux-design)
- Don't convey status by color alone, and avoid red/green adjacency and red-on-black. Keep the palette small with bright colors reserved for signals, and use fewer chart types. — [Grafana blog](https://grafana.com/blog/3-tips-to-improve-your-grafana-dashboard-design/?pg=blog)
- Expert-workflow needs: consistent interaction patterns, faster navigation, **keyboard efficiency**, and dense but readable layouts. — [Skins Factory](https://www.theskinsfactory.com/uiux-design-questions-answers/why-are-cybersecurity-dashboards-so-hard-to-use)
- Progressive disclosure in three layers: summary, then detail, then raw data. Make the next step obvious by limiting prominent controls. — [Cisco blog](https://blogs.cisco.com/security/from-frustration-to-clarity-embracing-progressive-disclosure-in-security-design/)
- Users report Atlassian dashboard gadgets failing accessibility because "color alone used to convey chart data" (Jira issue JRACLOUD-97766). It shows up as a tracked accessibility defect. — [Atlassian Jira](https://jira.atlassian.com/browse/JRACLOUD-97766) (search-result title only, not fetched)

### Inferences
- A practical stack for the console: shadcn/ui (Radix primitives give accessible focus management and ARIA), Tremor or Recharts for KPI cards and sparklines, TanStack Table with virtualization for alert tables, and React Flow or ELK for graphs. Use a Linear-style command palette (Cmd/Ctrl-K) and J/K/Enter/Esc queue navigation. This is a recommendation, not a sourced vendor practice.
- Severity tokens:
  - Critical: red plus a filled octagon icon plus the text label.
  - High: orange plus a triangle.
  - Medium: yellow/amber plus a circle.
  - Low: blue/gray.
  - Informational: neutral.
  - Validate each against both light and dark backgrounds for 4.5:1 text contrast.
- Default to dark theme for the SOC console (long shifts, wall displays) with a full light theme. Offer "comfortable" and "compact" table density.

### Gaps
- No verified evidence on which design systems CrowdStrike, SentinelOne, Microsoft (Fluent 2 is likely for Defender but not confirmed here), or Elastic (EUI is Elastic's public design system but not fetched here) use for their consoles.
- No Dribbble/Behance EDR case studies were retrieved with enough substance to cite.
