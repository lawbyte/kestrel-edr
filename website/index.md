---
layout: home

hero:
  name: Kestrel EDR
  text: Self-hosted EDR for Windows
  tagline: Catches infostealers while they work, contains the process on the device, and gives IT one incident that says what was taken and what to rotate. Your telemetry stays on your own server.
  image:
    light: /img/console/overview-hero-light.png
    dark: /img/console/overview-hero-dark.png
    alt: Kestrel console overview
  actions:
    - theme: brand
      text: Quick start
      link: /guide/quick-start
    - theme: alt
      text: What Kestrel is
      link: /guide/introduction
    - theme: alt
      text: Build from source
      link: /build/

features:
  - title: Infostealers first
    details: 16 stealer rules (ST-01 to ST-16) watch for credential-store reads, DPAPI decryption of browser secrets, browser debugging abuse, steal-then-send and canary decoys.
    link: /reference/rules
    linkText: Rule reference
  - title: Ransomware, credential dumping, persistence
    details: RW, CD and PS rule families cover shadow-copy deletion, mass encryption, LSASS dumps, hive theft, Run keys, tasks, services and WMI. Plus a 70-rule SigmaHQ pack in Audit.
    link: /reference/rules
    linkText: Rule families
  - title: Detection and containment on the device
    details: Rules run in the agent, so they keep working offline. Suspend, kill, quarantine, block network access through WFP, or isolate the host.
    link: /console/response
    linkText: Response actions
  - title: Incidents, not alert floods
    details: Alerts are grouped by device and process tree into one incident with a priority, a plain-language storyline, the data at risk and a remediation checklist.
    link: /console/
    linkText: Using the console
  - title: Self-hosted
    details: One Docker Compose stack per organisation (server, PostgreSQL, optional ClickHouse). Agents talk to it over mutual TLS with a pinned internal CA.
    link: /deploy/server
    linkText: Deploy the server
  - title: Honest about user mode
    details: Kestrel has no kernel driver. It aims to detect fast and contain fast; it does not guarantee prevention, and the docs say where the limits are.
    link: /guide/security
    linkText: Security model and limits
---
