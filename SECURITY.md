# Security policy

Kestrel is security software that runs as SYSTEM on endpoints, so security reports get priority.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability.

Use GitHub private vulnerability reporting: open the **Security** tab of this repository and click **Report a vulnerability**. The report is visible only to the maintainers.

Include, where you can:

* the affected component (agent, server, console, tray, installer) and version (`kestrel-agent --version`, or the version in the console footer)
* the steps to reproduce, and what an attacker gains (for example privilege escalation, detection bypass, remote code execution, data exposure)
* a proof of concept, if you have one

You will get an acknowledgement within 5 working days and a first assessment within 10 working days. Please give us reasonable time to release a fix before you publish details.

## Scope

In scope:

* the agent and its Windows service, the tray app, the MSI and its custom actions
* the server, its REST and gRPC APIs, the admin console and the remote access features
* bypasses of a detection rule or of response safety checks that work in the default configuration

Out of scope:

* attacks that need administrator or SYSTEM rights on the endpoint to disable or blind the agent; the user-mode design cannot prevent these and the [security model](https://lawbyte.github.io/kestrel-edr/guide/security) documents them
* findings that only affect the demo data or the lab scripts under `scripts/vm/`
* denial of service by flooding the server from a valid, enrolled agent

## Supported versions

Only the latest release receives security fixes.

## Past reviews

Independent reviews and their fixes are published in `docs/security-review-2026-10-21.md` and `docs/security-review-v1.1-2026-10-21.md`.
