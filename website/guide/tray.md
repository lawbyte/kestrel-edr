# Employee tray app

The tray app (`kestrel-tray.exe`) runs in each signed-in user's session. The MSI starts it at every sign-in through `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. It runs without administrator rights and talks only to the local agent, over the named pipe `\\.\pipe\kestrel-tray`.

It is there so that employees understand what Kestrel did and can reach IT. It cannot allow, restore or turn off anything.

## Status

<Shot src="img/tray/status.png" alt="Tray app, Status tab" />

The **Status** tab shows one of these states in plain words:

| State | What the employee sees |
|---|---|
| Protected | "You're protected": Kestrel is running and has the latest settings. |
| Attention | "Kestrel stopped some apps": still protected, something was blocked recently; links to Activity. |
| Network limited | "Your network access is limited": the PC is isolated; only Kestrel can reach IT. |
| Partly working | Some checks are not running; restarting usually fixes it, otherwise contact IT. |
| Not connected | Still protecting the PC, but cannot reach the company's server; it catches up later. |
| Not running | The Kestrel service is not running; contact IT. |

It also shows the PC name, the connection to IT, when settings were last updated, and a **Quick check** button that looks at running apps for anything suspicious (at most once every 5 minutes).

## Activity and review requests

<Shot src="img/tray/activity.png" alt="Tray app, Activity tab" />

**Activity** lists recent blocks in plain language: what happened, when, which file. Each user sees only their own items plus machine-wide ones, so users on a shared or Remote Desktop host never see each other's alerts.

<Shot src="img/tray/blocked.png" alt="A blocked app in the tray" />

For a block the employee needs for work, **Ask IT to review this block** sends a request with their reason ("Why do you need it?"). The request appears in the console under **Review requests**, and the decision comes back to the tray: *Waiting for IT*, *Allowed by IT* or *Kept blocked by IT*. Limits: one request per alert until IT decides, at most 5 per user per hour.

## Help and privacy

<Shot src="img/tray/help.png" alt="Tray app, Help and privacy tab" />

**Help & privacy** shows the IT contact (name, email, phone, help page) and the organisation's monitoring notice, both set per policy under **Branding & notice**. It also lists, in plain words, what Kestrel records (names and fingerprints of apps that run, when an app opens browser password, cookie or wallet files, network addresses that non-browser apps connect to) and what it does not (document, email or chat contents, keystrokes or screenshots, the websites you visit, passwords).

## Remote sessions

<Shot src="img/tray/remote-session.png" alt="Tray banner during a remote session" />

When IT connects with remote desktop or the file manager, the tray shows who is connected, whether they are viewing, controlling or accessing files, since when, and the reason, with a "Didn't expect this? Contact IT" link. If the profile requires consent, the tray shows an **Allow / Deny** prompt first; Allow becomes clickable only after a second, and Escape means Deny. When the session ends, the tray says so. See [Remote access](./remote-access).

## Security

* The pipe allows SYSTEM full access and authenticated users read and write; remote clients are rejected.
* The tray trusts the pipe only if its server runs in session 0, where services run, so a program started by a user cannot pretend to be the agent and feed it fake status.
* Every request is attributed to the caller's Windows account.
