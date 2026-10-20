export const SIGMA_TEMPLATE = `title: Non-browser process reads Chrome Login Data
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: Describe what the rule detects in one sentence.
author: Your Name
references:
  - https://example.com/write-up
tags:
  - attack.credential_access
  - attack.t1555.003
logsource:
  category: file_access
  product: windows
detection:
  selection:
    TargetFilename|endswith: '\\\\Login Data'
  filter_browsers:
    Image|endswith:
      - '\\\\chrome.exe'
      - '\\\\msedge.exe'
  condition: selection and not filter_browsers
falsepositives:
  - Password managers importing from Chrome
level: high
`
