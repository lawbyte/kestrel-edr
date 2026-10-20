# Kestrel SigmaHQ Audit pack: notice

This directory vendors 70 detection rules from the SigmaHQ project
(<https://github.com/SigmaHQ/sigma>), pinned to commit
`e3f466211866e92553d8389d621ed13cfed5523d` (2026-10-20).

* Each `.yml` file is the **unmodified** upstream file, kept at its upstream
  path (`rules/windows/...`). The `author`, `id`, `references` and every other
  field are exactly as published. `pack.json` records, for each rule, its
  author, title, level, status, the SHA-256 of the vendored file and the
  upstream URL pinned to the commit above. A test
  (`crates/kestrel-detect/tests/sigma_pack.rs`) fails if a file is changed.
* The rules are licensed under the **Detection Rule License (DRL) 1.1**
  (<https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md>).
  The licence text is reproduced below.
* How Kestrel meets the DRL obligations:
  * sharing: the server seeds each rule with `meta.author` = the rule's
    `author` field, `meta.license` = `DRL-1.1`, and `meta.references` = the
    pinned upstream URL followed by the rule's own `references`;
  * use on data: alerts from these rules carry the rule author
    (`Alert.rule_author`), and the console shows it in the alert view.
* Kestrel's own code is not under the DRL; the DRL applies to the rule content
  in this directory only.
* Selection criteria, field-mapping notes and the rules deliberately left out
  are in `docs/research/notes/sigma_and_peers.md` (section 3).

---

# Detection Rule License (DRL) 1.1

Permission is hereby granted, free of charge, to any person obtaining a copy of this rule set and associated documentation files (the "Rules"), to deal in the Rules without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Rules, and to permit persons to whom the Rules are furnished to do so, subject to the following conditions:

If you share the Rules (including in modified form), you must retain the following if it is supplied within the Rules:

1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).

2. a URI or hyperlink to the Rule set or explicit Rule to the extent reasonably practicable

3. indicate the Rules are licensed under this Detection Rule License, and include the text of, or the URI or hyperlink to, this Detection Rule License to the extent reasonably practicable

If you use the Rules (including in modified form) on data, messages based on matches with the Rules must retain the following if it is supplied within the Rules:

1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).

THE RULES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE RULES OR THE USE OR OTHER DEALINGS IN THE RULES.
