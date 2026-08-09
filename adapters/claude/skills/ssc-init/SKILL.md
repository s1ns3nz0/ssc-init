---
name: ssc-init
description: Inspect the latest local SSC Init supply-chain findings and explain available user-approved actions.
---

Run `ssc-init findings --json`. Present “No finding” rather than “Safe” when
the findings array is empty. Preserve verdict, severity, confidence, rule IDs,
and action exactly. Never claim that this advisory plugin blocked execution.
Do not quarantine, restore, install, or schedule anything without explicit user
approval.
