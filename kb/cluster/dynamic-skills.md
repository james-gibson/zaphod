---
title: Dynamic skills in zaphod's cluster
description: One skill per published channel, rung-certified by the smoke-alarm that is not here yet — so today every skill stops at rung 2, on purpose.
tags:
  - cluster
  - skills
  - certification
  - fiction
---

# Dynamic skills

Zaphod's cluster publishes channels. Every published channel is also a **skill**:
a capability that another agent can call, with a rung that says how much of it has
been proven. The name follows the channel:

```
tuner/channel/car-park
tuner/channel/gaffe-log
tuner/channel/acme-correspondence
tuner/channel/cabinet
```

## The rungs

Certification is the smoke-alarm's job, not the cluster's own. A skill's rung is
the highest claim it can evidence:

| rung | name | what it means |
| --- | --- | --- |
| 0 | declared | the skill exists in the inventory and nothing has been run |
| 1 | exists | a probe reached it: the endpoint answers |
| 2 | deterministic | two runs with the same input produced the same output |
| 3 | scenario-linked | an isotope transit bound it to a Gherkin scenario |

`hops` is the distance from the skill to the alarm that certified it — 0 when the
alarm is in the same cluster, and one per proxy hop otherwise. A skill reached
through a proxy is not less certified; it is certified further away, and the
preloaded set carries the same figure so that a position claiming 0 hops while the
distance says otherwise is refused (`distance ≥ hops × 8`, the hop penalty from
smoke-alarm's certification model).

## What this cluster claims

See [`../../cluster/skills.json`](../../cluster/skills.json). Today:

- `car-park` and `gaffe-log` at **rung 2** — they are deterministic, twice over;
- `acme-correspondence` at **rung 1** — it answers, and nothing more is claimed;
- `cabinet` at **rung 0** — the office will not confirm the ministry exists.

## Why nothing is at rung 3

Rung 3 needs an isotope binding, and an isotope binding needs a smoke-alarm to
issue it. This cluster does not run one. Every "eventually" in this knowledge base
is the same "eventually": the certification model is here, the certifier is not.

So the inventory stops at rung 2 and says so. That is not a gap in the fixture —
it is the honest state of a cluster that has skills and no auditor, and
`scripts/cluster-verify.sh` prints the note rather than quietly implying the next
rung.

## The inventory is signed

`cluster/skills.json` carries a detached signature from the burned key
(`scripts/sign-artifact.sh`), and `scripts/cluster-verify.sh` refuses it if the
signature is wrong, the signer is not the pinned key, or the skills disagree with
the certificate about which cluster they belong to.

Which is why ACME thinks the inventory is the interesting target: a rung is a
capability, and a file that can be edited is a capability that can be granted. See
[`../acme/red-team-objectives.md`](../acme/red-team-objectives.md).

## Preloaded, once

[`../../isotopes/zaphod-base.json`](../../isotopes/zaphod-base.json) is the same
inventory said in isotope terms: the edge and each channel as an isotope with a 42i
position. Every skill must appear in it, and it must not invent one — the set is
generated from this inventory rather than maintained beside it.

It was written once, for the first release, and signed. Editing it means a rotation
record and a rewritten lock, which is the price of having a set other repositories
can pin: a fixture that changes casually is not a fixture.
