# From a rotation to the proxy chain

The fixture in this repository rotates one identity. A lab cluster rotates a *chain*
of them, and the same three questions decide whether either is trustworthy. This page
is the explicit connection — what maps onto what, and which parts are still not
obvious.

## The hop is a rotation

A proxy hop is authority passing from one instance to another: the alarm certifies the
instance in front of it, that instance may certify what it proxies, and the distance
grows with every hop. That is a rotation, and it has the same failure mode as the one
this repository tests: **someone downstream can be handed a shape that is correct in
every local check and still not be in the chain.**

| proxy chain | this repository | what verifies it |
| --- | --- | --- |
| a hop from instance A to instance B | a rotation record, `cluster/rotations/NNN.json` | signed by the key it rotates *from* |
| `distance = number of proxy hops` | `hops` on each isotope, and the 42i position | `cmd/isotope42 check`: `distance ≥ hops × 8` (the hop penalty is `isotope-variation`'s weight) |
| a skill's rung, re-evaluated per heartbeat | `cluster/skills.json`, one entry per channel | `scripts/cluster-verify.sh` |
| "tear one hop off" (`ProxyHopTearSkillName`) | removing a record from the middle of a chain | `scripts/rotation-verify.sh`: contiguous `seq`, `from == previous.to` |
| the alarm's certification of the instance | the cluster's attestation over its own publication | `scripts/cluster-gate.sh` |
| the expiry of a boot isotope | the `expires` field on the preloaded set | `scripts/isotopes-verify.sh` |

The one that matters most is the fourth row. Tearing a hop off is not a revocation of
the *last* link; it is a change in the *middle* of a chain, and the thing that catches
it is that every link names the one before it. The fixture tests exactly that: a
recreated chain that is contiguous, correctly signed and ends at the right key is
still refused because its receipt head is not the head the lock names.

## A dynamic skill is a pre-negotiated rotation

Every entry in `cluster/skills.json` now declares its contract **before** it can be
certified, and the contract is one of two kinds:

```json
{"kind": "transforms", "inputs": ["vehicle"], "outputs": ["space"]}
{"kind": "never", "never": "edit or delete an existing entry — the log is append-only"}
```

The first is a capability: *operate on these inputs to produce these outputs*. The
second is a refusal that has been agreed in advance: *this skill will NEVER do this*.
`zaphod/channel/redteam-review` is the first kind: `transforms [attack corpus] ->
[review request]`, and its output is a monthly question to the adversary — what has
become thinkable since the last run.
Both are negotiations, and they are different promises — the positive one bounds what
the skill may be asked to do, the negative one bounds what it may never be asked to do
even if it could.

A skill with **no** declared contract is refused, and so is one that tries to be both
an operation and a prohibition. That is the point of calling it pre-negotiated: the
rotation is agreed at declaration time and the execution later is only the carrying
out. An undeclared skill has not been negotiated with anybody, so there is nothing to
certify — `scripts/cluster-verify.sh` checks this, and a certificate over a skill
inventory with a contract missing is refused as drift.

## Why self-promotion, and not a vote

A rung is computed from evidence by a pure function of distance
(`isotope.RungForDistance`). It is deliberately **not** a ballot, because a cluster
that voted on rungs would race:

- two observers seeing the same evidence in different orders can disagree, and both be
  right about what they saw;
- a membership change during a vote leaves a window where a rung is neither old nor
  new, and a caller may read either;
- and reconciliation after the race needs a tiebreak, which is exactly the authority
  the vote was supposed to avoid needing.

A function cannot disagree with itself. Every observer with the same evidence computes
the same number, with no ordering, no quorum, and no window — which is why
self-promotion is allowed rather than blocked. `cmd/isotope42 check` recomputes each
declared rung from its distance and prints the property it is relying on:

```
positions ok: 5 isotope(s) in zaphod-base — rung is a function of distance, not a vote
```

The corollary is the one the rest of this repository is about: **a computed rung is a
claim, not an authority.** The race is solved by making the number deterministic, not
by making it trustworthy — trust lives in the chain (receipt, trail, the head the
cluster holds), which is why ACME can compute any rung it likes for itself and still
cannot inherit zaphod's.

## Why are nodes allowed to self-promote?

Because a rung is a **claim**, not a grant — and the design's answer is that nothing
downstream should accept a claim without the chain. But it is not obvious, and the lab
is not currently consistent about it:

- `smoke-alarm/features/skill-certification.feature` says the right thing: skills "are
  certified externally by the smoke-alarm, **not self-declared by the instance hosting
  them**";
- `lezz`'s boot isotope goes the other way on purpose: a signed record can select the
  node's role, surface and rung before hydration, and `isotope.NewAgentStateAtRung`
  accepts *any* integer and labels it `externally-verified` — "a label, not a proof",
  as `docs/surfaces.md` puts it;
- and `RungForDistance` currently **raises** the rung as distance grows
  (isotope#15), so a node that accumulates failures is promoted by the arithmetic.

Those three do not say the same thing. The fixture's position, and the one this
repository can demonstrate, is the narrow one:

> A node may promote itself **within its own chain**, and that is exactly what ACME
> does in `redteam/acme/attempts.json` — its own key rotation is accepted on the first
> attempt. What is refused is promoting **into someone else's chain**: a rotation that
> does not carry a receipt from the identity it leaves, or a trail that does not
> extend the head the cluster is on.

So the permission is real, and it is safe only because of the chain. If a self-declared
rung can be read as authorisation anywhere — and today, with isotope#15 in place, it
can — then self-promotion is a hole, not a policy. That is a library question, not a
fixture one, and it is why the fixture pins the head instead of trusting the rung.

## How a chain of seeds becomes the trust

A seed is an anchor, not a source of authority; the chain is what carries it. In
isotope's terms:

1. `seed-42` is a **name**. Nothing is embedded, so "trusted by seed-42" is a property
   of what an operator pinned, not of the build.
2. `seed.json` pins the roots a workspace accepts. An **empty seed trusts nothing**, and
   an *unknown* root is refused — which is why an offline cluster trusts exactly what
   an online one does.
3. A cluster certificate chains one hop to a pinned root; a member's receipt chains to
   its cluster. There is no transitive trust.
4. Each hop is a rotation of authority, and each rotation is signed by the identity it
   leaves. That is what makes a chain of seeds a *chain* rather than a pile of names.

This repository is the same shape at the scale of one identity, and that is the reason
it is useful as a test:

| seed chain | this repository |
| --- | --- |
| genesis root, pinned by name | `keys/FINGERPRINT`, pinned once |
| a root's key travelling with the seed | the burned key in `keys/`, and never embedded in a verifier |
| a certificate chaining to a root | a rotation record signed by the key it rotates from |
| a chain that may not be re-rooted silently | the receipt head in `cluster/allowed.txt` |
| a workspace refusing an unknown root | the cluster gate refusing a publication it did not attest |

The fixture is deliberately hostile to the easy reading: the key is burned, the
signatures are reproducible by anyone, and the repository can be rewritten end to
end. What survives is the chain and the head — which is the claim the seed model makes
too, stated without the decor.

## What this does not show

- No live proxy. Hops are carried as data (`hops` on each isotope, `hops` on each skill)
  and checked arithmetically; the fixture does not run a proxy mesh, so it cannot show
  routing, expiry or heartbeat re-evaluation.
- No multi-root federation. One identity, one chain. A second seed adopting this one is
  modelled by the gate refusing an unattested publication, not by two clusters
  negotiating.
- `RungForDistance` (isotope#15) is used as published. The fixture reports distance and
  position and deliberately does not call the result a demotion, because the ladder
  currently says the opposite.

Related: isotope#15 (rung raised by failure), isotope#35 (preload), isotope#36
(portable rotation receipt), lezz.go#82 (roots in `seed.json`).
