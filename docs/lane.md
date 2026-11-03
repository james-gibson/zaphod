# An actor stays in lane

The red team in this repository is not an attacker against a secret. zaphod's key is
**burned**: the private half is committed and published, so ACME — the actor playing
the adversary — holds exactly the key zaphod signs with. Nothing here rests on ACME
being unable to produce a valid signature. It can. It does, in
`redteam/acme/attempts.json`, and that attempt is expected to be refused.

## What each layer can and cannot do

| Layer | The question it answers | Why a signature is not enough |
| --- | --- | --- |
| pin (`keys/FINGERPRINT`) | *is this the key we trust?* | `allowed_signers` lives in the same repo as the thing it vouches for, so a file that trusts ACME says yes |
| allowed version (`cluster/allowed.txt`) | *is this the version we allowed?* | a valid signature over a widened certificate is still a widened certificate |
| rotation chain (`cluster/rotations/`) | *was this update sanctioned?* | the key is public, so "signed by the allowed key" is available to everyone |
| receipt (`chain/rotations/*.receipt`, head in the lock) | *did this rotation come back onto the same identity?* | a chain recreated with another identity is a different chain, and no signature on it says otherwise |
| attestation (`attestation` field, checked by the cluster) | *did the running identity authorise it?* | the signing key is public, so a signature cannot answer this; the secret was never in the repository |
| cluster gate (`cluster-gate.sh`, state beside the secret) | *is this what I published?* | every file in the repository can be rewritten, including the lock and the pin, by anyone with the repo |

The three are independent, and the tests prove each one is load-bearing:
`scripts/teeth.sh` removes them one at a time in a throwaway copy and requires the
red team to succeed — going red, and showing the drift.

**ACME is not bumbling.** The suite would be worthless if it only ever said no: a
guard that refuses everything is indistinguishable from a broken guard, and a red
team that never does anything competently is not a red team. So the run also holds
positive controls — ACME rotates its own cluster key, extends its own receipt
chain, verifies its own certificate, and signs with its own key, all on the first
attempt, all accepted. It has the same tooling, the same procedures and the same
shape of evidence zaphod has.

The claim being tested is therefore narrow and true: **capability is not
continuity.** ACME can do everything; what it cannot do is inherit, extend or
recreate zaphod's rotation, because a receipt chains onto the identity it came from
and the head is in zaphod's lock. That is why the red team's wins and losses are
recorded together — the interesting fact is not that attempts fail, it is that the
one that should succeed for a competent actor does, and the rotation still does not
transfer.

## Set up to lose

The most interesting version of this test gives ACME everything a lawful adversary
could have: the repository, the **burned signing key**, the tooling, a proxy
position, and the filesystem the cluster's artifacts live on. No policy exemption,
no excluded credential. Under that model ACME produces a rotation that is correct in
every respect a third party can check — signature, public receipt chain, contiguous
history, coherent lock — and the cluster still refuses it:

```
held  rotation: forged with the repository, the key and the tooling — attestation is not mathematically the one this identity would produce
```

The refusal is arithmetic. A rotation carries an `attestation` computed from the
cluster's **identity secret**, which lives in the running identity and is never
written into the repository or handed to the artifacts:

```
attestation = SHA256(secret ":" canonical(rotation) ":" previous-receipt)
```

Everything an actor can obtain from the repository, the key and the tooling cannot
compute that value, so a forged rotation is not "unauthorised" — it is *wrong*, and
the check says so. The identity's own rotation is attested and accepted on the first
attempt, which the suite also asserts, so the guard is not simply refusing.

**The boundary, stated rather than implied.** This models access to the repository,
the signing key, the tooling, the artifacts and the filesystem. It does not model
reading a running process's memory. A secret in memory is a real boundary — a proxy
hop cannot read it, and neither can a file copy — but it is not an absolute one, and
`scripts/identity.sh` says so at the top rather than letting the demonstration imply
more than it proves.

## The lane

ACME owns its attempts and may rewrite them freely. It can change mutations, signing
keys, and trust files. It cannot change the guard: the pin, the lock, the verifier
and the CI job. That is not enforced by permissions — ACME can write files in the
repo — it is enforced by **review**: a change to the guard is a diff somebody reads,
while a change to the attempts is expected and unremarkable.

**And the cluster cannot rely on corporate policy to save it.** An adversary is not
bound by zaphod's rules, by review, or by who owns a file. The repository is a
*publication*: anyone with it can rewrite the artifacts, the lock, the pin and the
rotation chain, and produce something that is internally consistent — every check a
third party can run against the repository passes, because the repository says so.
That is why the last check does not read the repository's bookkeeping at all. The
cluster keeps its own state beside its identity secret, outside the repository, and
asks a different question:

```
held  publication: rewritten corpus, self-consistent, with the signing key — the published certificate is not the version this cluster attested
```

So the demonstration is not "tampering is impossible". It is "tampering cannot be
quiet, and the position it cannot reach is the one the cluster holds." ACME may do
anything inside the space it owns; every change outside that space arrives as a
record — a rotation with a signature, a lock rewrite, a diff — and what is not
recorded is refused by arithmetic rather than by process.

## Why zaphod's update is accepted and ACME's is not

**Policy is not part of the model.** An earlier version of this file excused ACME
from the burned key on corporate-policy grounds. That flattered the test: it made
zaphod's first-attempt rotation look like a privilege when the difference was
permission, and it left the guard unmeasured against the one adversary that matters.
The model now grants every lawful advantage — the repository, the burned key (it is
published, so using it is lawful), the tooling, a proxy position, the filesystem.
Two of the refused attempts use the burned key and fail on the **version**, not on
permission.

With that closed, the interesting question is what stops ACME *recreating the
sanctioned shape exactly*: its own key, its own rotation records, contiguous,
correctly signed, receipts chained, ending at zaphod's current key. Structurally it
is a perfect rotation. It is still refused, by one line:

```
chain head 4f8602f4c627abdc… is not the head the lock names (d176538a81e0774b…)
```

That line is the **receipt**. Each rotation carries a receipt computed from the
identity it rotates from over the rotation's content and the previous receipt:

```
receipt_n = SHA256("zaphod-rotation-v1:" + from_fingerprint + ":" + canonical(record_n) + ":" + receipt_{n-1})
```

so a rotation is a claim made *back onto itself*: the identity that is being left
vouches for the identity being adopted, and the chain can only be extended by
continuing it. ACME's recreation is a different chain with a different head. It
gains a rotation; it does not gain **zaphod's** rotation, and it cannot splice its
own key onto the chain that already exists.

zaphod's update is accepted because it extends the chain that was reviewed, signed
by the key it rotates from, with the lock rewritten in the same commit — one attempt,
no manual edits. And if an insider signed an unsanctioned change with the allowed
key, the lock refuses that too; `scripts/teeth.sh` proves all three layers.

**The first rotation is what makes this real.** While the cluster runs on the burned
key, ACME can recompute a receipt chain — the formula is public and so is every
input — but it cannot *extend* one: the next record must be signed by the key the
chain ends on, and after the first rotation that key is no longer burned. So the
rotation is not a formality; it moves the identity off a key everybody has, and the
receipt is what says it is still the same identity afterwards. The fixture performs
that rotation in CI on every push (`Zaphod rotates on the first attempt`), which is
also the only way this claim stays tested rather than assumed.

The portable receipt is a library concern and is filed as
[isotope#36](https://github.com/james-gibson/isotope/issues/36); the fixture's
`scripts/lib-receipt.sh` implements the shape so the file layout does not change
when the library provides it.

An actor that stays in lane is one whose changes are all accounted for. That is what
the suite measures.

## The 42i reading

Every accepted attempt is a violation, and the isotope library already prices
violations: `scope-compliance` is 20, `secret-flow-violation` is 24, and so on. The
run ends by asking the library where the cluster would now be:

```
42i 42 + 0i (seed-42, rung 0)
verdict: ground truth — nothing was accepted
```

Had one attempt been accepted (the receipt layer is what keeps a recreated chain
from counting as one):

```
42i 42 + 20.0i (magnitude 46.5, rung 1, direction: boundary-violation)
verdict: drifted — 1 accepted violation(s) of scope-compliance; distance 20 from ground truth
```

That is the same signal the rest of the lab uses: 42+0i is the ground truth, and any
accepted change away from the only allowed version is distance from it. The reading
comes from the library (`github.com/james-gibson/isotope`), not a local
reimplementation, so the fixture and a real cluster measure the same axis.
