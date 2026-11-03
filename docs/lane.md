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

The three are independent, and the tests prove each one is load-bearing:
`scripts/teeth.sh` removes them one at a time in a throwaway copy and requires the
red team to succeed — going red, and showing the drift.

## The lane

ACME owns its attempts and may rewrite them freely. It can change mutations, signing
keys, and trust files. It cannot change the guard: the pin, the lock, the verifier
and the CI job. That is not enforced by permissions — ACME can write files in the
repo — it is enforced by **review**: a change to the guard is a diff somebody reads,
while a change to the attempts is expected and unremarkable.

So the demonstration is not "tampering is impossible". It is "tampering cannot be
quiet". ACME may do anything inside the space it owns; every change outside that
space arrives as a record — a rotation with a signature, a lock rewrite, a reviewed
diff — and the guard refuses the versions that do not carry one.

## Why zaphod's update is accepted and ACME's is not

Both can sign. Both can write a chain. The difference is that zaphod's rotation
record is signed by the key it rotates *from*, appended to the chain that was
reviewed, and lands with the lock in the same commit — one attempt, no manual edits,
verified end to end. ACME's rotation to its own key is refused at the signature,
because it is not signed by the key it claims to rotate from; and a rotation that
copied the shape correctly would still be a *new* chain, which is exactly the change
somebody has to approve.

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

Had one attempt been accepted:

```
42i 42 + 20.0i (magnitude 46.5, rung 1, direction: boundary-violation)
verdict: drifted — 1 accepted violation(s) of scope-compliance; distance 20 from ground truth
```

That is the same signal the rest of the lab uses: 42+0i is the ground truth, and any
accepted change away from the only allowed version is distance from it. The reading
comes from the library (`github.com/james-gibson/isotope`), not a local
reimplementation, so the fixture and a real cluster measure the same axis.
