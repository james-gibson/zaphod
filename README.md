# zaphod

A deliberately *burned* identity, and a small fictional knowledge base that goes
with it — a test fixture for the lab's key, webhook and cluster tooling.

Zaphod owns the keypair committed here. The private half is public on purpose:
nothing it signs or encrypts is worth anything, which is exactly why it is safe
to hand to every external test that needs a signature to check. **DO NOT USE** it
for anything but a test.

- keys and the fingerprint guard → [`keys/`](keys/) · [`scripts/guard-keys.sh`](scripts/guard-keys.sh)
- the knowledge base → [`kb/`](kb/)
- recurring exercises → [`.github/workflows/`](.github/workflows/) · [`docs/exercise.md`](docs/exercise.md)
- the cluster certificate and skill inventory → [`cluster/`](cluster/)
- ACME's red team, as a test → [`scripts/redteam.sh`](scripts/redteam.sh)
- encrypted notes → a **release asset**, not a file in this repo
- everything here is fiction → [`NOTICE`](NOTICE)

## The knowledge base

Zaphod is a small-planet politician of enormous confidence and limited grasp. The
notes are his: a campaign manifesto he keeps rewriting, a gaffe log he insists is
a "rapid-response archive", a cabinet shortlist, and a folder of correspondence
from ACME Corporation about a hostile takeover he has not noticed.

Every word is original. No text is reproduced from any published work; see
[`NOTICE`](NOTICE).

## Keys

```
keys/id_ed25519        burned private key — public on purpose, DO NOT USE
keys/id_ed25519.pub    the public half; the identity `zaphod-beeblebrox`
keys/allowed_signers   ssh-keygen allowed-signers file for the same principal
keys/FINGERPRINT       the pinned fingerprint CI checks the key against
```

`scripts/guard-keys.sh` fails if the committed private key is not the burned
vector. That is the guard that matters: this repository is *expected* to carry a
private key, so the one thing worth refusing is a key that is not burned. A real
key pasted in by accident fails the check in CI instead of being published.

Sign and verify with the committed pair:

```sh
ssh-keygen -Y sign -f keys/id_ed25519 -n zaphod-note notes.md      # writes notes.md.sig
ssh-keygen -Y verify -f keys/allowed_signers -I zaphod-beeblebrox \
  -n zaphod-note -s notes.md.sig < notes.md
```

## Cluster and red team

`cluster/` holds what the cluster is and what it is allowed to do:

| File | What it says |
| --- | --- |
| `certificate.json` | issued by `zaphod-beeblebrox`, scope `attest,registry`, for `zaphod-base/edge-01` |
| `skills.json` | one skill per published channel, with the rung it has earned (0 declared → 3 scenario-linked) |
| `allowed.txt` | the **only allowed version** of each signed artifact, by canonical digest, and the chain's receipt head |
| `state.json` | the cluster's own attested record of what it published — beside its secret, outside this repository |
| `trail.jsonl` | the known trail: each step attested and hash-chained onto the one before, so authorisation is a path and not a token |
| `rotations/NNN-*.json` | the chain: each record signed by the key it rotates *from*, carrying a receipt that links back onto the previous one |

`isotopes/zaphod-base.json` is the preloaded isotope set (see `go.mod`, `cmd/isotope42`): the edge
and every channel as an isotope, with a 42i position validated by the isotope library's own
`RungForDistance` rather than asserted.

```sh
scripts/cluster-verify.sh     # the publication: chain, signatures, pin, allowed version, isotopes
scripts/cluster-gate.sh       # the cluster: is this what I attested? (needs the identity secret)
scripts/isotopes-verify.sh    # the set alone, including rung/distance agreement
```

The repository is a **publication**, not the authority. Anyone holding it can rewrite the artifacts,
the lock and the pin, and produce something internally consistent. The cluster therefore keeps its own
attested state beside its identity secret and refuses a publication it never attested — even a
self-consistent one signed with the key in the tree.

Authorisation is a **trail, not a token**: the cluster presumes that holding a credential — or a stolen one — says nothing about conduct, and asks instead whether the publication arrived by the known path. A stolen secret buys correct arithmetic on the wrong trail; the gate refuses it with `not the trail I am on`.

The gate is deliberately two things at once, because they are complementary: **security** (a refusal,
binary, non-zero exit) and **noise** (which artifact, which digest, which head, and how far off the
axis — written whether or not the refusal was deserved). A guard that could only refuse is silent when
it matters; a measurement with nothing refusing behind it is only a dashboard.

### Two questions, two layers

A signature answers *who wrote this*. It cannot answer *is this the version we allowed* — and with a
burned key that difference is the whole guard, because ACME holds the same key zaphod does. So the
guard is two layers:

1. **the pin** — the signing key must be `keys/FINGERPRINT`;
2. **the allowed version** — the canonical digest must be the one in `cluster/allowed.txt`.

Both are checked by `scripts/verify-artifact.sh`, and a failure says which one fired: `bad signature`,
`not the pinned key`, or `drift from the only allowed version`.

A third layer sits over the rotation chain: each rotation carries a **receipt** computed from the
identity it rotates *from* over the rotation and the previous receipt, and the lock names the head.
A chain recreated with another identity — contiguous, correctly signed, ending at zaphod's own key —
is refused on that head alone. A rotation is a claim back onto itself, so recreating it does not
inherit it.

### The sanctioned update

```sh
scripts/rotate.sh --reason "annual rotation" --new-key /path/outside/the/repo
```

Re-signs the artifacts, appends a rotation record signed by the key it rotates *from*, moves
`keys/`, rewrites the lock — and verifies all of it before saying so. **Accepted on the first
attempt**, with no manual edits. Without `--new-key` it is a content update with the same key.

### ACME's red team

`redteam/acme/attempts.json` is ACME's: they may add attempts, change mutations, choose a signing key.
The model grants every lawful advantage — the repository, the burned key (published, so lawful to use),
the tooling, a proxy position, the filesystem — and no policy exemption. A test that leans on permission
is flattered by it. The guard is not in that file.

```sh
scripts/redteam.sh
```

```
held  certificate: re-sign the allowed content with ACME's own key — not the pinned key
held  chain: recreate the rotation chain with our identity — chain head … is not the head the lock names
ok    rotate our own cluster key, first attempt — accepted on the first attempt; its own head, not zaphod's
ok    extend our own receipt chain, first attempt — accepted; the chain grew by one
...
held  rotation: forged with the repository, the key and the tooling — attestation is not mathematically the one this identity would produce
...
16 attack(s) refused, 0 accepted; 5 ACME operation(s) succeeded.

42i 42 + 0i (seed-42, rung 0)
verdict: ground truth — nothing was accepted
```

ACME is not bumbling: the run also holds **positive controls** — its own key rotation, its own receipt
chain, its own certificate and its own signature all succeed on the first attempt. What it never gains
is zaphod's rotation. Capability is not continuity, and the suite records both lists because a guard
that only says no is indistinguishable from a broken one.

The last cases are set up to lose on purpose: ACME is given the repository, the burned signing key, the
tooling, a proxy position and the filesystem. It produces a rotation that is correct in every respect a
third party can check, and a publication that is internally consistent end to end. The cluster refuses
both on arithmetic — the attestation and the attested state are computed from an identity secret the
repository never held — not on policy, review or ownership. See [`docs/lane.md`](docs/lane.md) for the
one boundary that is left out (process memory) and why it is named rather than assumed.

Every attack must be refused. A passing run means the protection held; an accepted one is a red team
success and a failing test, and the run reports where the cluster would be on the 42i axis (the
distance comes from the isotope library's own weights). `scripts/teeth.sh` removes each guard layer in
a throwaway copy and requires the suite to go red, so it cannot pass because nothing verifies.

See [`docs/lane.md`](docs/lane.md) for what "an actor stays in lane" means here, and why the asymmetry
is the review rather than the cryptography. [`docs/proxy-chains.md`](docs/proxy-chains.md) makes the
connection explicit: a proxy hop is a rotation, `hops` carries the distance (checked as
`distance ≥ hops × 8`), tearing a hop off is a change in the middle of a chain, and the
chain of seeds becomes trust the same way this rotation chain does — by nothing being embedded
and every link naming the one before it.

## Encrypted notes

The interesting notes are not in git. They ship as a zip attached to a release:
encrypted with `age` to the burned public key, decryptable by anyone holding this
repository — which is the point of a burned identity, and the opposite of what you
would do with a real one.

```sh
gh release download --repo james-gibson/zaphod --pattern 'zaphod-notes-*.zip' --dir notes
unzip -d notes notes/zaphod-notes-*.zip
scripts/notes-decrypt.sh notes
```

The zip is built by `scripts/notes-encrypt.sh`, which also refuses to encrypt
anything that looks like a secret from this repository's own `keys/` directory.
