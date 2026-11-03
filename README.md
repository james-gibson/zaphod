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
