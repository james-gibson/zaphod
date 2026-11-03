# Keys

```
id_ed25519        burned private key — public on purpose, DO NOT USE
id_ed25519.pub    the public half; principal `zaphod-beeblebrox`
allowed_signers   ssh-keygen allowed-signers file for the same principal
FINGERPRINT       the pinned fingerprint CI checks the key against
```

## Burned, not merely public

This keypair is the lab's burned vector: the private half is published on
purpose, so that any external test can sign something and any verifier can check
it without exchanging a secret. It is a **test identity**, not a credential.
Nothing it signs is worth anything, and publishing it costs nothing — the
alternative, a shared secret in a test fixture, would be a real key in a public
repository.

`scripts/guard-keys.sh` refuses the case that would actually be dangerous: a
*real* key pasted in where the burned one belongs. It checks the fingerprint
against `FINGERPRINT`, checks the private half is the pair of the public half,
and checks that exactly one private key exists in the tree.

## Use

```sh
scripts/verify-note.sh sign   kb/politics/gaffes.md
scripts/verify-note.sh verify kb/politics/gaffes.md
```

Or by hand, in namespace `zaphod-note`:

```sh
ssh-keygen -Y sign -f keys/id_ed25519 -n zaphod-note note.md
ssh-keygen -Y verify -f keys/allowed_signers -I zaphod-beeblebrox \
  -n zaphod-note -s note.md.sig < note.md
```

Encryption uses the same pair through `age` (see `scripts/notes-encrypt.sh`):
notes are encrypted to `id_ed25519.pub` and decrypted with `id_ed25519`. Because
the private half is here too, the encryption demonstrates the mechanism rather
than protecting anything.
