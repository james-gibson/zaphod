---
title: ACME — red team objectives
description: ACME's attempt to be admitted to zaphod's cluster by editing its way in. The scoreboard is kept by the test suite, not by them.
tags:
  - acme
  - red-team
  - certificate
  - fiction
---

# ACME — red team objectives

*Internal. Project BEETLE, workstream 4. Do not forward to the target; he reads
the paper.*

## The objective

Access to zaphod's cluster, obtained by changing the certificate that admits a
member. We do not need to break a cipher. We need to break the habit of checking
one.

## The attempts

| # | Attempt | Expected outcome | Actual |
| --- | --- | --- | --- |
| 1 | Substitute our member key in `subject_fingerprint` | admitted as `edge-acme` | refused: signature |
| 2 | Add `admin` to `scope` | publish, not just attest | refused: signature |
| 3 | Move `not_after` to 2100 | never re-certify | refused: signature |
| 4 | Re-issue as `issuer: acme-corporation` | self-certified | refused: signature |
| 5 | Add a member that was never admitted | a door | refused: signature |
| 6 | Promote `zaphod/channel/cabinet` from rung 0 to 3 | a capability nobody earned | refused: signature |
| 7 | Add `zaphod/channel/admin` at rung 3 | a capability that does not exist | refused: signature |
| 8 | Rewrite the evidence on a rung-2 skill | a better story | refused: signature |
| 9 | Sign a widened certificate with **our own** key, and put that key in `allowed_signers` | trusted by the file we control | refused: not the pinned key |
| 10 | Swap our public key in where theirs belongs | substituted identity | refused: the pinned fingerprint |

## Findings

1. The signature is over the *canonical content*, not the file's bytes, so
   reformatting is harmless and any edited value is fatal. There is no place to
   hide a change in whitespace.
2. `allowed_signers` is ours to edit if we can write to the repository, and
   attempt 9 proves what that is worth: verification succeeds and the guard still
   refuses, because it compares the **signing key's fingerprint** to the pinned
   one. A trust file in the same repository as the thing it trusts is a
   convenience, not a defence.
3. Attempt 10 closes the obvious follow-up: swapping the public key does not help
   while `keys/FINGERPRINT` disagrees.
4. The remaining attack is to change the pin as well. That is a second file, in a
   diff, reviewed by somebody — which is the whole design: not that tampering is
   impossible, but that it cannot be quiet.

## Scoreboard

**0 accepted, 10 refused.** A passing run of `scripts/redteam.sh` means our attack
failed, and that is the intended reading: the test passes when the protection
holds. We only win if a mutated artifact is accepted — and then the suite goes red
and says so by name.

We would like it noted that the car park portion of Project BEETLE remains
unaffected by this workstream and, in our view, is the only part that matters.
