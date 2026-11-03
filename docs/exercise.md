# Exercising webhooks and cluster actions

Two workflows are prepared to fire at a target you configure. Neither has a
default target: with no configuration they run, print a notice and exit 0, so the
schedule does not go red on a fresh clone.

| Workflow | Timer | Variable | Optional secret |
| --- | --- | --- | --- |
| `exercise-webhooks.yml` | every 6h (`23 */6 * * *`) | `vars.ZAPHOD_WEBHOOK_URL` | `secrets.ZAPHOD_WEBHOOK_TOKEN` |
| `exercise-cluster.yml` | every 6h (`41 */6 * * *`) | `vars.ZAPHOD_CLUSTER_URL` | `secrets.ZAPHOD_CLUSTER_TOKEN` |

Set them under **Settings → Secrets and variables → Actions**. The URLs are
variables, not secrets, because a URL is not a credential; the tokens are
secrets and are never echoed.

## Triggers

Both run on a schedule, on `workflow_dispatch`, and on `repository_dispatch`, so
an external test can ask for one immediately:

```sh
gh workflow run exercise-webhooks.yml -f event=deploy-finished
gh api repos/james-gibson/zaphod/dispatches \
  -f event_type=zaphod-exercise -F client_payload[sha]=deadbeef
```

## What the webhook exercise sends

A JSON body, POSTed as-is, with a detached signature in a header:

```
X-Zaphod-Signer:    zaphod-beeblebrox
X-Zaphod-Namespace: zaphod-webhook
X-Zaphod-Signature: base64(payload.json.sig)
Authorization:      Bearer <token>        (only when the secret is set)
```

The body is signed with the burned key. A receiver verifies it with the
`allowed_signers` file from this repository and the raw body — no secret needs to
be shared, and the signature proves only that whoever sent it had a key everybody
has. That is the right property for a test: it exercises the verification path
without creating something that must be protected.

```sh
curl -fsSLo allowed_signers https://raw.githubusercontent.com/james-gibson/zaphod/main/keys/allowed_signers
curl -fsSL -H "X-Zaphod-Signature: ..." "$URL" > payload.json     # whatever you stored
base64 -d header.txt > payload.json.sig
ssh-keygen -Y verify -f allowed_signers -I zaphod-beeblebrox \
  -n zaphod-webhook -s payload.json.sig < payload.json
```

## What the cluster exercise does

Against `vars.ZAPHOD_CLUSTER_URL`, which is expected to be the base of a lezz
demo registry:

- reads `<url>/cluster` and reports how many clusters answered (always);
- when `secrets.ZAPHOD_CLUSTER_TOKEN` is set, POSTs a signed exercise
  registration to `<url>/cluster/zaphod` and reports the status.

The second step is a placeholder route: point the variable at an endpoint that
speaks your cluster's API, or leave the token unset and the workflow stays
read-only.

## Guard rails

- A target must be `https://`. The workflows refuse anything else, including
  `http://127.0.0.1`, rather than treating a configured-but-insecure target as
  acceptable.
- No secret is ever printed; `curl` is given the header through the environment.
- `--max-time 15` and `--fail-with-body`: a configured target that refuses is a
  real failure, not a silent pass.
