# tfstatescan

A `.tfstate` file is plaintext JSON, and Terraform's own docs say so
directly: "sensitive data ... will be persisted in the state file." Once a
resource has a `password`/`result`/`private_key_pem`-shaped attribute, its
real value sits unencrypted in state — including a `random_password` you
generated specifically so you'd never have to hardcode one, and even a
Kubernetes Secret's `data` map, whose entire purpose is holding sensitive
values. That state file then gets committed to a repo, or sits in an S3
backend bucket someone forgot to lock down. `tfstatescan` reads a state
file and tells you exactly which resource attributes hold real plaintext
secret material — not just anything that looks scary, and not everything
with the word "secret" in its name.

## Usage

```bash
tfstatescan terraform.tfstate
tfstatescan terraform.tfstate --json    # machine-readable findings for CI
```

Exit code `1` if anything is found — this is meant to gate a CI job the
same way `depaudit`/`leakscan` do elsewhere in this workspace.

## How detection works

Two tiers, the same shape `leakscan` uses for the same reason (known shapes
first, a broader fallback second, never double-counted):

- **Known** — a hand-maintained table of `(resource_type, attribute_path)`
  pairs where the *provider's own documented schema* says the attribute
  holds real secret material: `aws_db_instance.password`,
  `random_password.result`, `tls_private_key.private_key_pem`,
  `aws_secretsmanager_secret_version.secret_string` (yes — the value you
  handed to Secrets Manager sits in your state file too, a real,
  documented gotcha of that exact resource), `azurerm_key_vault_secret.value`,
  and about fifteen others (see `KNOWN_RULES` in `src/scan.rs`).
  `kubernetes_secret.data.*` is a prefix rule rather than a fixed key list,
  since a Secret's `data` map has caller-defined keys — every child under
  it is treated as sensitive, on the reasoning that a Kubernetes Secret's
  entire purpose is holding sensitive values (its `username` field gets
  flagged alongside its `password` field; see Status for what this means
  in practice).
- **Heuristic** — for anything not in that table, the attribute's own
  *name* (not its value's content — see below) is checked against a
  keyword list (`password`, `secret`, `token`, `private_key`, `api_key`,
  `credential`, ...), with an explicit exclusion list for names that
  contain one of those words but are references or metadata rather than
  the material itself: anything ending in `_id`, `_arn`, `_endpoint`,
  `_url`, `_length`, `_count`, `_version`, `_enabled`, `_required`, or
  `_hash` is skipped (`secret_id`, `secret_arn`, `token_endpoint` all
  survive unflagged), and any value that looks like an AWS ARN
  (`arn:aws:...`) is skipped regardless of the key name.

Only string leaf values are inspected (numbers, booleans, and `null` are
structurally never plaintext secrets), and empty strings are skipped —
`"password": ""` (no password set) and `"password": null` (AWS-managed
password via `manage_master_user_password = true`) both correctly produce
no finding.

**Terraform 1.11+ write-only arguments** (`password_wo`, ending in `_wo` or
`_wo_version`) are explicitly excluded from the heuristic, regardless of
what they contain — this is a real, recent Terraform feature specifically
designed so the value is *never* persisted to state at all (in practice
these are always `null` in a real state file; the exclusion is name-based
so it holds even if that assumption is ever wrong).

**Value content is never analyzed** — no entropy check, no regex against
the string itself, unlike `leakscan`. A `description` field whose text
happens to say "rotate the database password every 90 days" is not
flagged, because its *key* (`description`) isn't secret-shaped. This is a
deliberate scope decision: `.tfstate` secrets are a well-documented,
name-driven problem (a fixed, small set of provider attributes), not an
open-ended "grep for anything secret-shaped" problem the way arbitrary
source files are.

## Redaction

Findings print `redact()`'s output, never the raw value: the first and
last 4 characters, with everything between blotted out (`Sup3************s!42`),
or full masking for anything 8 characters or shorter where showing 4-and-4
would leak the whole thing.

## Scope: Terraform state format version 4

This targets the state shape every Terraform release since 0.12 produces
(nested-JSON `attributes`, not the pre-0.12 dotted-key flatmap format) —
see **Not done** below.

## Status: built and verified against a realistic hand-built state fixture with 7 planted secrets and 9 real safe values around them

- **19 unit tests** (`cargo test --lib`): `state` parsing (4 — a realistic
  multi-field state document, missing `resources` defaulting to empty,
  malformed JSON and a missing `type` field both clean errors); `scan`
  module (15 — `redact` at both size thresholds, `leaf_name`'s array-index
  stripping, every known-table rule firing on its documented attribute and
  *not* firing on that same resource's safe sibling attribute
  (`aws_db_instance.username`, `tls_private_key.public_key_pem`), the
  `kubernetes_secret.data.*` prefix rule flagging every child key, the
  `aws_secretsmanager_secret_version.secret_id` ARN correctly *not* flagged
  next to its `secret_string` sibling that *is*, the generic heuristic
  catching an attribute on a resource type with zero entries in the known
  table, `manage_master_user_password = true` leaving `password: null`
  unflagged, a `*_wo`-named attribute never flagged even when given a
  non-null secret-shaped value, and a `description` field whose *text*
  contains the word "password" correctly not flagged since only the key
  name is judged).
- **Live-verified against `tests/fixtures/realistic.tfstate` through the
  actual compiled binary**, a real Terraform state-v4 document (9
  resources) with exactly 7 secrets planted among realistic safe
  attributes: `aws_db_instance.primary`'s `password`, a second
  `aws_db_instance` using `manage_master_user_password` (password
  correctly `null`, correctly *not* one of the 7),
  `random_password.app_secret`'s `result`, `tls_private_key.ca`'s
  `private_key_pem` (its `public_key_pem` sibling correctly excluded),
  `kubernetes_secret.app_creds`'s `data.password` *and* `data.username`
  (both flagged — see the `data.*` design note above),
  `aws_secretsmanager_secret_version.example`'s `secret_string` (its
  `secret_id` ARN sibling correctly excluded), and one deliberately
  unlisted resource type's `api_token` field caught by the heuristic tier
  rather than the known table — confirmed by running the actual binary:
  ```
  tests/fixtures/realistic.tfstate: 7 plaintext secret(s) found across 9 resource(s)

  [known] aws_db_instance.primary (instance #0) password = Sup3************s!42
  [known] random_password.app_secret (instance #0) result = xK9$************wZ8y
  [known] tls_private_key.ca (instance #0) private_key_pem = ----***...---
  [known] kubernetes_secret.app_creds (instance #0) data.password = hunt****************king
  [known] kubernetes_secret.app_creds (instance #0) data.username = *******
  [known] aws_secretsmanager_secret_version.example (instance #0) secret_string = prod***************6c5b
  [heuristic] some_saas_provider_user.svc (instance #0) api_token = tok_*******************2d1e
  ```
  exit code `1`. A clean state file (`{"version":4,"resources":[]}`)
  through the same binary printed the zero-findings message and exited
  `0`. Every redacted value on screen matches `redact()`'s documented
  first-4/last-4 behavior, and none of the 9 resources' safe attributes
  (`username`, `id`, `ami`, `tags`, `description`, `hex`, `public_key_pem`,
  `secret_id`) appear anywhere in the findings list.

**Not done / deliberately deferred**: the pre-0.12 state format (schema
versions 1-3, `attributes` as a dotted-key flatmap like `{"tags.%": "1",
"tags.Name": "web-1"}` instead of real nested JSON) isn't parsed — a state
file that old should be `terraform state push`'d through a current
Terraform binary first, which upgrades it automatically. The known-table is
hand-maintained against providers' *documented* schemas, not generated
from the providers' actual Go source or protobuf schema — a provider
version that renames or adds a sensitive attribute won't be caught until
the table is updated (the heuristic tier is the safety net for exactly
this gap, at the cost of being name-based rather than authoritative).
Terraform Cloud/Enterprise's remote state API isn't fetched from directly —
this reads a local `.tfstate` file (or a `terraform state pull > file`
you've already run) rather than talking to a backend itself. No attempt is
made to correlate a found secret back to the original HCL that produced it
(no source-map from state back to `.tf` files) — the fix for a finding here
is always "stop putting this value in a resource argument that Terraform
persists to state," not something this tool can automate.
