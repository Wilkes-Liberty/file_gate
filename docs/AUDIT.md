# Durable audit trail (audit_chain)

File Gate always logs operational events to the `file_gate` PSR logger
channel (dblog / syslog). That is fine for dashboards and day-to-day ops, but
it is **not** a compliance-grade audit: rows can be deleted, are not hash-
chained, and disappear with log rotation.

## Recommendation: soft-enable `audit_chain`

**Yes — use [audit_chain](https://www.drupal.org/project/audit_chain) when you
need a verifiable trail.** It is a sibling W&L module: append-only rows, each
hash covering content plus the previous row, optional HMAC via Key module.

File Gate integrates **softly**:

| Mode | Behaviour |
|------|-----------|
| `audit_chain` **enabled** | `file_gate.audit` writes channel `file_gate` via `audit_chain.logger` |
| `audit_chain` **absent** | `file_gate.audit` is a no-op (chain-only). Operational dblog still comes from controllers / `logger.channel.file_gate`, not this service |

There is **no hard dependency** on Key/Encrypt — gated downloads keep working
on lean installs. Composer `suggests` `drupal/audit_chain`.

### Enable

```bash
composer require drupal/audit_chain
drush en audit_chain -y
# Configure signing key at /admin/config/system/audit-chain
drush audit-chain:verify
```

### Operations recorded

| Operation | When |
|-----------|------|
| `mint` | Successful grant mint |
| `mint_denied` | Scope / identity / A2 refusal (reason in metadata) |
| `download` | Successful gated delivery |
| `download_denied` | Hard grant reject (not soft step-up challenges) |
| `otp_issue` | OTP code issued (never the code itself) |
| `revoke` | Token or jti revoke |
| `field_gating_refused` | A save that would gate a field on a non-private file scheme was refused. Metadata: `storage` (config name), `scheme`, `write` (`entity` or `config`) |

Metadata promotes `entity_type` / `id` / `label` when present; free keys
(`uuid`, `gate_method`, `field`, `reason`, `secret_id`) stay in JSON. **Never**
store raw secrets, full tokens, or original filenames.

`label` is always an opaque identifier (`file:<id>`), never
`FileInterface::getFilename()`. audit_chain copies `label` into the indexed
`entity_label` column; a filename there cannot be redacted without breaking
the hash chain.

### Evidence-required delivery (`audit_require_keyed`)

By default, mint and download use best-effort `log()`. If the chain is
absent or the signing key will not resolve, the event is unsigned or
dropped and **delivery still proceeds**.

Set `file_gate.settings.audit_require_keyed` to `true` (also a checkbox on
the File Gate settings form) when a signed row is mandatory evidence.
Mint and download then call `logKeyed()` and, if the signed append fails,
return **HTTP 503** with a generic body and **do not stream file bytes**.
Denied paths (`mint_denied`, `download_denied`, `otp_issue`, `revoke`) stay
best-effort: they already refuse the action.

Leave the setting off unless the site has `audit_chain` enabled and a
signing key configured. A missing key with the setting on fails closed for
every mint and download.

### Code

```php
// Service: file_gate.audit → \Drupal\file_gate\Service\FileGateAudit
$this->audit->logDelivery('download', [
  'entity_type' => 'file',
  'id' => (string) $file->id(),
  'label' => FileGateAudit::fileLabel($file),
  'uuid' => $file->uuid(),
  'gate_method' => $gate['method'],
  'field' => $gate['field'],
]);
```

Verify integrity globally (all channels): `drush audit-chain:verify`.
