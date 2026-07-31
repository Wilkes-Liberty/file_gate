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
| `audit_chain` **absent** | no-op; dblog/logger still work |

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

Metadata promotes `entity_type` / `id` / `label` when present; free keys
(`uuid`, `gate_method`, `field`, `reason`, `secret_id`) stay in JSON. **Never**
store raw secrets or full tokens.

### Code

```php
// Service: file_gate.audit → \Drupal\file_gate\Service\FileGateAudit
$this->audit->log('download', [
  'entity_type' => 'file',
  'id' => (string) $file->id(),
  'label' => $file->getFilename() ?? '',
  'uuid' => $file->uuid(),
  'gate_method' => $gate['method'],
  'field' => $gate['field'],
]);
```

Verify integrity globally (all channels): `drush audit-chain:verify`.
