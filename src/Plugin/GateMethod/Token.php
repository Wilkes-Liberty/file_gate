<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\GateMethod;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\Exception\GrantWindowClosedException;
use Drupal\file_gate\ActiveSecret;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\GateMethodBase;
use Drupal\file_gate\GrantLockTrait;
use Drupal\file_gate\GrantSignerInterface;
use Drupal\file_gate\SecretRegistryInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grants access when the request carries a valid token.
 *
 * Complements signed_url with the one thing a bare signature cannot do: revoke
 * a single live link without rotating the site secret (which would break every
 * other link). It supports two token shapes, distinguished at redemption by
 * whether a signature is present:
 *
 * - Minted, revocable (the primary shape). mint() self-issues a random
 *   per-grant token, records its SHA-256 hash in an expirable store, and binds
 *   that hash into the signature alongside the expiry. The browser redeems the
 *   signed URL with the plaintext token. Revoke by deleting the stored hash —
 *   the request then fails because no live row backs the token. Because mint()
 *   receives no caller input, the token is per-grant / independently revocable,
 *   not tied to a named recipient; a trusted back end records token → recipient
 *   on its side.
 *
 * - Pre-shared campaign (optional). A field may configure an allowlist of token
 *   hashes ("tokens"); a static link carrying only "?token=<plaintext>" (no
 *   signature) is granted when the token's hash is in that allowlist. Revoke by
 *   removing the hash from the field's configuration. These links are static —
 *   no per-request expiry or signature.
 *
 * The two paths do not cross: a minted token that is not in the allowlist,
 * presented without a signature, is denied; a pre-shared token presented with a
 * forged signature fails the signature check.
 *
 * Per-field method settings (under the field's File Gate "method_settings"):
 * - ttl: minted-link lifetime in seconds (defaults to the global TTL);
 * - available_until: an absolute Unix timestamp capping a minted link's expiry;
 * - max_uses: redemptions per minted token (0 = unlimited, 1 = one-time);
 * - tokens: an array of SHA-256 hashes of pre-shared tokens (never plaintext).
 *
 * Tokens are stored and configured only as hashes, so a store or config dump
 * yields no usable bearer credentials. The revocation store is a fast key/value
 * store, not itself atomic, so the redemption read-modify-write and the revoke
 * delete are serialized with a lock keyed on the token hash (see
 * GrantLockTrait): a redemption cannot resurrect a just-revoked row, and a
 * one-time token cannot be double-spent by a concurrent burst. A request that
 * cannot acquire the lock is denied (fail closed).
 */
#[GateMethod(
  id: 'token',
  label: new TranslatableMarkup('Token'),
  description: new TranslatableMarkup('Deliver via a revocable token. A trusted back end mints a per-grant token (its hash bound in the signature and stored so it can be revoked without rotating the secret); a field may also accept a pre-shared allowlist of token hashes as static campaign links. Supports TTL, an availability window, and usage limits for minted links.'),
)]
final class Token extends GateMethodBase {

  use GrantLockTrait;

  /**
   * The token store collection name (keyed by the SHA-256 hash of the token).
   */
  private const TOKEN_COLLECTION = 'file_gate_tokens';

  /**
   * The signed-payload claim key binding a grant to its token hash.
   */
  private const CLAIM_TOKEN_HASH = 'th';

  /**
   * The grant signer.
   */
  protected GrantSignerInterface $signer;

  /**
   * The stream wrapper manager (to normalize the file URI before signing).
   */
  protected StreamWrapperManagerInterface $streamWrapperManager;

  /**
   * The time service.
   */
  protected TimeInterface $time;

  /**
   * The expirable key/value factory (backs the token store).
   */
  protected KeyValueExpirableFactoryInterface $keyValueExpirableFactory;

  /**
   * The lock backend (serializes redemption against revocation).
   */
  protected LockBackendInterface $lock;

  /**
   * Active secret for this mint request.
   */
  protected ActiveSecret $activeSecret;

  /**
   * Secret registry (field scope at redemption).
   */
  protected SecretRegistryInterface $secrets;

  /**
   * Gate resolver (field key at redemption).
   */
  protected FileGateResolver $resolver;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    $instance = new static($configuration, $plugin_id, $plugin_definition);
    $instance->signer = $container->get('file_gate.grant_signer');
    $instance->streamWrapperManager = $container->get('stream_wrapper_manager');
    $instance->time = $container->get('datetime.time');
    $instance->keyValueExpirableFactory = $container->get('keyvalue.expirable');
    $instance->lock = $container->get('lock');
    $instance->activeSecret = $container->get('file_gate.active_secret');
    $instance->secrets = $container->get('file_gate.secret_registry');
    $instance->resolver = $container->get('file_gate.resolver');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    $token = (string) $request->query->get('token', '');
    if ($token === '') {
      return FALSE;
    }
    $token_hash = hash('sha256', $token);

    // Minted path: a signature is present, so this is a minted, revocable
    // token. Commit to it — never fall through to the pre-shared allowlist.
    $sig = (string) $request->query->get('sig', '');
    if ($sig !== '') {
      $exp = $request->query->get(GrantSignerInterface::CLAIM_EXPIRES);
      if ($exp === NULL) {
        return FALSE;
      }
      // Reconstruct exactly the claims mint() signed. The token hash is derived
      // from the presented token, never read from the URL, so a client cannot
      // present a hash that differs from the token it actually holds.
      $claims = [
        GrantSignerInterface::CLAIM_EXPIRES => (int) $exp,
        self::CLAIM_TOKEN_HASH => $token_hash,
      ];
      $secret_id = NULL;
      if ($request->query->has('k')) {
        $k = (string) $request->query->get('k');
        $secret_id = $k !== '' ? $k : NULL;
      }
      if (!$this->signer->validate($this->resourceId($file), $claims, $sig, $secret_id)) {
        return FALSE;
      }
      $gate = $this->resolver->getGateForFile($file);
      if ($gate === NULL || !$this->secrets->allowsField($secret_id, $gate['field'])) {
        return FALSE;
      }
      return $this->consumeMintedToken($token_hash, (int) $exp);
    }

    // Pre-shared path: no signature. Grant only if the token's hash is in the
    // field's configured allowlist (a shared campaign token).
    return $this->presharedGrants($token_hash);
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): array {
    $exp = $this->expiry();

    // A capped availability window that has already closed leaves no live grant
    // to issue. Refuse rather than hand back an already-expired link.
    if ($exp <= $this->time->getRequestTime()) {
      throw new GrantWindowClosedException('The file is no longer available for download.');
    }

    // A fresh, unguessable bearer token for this single grant. It is returned
    // to the caller in the URL, but only its hash is ever stored or signed.
    $token = bin2hex(random_bytes(16));
    $token_hash = hash('sha256', $token);

    // Record the token hash immediately. This stored row is the revocation
    // gate: grants() denies any minted token without a live row, so deleting
    // the row revokes the link without touching the site secret. Stored
    // unconditionally — including unlimited-use tokens — so every token is
    // revocable.
    $max_uses = (int) ($this->configuration['max_uses'] ?? 0);
    $this->tokenStore()->setWithExpire(
      $token_hash,
      ['uses' => 0, 'max' => $max_uses],
      max(1, $exp - $this->time->getRequestTime()),
    );

    // Bind the token hash into the signature alongside the expiry, so a token
    // minted for this file and expiry cannot be replayed against another file,
    // expiry, or a different recipient's still-live token.
    $claims = [
      GrantSignerInterface::CLAIM_EXPIRES => $exp,
      self::CLAIM_TOKEN_HASH => $token_hash,
    ];
    $secret_id = $this->activeSecret->isAuthenticated() ? $this->activeSecret->get() : NULL;
    $sig = $this->signer->sign($this->resourceId($file), $claims, $secret_id);

    // Only the plaintext token travels in the URL; grants() recomputes its
    // hash, so the stored key is never exposed.
    $params = [
      GrantSignerInterface::CLAIM_EXPIRES => $exp,
      'token' => $token,
      'sig' => $sig,
    ];
    if ($secret_id !== NULL) {
      $params['k'] = $secret_id;
    }
    return $params;
  }

  /**
   * Validates and consumes one use of a minted token.
   *
   * @param string $token_hash
   *   The SHA-256 hash of the presented token (the store key).
   * @param int $exp
   *   The grant expiry (the counter is discarded no later than this).
   *
   * @return bool
   *   TRUE when a live, unspent token was found and one use consumed; FALSE
   *   when the token was revoked, never issued, or has reached its usage cap.
   */
  private function consumeMintedToken(string $token_hash, int $exp): bool {
    // Serialize the read-modify-write against a concurrent revocation (which
    // takes the same lock before deleting) and against other redemptions of the
    // same token. Without this, a redemption could resurrect a revoked row or a
    // one-time token could be double-spent in a burst. Contention fails closed.
    return (bool) $this->runLocked($this->tokenLockName($token_hash), function () use ($token_hash, $exp): bool {
      $store = $this->tokenStore();
      $record = $store->get($token_hash);
      // No live row ⇒ the token was revoked or never issued. Fail closed.
      if (!is_array($record)) {
        return FALSE;
      }
      $max = (int) ($record['max'] ?? 0);
      $uses = (int) ($record['uses'] ?? 0);
      if ($max > 0 && $uses >= $max) {
        return FALSE;
      }
      // Consume one use, preserving the record shape. The row only needs to
      // outlive the grant itself.
      $record['uses'] = $uses + 1;
      $store->setWithExpire($token_hash, $record, max(1, $exp - $this->time->getRequestTime()));
      return TRUE;
    });
  }

  /**
   * Whether a token hash is in the field's pre-shared allowlist.
   *
   * @param string $token_hash
   *   The SHA-256 hash of the presented token.
   *
   * @return bool
   *   TRUE when the hash matches a configured pre-shared token; FALSE otherwise
   *   (including when no allowlist is configured — pre-shared mode is off).
   */
  private function presharedGrants(string $token_hash): bool {
    $allowed = (array) ($this->configuration['tokens'] ?? []);
    if ($allowed === []) {
      return FALSE;
    }
    // Compare against every configured hash without short-circuiting, so timing
    // does not reveal which entry (if any) matched.
    $match = FALSE;
    foreach ($allowed as $allowed_hash) {
      if (hash_equals((string) $allowed_hash, $token_hash)) {
        $match = TRUE;
      }
    }
    return $match;
  }

  /**
   * Computes a minted link's expiry from the field's TTL / availability window.
   *
   * @return int
   *   The Unix expiry timestamp.
   */
  private function expiry(): int {
    $ttl = (int) ($this->configuration['ttl'] ?? 0);
    if ($ttl <= 0) {
      $ttl = $this->signer->defaultTtl();
    }
    $exp = $this->time->getRequestTime() + $ttl;

    // An absolute availability window caps the expiry ("available until X").
    $available_until = (int) ($this->configuration['available_until'] ?? 0);
    if ($available_until > 0) {
      $exp = min($exp, $available_until);
    }
    return $exp;
  }

  /**
   * The token store.
   *
   * @return \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface
   *   The expirable key/value store holding minted token hashes.
   */
  private function tokenStore(): KeyValueStoreExpirableInterface {
    return $this->keyValueExpirableFactory->get(self::TOKEN_COLLECTION);
  }

  /**
   * The signed resource id for a file: its UUID plus its normalized stream URI.
   *
   * The UUID binds the grant to this exact file entity, so two managed files
   * that happen to reference the same private:// URI do not share a signature
   * (a grant minted for one cannot be redeemed for the other). Normalizing the
   * URI guarantees the string signed at mint time matches the string validated
   * at redemption, where core reconstructs the URI from the request.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return string
   *   The resource id: "<uuid>|private://…".
   */
  private function resourceId(FileInterface $file): string {
    return $file->uuid() . '|' . $this->streamWrapperManager->normalizeUri((string) $file->getFileUri());
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    return [
      'ttl' => [
        '#type' => 'number',
        '#title' => $this->t('Minted-token lifetime (TTL)'),
        '#field_suffix' => $this->t('seconds'),
        '#min' => 0,
        '#default_value' => (int) ($settings['ttl'] ?? 0),
        '#description' => $this->t('How long a minted token stays valid. 0 uses the global default.'),
      ],
      'available_until' => [
        '#type' => 'number',
        '#title' => $this->t('Available until'),
        '#field_suffix' => $this->t('Unix timestamp'),
        '#min' => 0,
        '#default_value' => (int) ($settings['available_until'] ?? 0),
        '#description' => $this->t('An absolute cap on the minted token expiry. 0 = no cap.'),
      ],
      'max_uses' => [
        '#type' => 'number',
        '#title' => $this->t('Maximum redemptions per minted token'),
        '#min' => 0,
        '#default_value' => (int) ($settings['max_uses'] ?? 0),
        '#description' => $this->t('0 = unlimited; 1 = a one-time link.'),
      ],
      'tokens' => [
        '#type' => 'textarea',
        '#title' => $this->t('Pre-shared token hashes'),
        '#default_value' => implode("\n", (array) ($settings['tokens'] ?? [])),
        '#description' => $this->t('Optional. One <strong>SHA-256 hash</strong> per line of a pre-shared campaign token. Store hashes only, never the plaintext token. Leave empty to disable pre-shared mode.'),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    $settings = [];
    foreach (['ttl', 'available_until', 'max_uses'] as $key) {
      $settings[$key] = (int) ($values[$key] ?? 0);
    }
    // One hash per line; drop blanks and surrounding whitespace.
    $tokens = array_filter(array_map('trim', preg_split('/\R/', (string) ($values['tokens'] ?? ''))));
    if ($tokens) {
      $settings['tokens'] = array_values($tokens);
    }
    return $settings;
  }

}
