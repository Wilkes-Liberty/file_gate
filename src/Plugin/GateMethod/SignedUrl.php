<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\GateMethod;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
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
use Drupal\file_gate\Service\GrantInventory;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grants access when the request carries a valid, unexpired signed grant.
 *
 * This is the fully decoupled method. A trusted back end mints a short-lived,
 * HMAC-signed URL (after running its own gate — a lead form, a login, …) and
 * the visitor's browser redeems it. Drupal never renders the gate; it only
 * verifies the signature. The signature binds the file's exact normalized URI
 * plus every claim, so a grant minted for one file cannot be replayed to fetch
 * another and its constraints cannot be altered.
 *
 * Per-field method settings (stored in the field's File Gate third-party
 * settings under "method_settings"):
 * - ttl: signed-URL lifetime in seconds (defaults to the global TTL);
 * - available_until: an absolute Unix timestamp that caps every grant's expiry
 *   (the "the download is available until <date>" window);
 * - max_uses: maximum number of times a single minted URL may be redeemed
 *   (1 = a one-time link). Enforced with an expirable redemption counter.
 *
 * Extended by the referrer_lock method, which reuses this mint/validate/usage
 * logic unchanged and layers an origin allowlist check on top of grants().
 */
#[GateMethod(
  id: 'signed_url',
  label: new TranslatableMarkup('Signed URL'),
  description: new TranslatableMarkup('A trusted back end mints a short-lived, HMAC-signed URL after its own gate (lead form, login, …); the browser redeems it. Supports per-field TTL, an absolute availability window, and usage limits (one-time links). Fully front-end-agnostic.'),
)]
class SignedUrl extends GateMethodBase {

  use GrantLockTrait;

  /**
   * The redemption-counter collection name (keyed by grant token).
   */
  private const REDEMPTION_COLLECTION = 'file_gate_redemptions';

  /**
   * Core claims reserved by signed-url grants.
   */
  private const CORE_CLAIM_KEYS = [
    GrantSignerInterface::CLAIM_EXPIRES,
    GrantSignerInterface::CLAIM_NOT_BEFORE,
    'jti',
    'max',
  ];

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
   * The expirable key/value factory (backs usage-limit counters).
   */
  protected KeyValueExpirableFactoryInterface $keyValueExpirableFactory;

  /**
   * The lock backend (serializes usage-counter increments).
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
   * Gate resolver (field key for the file at redemption).
   */
  protected FileGateResolver $resolver;

  /**
   * Jti inventory index (GH #44).
   */
  protected GrantInventory $grantInventory;

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
    $instance->grantInventory = $container->get('file_gate.grant_inventory');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    if (!$this->signatureValid($file, $request)) {
      return FALSE;
    }
    $claims = $this->claimsFromRequest($request);
    // Enforce a usage limit when the grant carries one (burn only on delivery).
    if (isset($claims['max'])) {
      return $this->consumeUse(
        (string) ($claims['jti'] ?? ''),
        (int) $claims['max'],
        (int) $claims[GrantSignerInterface::CLAIM_EXPIRES],
      );
    }
    return TRUE;
  }

  /**
   * Whether the request carries a cryptographically valid, unexpired grant.
   *
   * Does not consume usage limits. Used by assurance session-bridge establish
   * so a step-up proof never burns a one-time link before the file streams.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file being requested.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request (query must carry the mint claims + sig).
   *
   * @return bool
   *   TRUE when the HMAC and field scope check pass.
   */
  public function signatureValid(FileInterface $file, Request $request): bool {
    $sig = (string) $request->query->get('sig', '');
    if ($sig === '') {
      return FALSE;
    }
    $claims = $this->claimsFromRequest($request);
    if (!isset($claims[GrantSignerInterface::CLAIM_EXPIRES])) {
      return FALSE;
    }
    $secret_id = $this->secretIdFromRequest($request);
    if (!$this->signer->validate($this->resourceId($file), $claims, $sig, $secret_id)) {
      return FALSE;
    }
    // Enforce field scope at redemption so narrowing a secret revokes
    // outstanding grants (not only future mints).
    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL || !$this->secrets->allowsField($secret_id, $gate['field'])) {
      return FALSE;
    }
    // Soft check: usage already exhausted ⇒ treat as invalid for bridge too.
    if (isset($claims['max'])) {
      $token = (string) ($claims['jti'] ?? '');
      $max = (int) $claims['max'];
      if ($token === '' || $max <= 0) {
        return FALSE;
      }
      $store = $this->keyValueExpirableFactory->get(self::REDEMPTION_COLLECTION);
      if ((int) $store->get($token, 0) >= $max) {
        return FALSE;
      }
    }
    return TRUE;
  }

  /**
   * Reconstructs the signed claim bag from the request query.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return array<string, mixed>
   *   Claim key => query value for every key this method signs.
   */
  protected function claimsFromRequest(Request $request): array {
    // Reconstruct exactly the claim set a mint could have produced. Any claim
    // an attacker adds or alters changes the canonical payload and fails the
    // HMAC. k= selects the key only; it is not part of the signed payload.
    $claims = [];
    foreach ($this->signedClaimKeys() as $key) {
      if ($request->query->has($key)) {
        $claims[$key] = $request->query->get($key);
      }
    }
    return $claims;
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): ?array {
    $settings = $this->configuration;

    $ttl = (int) ($settings['ttl'] ?? 0);
    if ($ttl <= 0) {
      $ttl = $this->signer->defaultTtl();
    }
    $now = $this->time->getRequestTime();
    $exp = $now + $ttl;

    // An absolute availability window caps the expiry ("available until X").
    $available_until = (int) ($settings['available_until'] ?? 0);
    if ($available_until > 0) {
      $exp = min($exp, $available_until);
    }

    // A window that has already closed leaves no live grant to issue. Refuse
    // rather than hand back an already-expired link.
    if ($exp <= $now) {
      throw new GrantWindowClosedException('The file is no longer available for download.');
    }

    $claims = [GrantSignerInterface::CLAIM_EXPIRES => $exp];

    // Let subclasses bind additional claims (e.g. an assurance level). Keys
    // they add here MUST also appear in signedClaimKeys() so grants()
    // reconstructs the exact signed payload.
    foreach ($this->extraMintClaims($file) as $key => $value) {
      if (!is_string($key) || $key === '' || isset($claims[$key]) || in_array($key, self::CORE_CLAIM_KEYS, TRUE) || !is_scalar($value)) {
        return NULL;
      }
      $claims[$key] = $value;
    }

    // A usage cap needs a unique, unguessable token so redemptions of THIS
    // grant can be counted independently of any other.
    $max_uses = (int) ($settings['max_uses'] ?? 0);
    if ($max_uses > 0) {
      $claims['jti'] = bin2hex(random_bytes(12));
      $claims['max'] = $max_uses;
    }

    $secret_id = $this->activeSecretId();
    $sig = $this->signer->sign($this->resourceId($file), $claims, $secret_id);

    // Index usage-limited grants for inventory / bulk-revoke (GH #44).
    if ($max_uses > 0 && !empty($claims['jti'])) {
      $gate = $this->resolver->getGateForFile($file);
      $field = is_array($gate) ? (string) ($gate['field'] ?? '') : '';
      $this->grantInventory->record(
        (string) $claims['jti'],
        $file->uuid(),
        $field,
        (int) $claims[GrantSignerInterface::CLAIM_EXPIRES],
        $secret_id,
        $max_uses,
        isset($claims['sh']) ? (string) $claims['sh'] : '',
      );
    }

    // The claims travel in the URL (bound by the signature); the controller
    // appends them, plus "sig", to the download link. k= names the secret for
    // redemption (JWT kid); absent k means the legacy site secret.
    $params = $claims + ['sig' => $sig];
    if ($secret_id !== NULL && $secret_id !== '') {
      $params['k'] = $secret_id;
    }
    return $params;
  }

  /**
   * Secret id authenticated for this mint request, or NULL for legacy.
   */
  protected function activeSecretId(): ?string {
    return $this->activeSecret->isAuthenticated() ? $this->activeSecret->get() : NULL;
  }

  /**
   * Secret id from the download query k= param (NULL if absent/empty).
   */
  protected function secretIdFromRequest(Request $request): ?string {
    if (!$request->query->has('k')) {
      return NULL;
    }
    $k = (string) $request->query->get('k');
    return $k !== '' ? $k : NULL;
  }

  /**
   * The query parameter keys that reconstruct the signed claim set.
   *
   * Subclasses that bind extra claims at mint MUST add their keys here, so
   * grants() reconstructs exactly the payload that was signed (any missing or
   * extra key changes the canonical payload and the HMAC fails closed).
   *
   * @return string[]
   *   The claim keys to read from the request query.
   */
  protected function signedClaimKeys(): array {
    return [
      GrantSignerInterface::CLAIM_EXPIRES,
      GrantSignerInterface::CLAIM_NOT_BEFORE,
      'jti',
      'max',
    ];
  }

  /**
   * Additional scalar claims to bind into the grant at mint time.
   *
   * Subclasses override this to bind extra signed claims (e.g. an assurance
   * level). Every key returned here MUST also be listed by signedClaimKeys().
   *
   * @param \Drupal\file\FileInterface $file
   *   The file being minted.
   *
   * @return array
   *   Extra scalar claims keyed by claim name.
   */
  protected function extraMintClaims(FileInterface $file): array {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    return [
      'ttl' => [
        '#type' => 'number',
        '#title' => $this->t('Signed-URL lifetime (TTL)'),
        '#field_suffix' => $this->t('seconds'),
        '#min' => 0,
        '#default_value' => (int) ($settings['ttl'] ?? 0),
        '#description' => $this->t('How long a minted URL stays valid. 0 uses the global default.'),
      ],
      'available_until' => [
        '#type' => 'number',
        '#title' => $this->t('Available until'),
        '#field_suffix' => $this->t('Unix timestamp'),
        '#min' => 0,
        '#default_value' => (int) ($settings['available_until'] ?? 0),
        '#description' => $this->t('An absolute cap on every grant expiry. 0 = no cap.'),
      ],
      'max_uses' => [
        '#type' => 'number',
        '#title' => $this->t('Maximum redemptions per URL'),
        '#min' => 0,
        '#default_value' => (int) ($settings['max_uses'] ?? 0),
        '#description' => $this->t('0 = unlimited; 1 = a one-time link.'),
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
    return $settings;
  }

  /**
   * Consumes one use of a usage-limited grant.
   *
   * The read-check-increment runs under a lock keyed on the grant token, so a
   * concurrent burst cannot redeem a one-time link more than its cap allows
   * (every request would otherwise read the same pre-increment counter). A
   * request that cannot acquire the lock is denied (fail closed).
   *
   * @param string $token
   *   The grant's unique token (jti claim).
   * @param int $max
   *   The maximum number of redemptions allowed.
   * @param int $exp
   *   The grant expiry (the counter is discarded no later than this).
   *
   * @return bool
   *   TRUE if a use remained and was consumed; FALSE if the cap is reached.
   */
  private function consumeUse(string $token, int $max, int $exp): bool {
    if ($token === '' || $max <= 0) {
      return FALSE;
    }
    return (bool) $this->runLocked('file_gate_redemption:' . $token, function () use ($token, $max, $exp): bool {
      $store = $this->keyValueExpirableFactory->get(self::REDEMPTION_COLLECTION);
      $count = (int) $store->get($token, 0);
      if ($count >= $max) {
        return FALSE;
      }
      // The counter only needs to outlive the grant itself.
      $store->setWithExpire($token, $count + 1, max(1, $exp - $this->time->getRequestTime()));
      return TRUE;
    });
  }

  /**
   * The signed resource id for a file: its UUID plus its normalized stream URI.
   *
   * The UUID binds the grant to this exact file entity, so two managed files
   * that happen to reference the same private:// URI do not share a signature
   * (a grant minted for one cannot be redeemed for the other). Normalizing the
   * URI (e.g. collapsing "private://./x" to "private://x") guarantees the
   * string signed at mint time matches the string validated at redemption,
   * where core reconstructs the URI from the request path.
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

}
