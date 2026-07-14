<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\GateMethod;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\GateMethodBase;
use Drupal\file_gate\GrantSignerInterface;
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

  /**
   * The redemption-counter collection name (keyed by grant token).
   */
  private const REDEMPTION_COLLECTION = 'file_gate_redemptions';

  /**
   * The grant signer.
   */
  private GrantSignerInterface $signer;

  /**
   * The stream wrapper manager (to normalize the file URI before signing).
   */
  private StreamWrapperManagerInterface $streamWrapperManager;

  /**
   * The time service.
   */
  private TimeInterface $time;

  /**
   * The expirable key/value factory (backs usage-limit counters).
   */
  private KeyValueExpirableFactoryInterface $keyValueExpirableFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    $instance = new static($configuration, $plugin_id, $plugin_definition);
    $instance->signer = $container->get('file_gate.grant_signer');
    $instance->streamWrapperManager = $container->get('stream_wrapper_manager');
    $instance->time = $container->get('datetime.time');
    $instance->keyValueExpirableFactory = $container->get('keyvalue.expirable');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    $sig = (string) $request->query->get('sig', '');
    if ($sig === '') {
      return FALSE;
    }
    // Reconstruct exactly the claim set a mint could have produced. Any claim
    // an attacker adds or alters changes the canonical payload and fails the
    // HMAC.
    $claims = [];
    foreach ($this->signedClaimKeys() as $key) {
      if ($request->query->has($key)) {
        $claims[$key] = $request->query->get($key);
      }
    }
    if (!isset($claims[GrantSignerInterface::CLAIM_EXPIRES])) {
      return FALSE;
    }
    if (!$this->signer->validate($this->resourceId($file), $claims, $sig)) {
      return FALSE;
    }
    // Enforce a usage limit when the grant carries one.
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

    $claims = [GrantSignerInterface::CLAIM_EXPIRES => $exp];

    // Let subclasses bind additional claims (e.g. an assurance level). Keys
    // they add here MUST also appear in signedClaimKeys() so grants()
    // reconstructs the exact signed payload.
    foreach ($this->extraMintClaims($file) as $key => $value) {
      $claims[$key] = $value;
    }

    // A usage cap needs a unique, unguessable token so redemptions of THIS
    // grant can be counted independently of any other.
    $max_uses = (int) ($settings['max_uses'] ?? 0);
    if ($max_uses > 0) {
      $claims['jti'] = bin2hex(random_bytes(12));
      $claims['max'] = $max_uses;
    }

    $sig = $this->signer->sign($this->resourceId($file), $claims);

    // The claims travel in the URL (bound by the signature); the controller
    // appends them, plus "sig", to the download link.
    return $claims + ['sig' => $sig];
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
   * Atomically-ish consumes one use of a usage-limited grant.
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
    $store = $this->keyValueExpirableFactory->get(self::REDEMPTION_COLLECTION);
    $count = (int) $store->get($token, 0);
    if ($count >= $max) {
      return FALSE;
    }
    // The counter only needs to outlive the grant itself.
    $store->setWithExpire($token, $count + 1, max(1, $exp - $this->time->getRequestTime()));
    return TRUE;
  }

  /**
   * The signed resource id for a file: its normalized stream URI.
   *
   * Normalizing (e.g. collapsing "private://./x" to "private://x") guarantees
   * the string signed at mint time matches the string validated at redemption
   * time, where core reconstructs the URI from the request path.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return string
   *   The normalized "private://…" URI.
   */
  private function resourceId(FileInterface $file): string {
    return $this->streamWrapperManager->normalizeUri((string) $file->getFileUri());
  }

}
