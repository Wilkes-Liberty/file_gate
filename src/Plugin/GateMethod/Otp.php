<?php

declare(strict_types=1);

namespace Drupal\file_gate\Plugin\GateMethod;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\GateMethodBase;
use Drupal\file_gate\SecretRegistryInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grants delivery after the requester proves control of an email address.
 *
 * A one-time passcode is e-mailed to a self-identified address (a trusted back
 * end requests it at POST /api/file-gate/otp) and bound to (file, email). The
 * visitor then redeems the download with that email and code; grants() verifies
 * the code against the stored hash, within its window, under an attempt cap,
 * and consumes it (single use). A step up from a bare token — proof of email
 * control — without standing up an account.
 *
 * A live-decision method: mint() returns NULL (there is no pre-issued signed
 * grant); the redemption carries "email" and "otp" query parameters instead.
 * Codes are stored as an HMAC-SHA256 keyed by the mint credential's secret
 * material (named secret or legacy download_secret; dual-key rotation
 * materials are accepted at redeem). Brute force is bounded by the TTL, the
 * per-code attempt cap (lockout), and the send endpoint's rate limiting.
 *
 * SECURITY: the passcode is delivered by e-mail, which is not a confidential
 * channel — it proves *control* of the address, not that the message is secret.
 * Anyone able to read the recipient's mail (or intercept it without transport
 * encryption) can use the code within its window. Use this to gate lead-gen /
 * self-service documents, not to protect content that a real secret should
 * protect; short TTLs keep the exposure small.
 *
 * Per-field method settings:
 * - ttl: code lifetime in seconds (default 600);
 * - max_attempts: wrong-code tries before the code is locked out (default 5);
 * - code_length: number of digits in the code (default 6).
 */
#[GateMethod(
  id: 'otp',
  label: new TranslatableMarkup('One-time passcode (email)'),
  description: new TranslatableMarkup('E-mail a one-time passcode to a self-identified address and deliver the file once the correct code is entered within its window. Proof of email control without an account; single-use, TTL-limited, with an attempt lockout.'),
)]
final class Otp extends GateMethodBase {

  /**
   * The OTP store collection name.
   */
  public const STORE_COLLECTION = 'file_gate_otp';

  /**
   * The default code lifetime, in seconds.
   */
  public const DEFAULT_TTL = 600;

  /**
   * The default wrong-code attempt cap.
   */
  public const DEFAULT_MAX_ATTEMPTS = 5;

  /**
   * The default code length (digits).
   */
  public const DEFAULT_CODE_LENGTH = 6;

  /**
   * The expirable key/value factory (backs the OTP store).
   */
  protected KeyValueExpirableFactoryInterface $keyValueExpirableFactory;

  /**
   * The config factory.
   */
  /**
   * The time service.
   */
  protected TimeInterface $time;

  /**
   * Secret registry (HMAC materials for named + previous keys).
   */
  protected SecretRegistryInterface $secrets;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    $instance = new static($configuration, $plugin_id, $plugin_definition);
    $instance->keyValueExpirableFactory = $container->get('keyvalue.expirable');
    $instance->time = $container->get('datetime.time');
    $instance->secrets = $container->get('file_gate.secret_registry');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    $email = self::normalizeEmail((string) $request->query->get('email', ''));
    $code = trim((string) $request->query->get('otp', ''));
    if ($email === '' || $code === '') {
      return FALSE;
    }

    $store = $this->store();
    $key = self::storeKey($file->uuid(), $email);
    $record = $store->get($key);
    if (!is_array($record)) {
      // No outstanding code for this file + email (never sent, expired, or
      // already spent). Fail closed.
      return FALSE;
    }

    $now = $this->time->getRequestTime();
    $exp = (int) ($record['exp'] ?? 0);
    $max = (int) ($record['max'] ?? self::DEFAULT_MAX_ATTEMPTS);
    $attempts = (int) ($record['attempts'] ?? 0);
    if ($exp <= $now || $attempts >= $max) {
      // Expired or locked out — discard and deny.
      $store->delete($key);
      return FALSE;
    }

    // Prefer the secret id stored at issue; fall back to legacy for rows minted
    // before GH #39. Try current + previous materials (rotation grace).
    $secret_id = NULL;
    if (array_key_exists('k', $record)) {
      $raw_k = $record['k'];
      $secret_id = (is_string($raw_k) && $raw_k !== '') ? $raw_k : NULL;
    }
    $materials = $this->secrets->validationMaterials($secret_id);
    // Pre-#39 rows had no k= and used only download_secret.
    if ($materials === [] && !array_key_exists('k', $record)) {
      $materials = $this->secrets->validationMaterials(NULL);
    }
    $stored = (string) ($record['hash'] ?? '');
    foreach ($materials as $secret) {
      if ($secret !== '' && hash_equals($stored, self::codeHash($code, $secret))) {
        // Correct: consume the code (single use).
        $store->delete($key);
        return TRUE;
      }
    }

    // Wrong code: count the attempt against the cap, preserving the window.
    $record['attempts'] = $attempts + 1;
    $store->setWithExpire($key, $record, max(1, $exp - $now));
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): ?array {
    // Nothing to pre-issue; the redemption carries the email + code.
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    return [
      'ttl' => [
        '#type' => 'number',
        '#title' => $this->t('Code lifetime (TTL)'),
        '#field_suffix' => $this->t('seconds'),
        '#min' => 30,
        '#default_value' => (int) ($settings['ttl'] ?? self::DEFAULT_TTL),
        '#description' => $this->t('How long a passcode stays valid. Default 600 (10 minutes).'),
      ],
      'max_attempts' => [
        '#type' => 'number',
        '#title' => $this->t('Attempt limit'),
        '#min' => 1,
        '#default_value' => (int) ($settings['max_attempts'] ?? self::DEFAULT_MAX_ATTEMPTS),
        '#description' => $this->t('Wrong-code tries before the code is locked out. Default 5.'),
      ],
      'code_length' => [
        '#type' => 'number',
        '#title' => $this->t('Code length'),
        '#field_suffix' => $this->t('digits'),
        '#min' => 4,
        '#max' => 10,
        '#default_value' => (int) ($settings['code_length'] ?? self::DEFAULT_CODE_LENGTH),
        '#description' => $this->t('Number of digits in the passcode. Default 6.'),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    return [
      'ttl' => max(30, (int) ($values['ttl'] ?? self::DEFAULT_TTL)),
      'max_attempts' => max(1, (int) ($values['max_attempts'] ?? self::DEFAULT_MAX_ATTEMPTS)),
      'code_length' => min(10, max(4, (int) ($values['code_length'] ?? self::DEFAULT_CODE_LENGTH))),
    ];
  }

  /**
   * The store key binding a code to a file and email.
   *
   * @param string $file_uuid
   *   The file UUID.
   * @param string $email
   *   The normalized email address.
   *
   * @return string
   *   The opaque store key.
   */
  public static function storeKey(string $file_uuid, string $email): string {
    return hash('sha256', $file_uuid . '|' . $email);
  }

  /**
   * Normalizes an email address for consistent keying.
   *
   * @param string $email
   *   The raw email.
   *
   * @return string
   *   The trimmed, lower-cased email (empty string if blank).
   */
  public static function normalizeEmail(string $email): string {
    return mb_strtolower(trim($email));
  }

  /**
   * Builds the keyed hash used for OTP storage and comparison.
   *
   * @param string $code
   *   The OTP code.
   * @param string $secret
   *   The File Gate shared secret.
   *
   * @return string
   *   The HMAC-SHA256 digest.
   */
  public static function codeHash(string $code, string $secret): string {
    return hash_hmac('sha256', $code, $secret);
  }

  /**
   * The OTP store.
   *
   * @return \Drupal\Core\KeyValueStore\KeyValueStoreExpirableInterface
   *   The expirable key/value store holding outstanding codes.
   */
  private function store(): KeyValueStoreExpirableInterface {
    return $this->keyValueExpirableFactory->get(self::STORE_COLLECTION);
  }

}
