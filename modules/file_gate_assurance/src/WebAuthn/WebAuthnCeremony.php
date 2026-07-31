<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\WebAuthn;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Site\Settings;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Cose\Algorithms;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Native WebAuthn registration and assertion ceremonies.
 *
 * Uses web-auth/webauthn-lib. Fail closed when the library or configuration
 * (rp_id / allowed origins) is missing. Challenges are single-use and stored
 * only long enough for one ceremony.
 *
 * Honest scope: File Gate is the RP for this resource. This does not make the
 * whole site AAL3 under NIST SP 800-63B; it proves possession of a registered
 * authenticator for a gated download.
 */
final class WebAuthnCeremony {

  /**
   * Challenge store collection.
   */
  private const CHALLENGE_COLLECTION = 'file_gate_webauthn_challenges';

  /**
   * Challenge TTL (seconds).
   */
  private const CHALLENGE_TTL = 300;

  /**
   * Constructs the ceremony service.
   */
  public function __construct(
    private readonly WebAuthnCredentialStorage $storage,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly TimeInterface $time,
    private readonly Settings $settings,
  ) {}

  /**
   * Whether the WebAuthn library is loadable.
   */
  public function isAvailable(): bool {
    return class_exists(CeremonyStepManagerFactory::class)
      && class_exists(WebauthnSerializerFactory::class);
  }

  /**
   * Builds registration options for an authenticated Drupal user.
   *
   * @param string $user_handle
   *   Stable handle (usually uid as string).
   * @param string $user_name
   *   Display name / login.
   * @param array $config
   *   Method settings (rp_id, rp_name, origins, timeout).
   *
   * @return array{options: array<string, mixed>, challenge_id: string}|null
   *   PublicKeyCredentialCreationOptions as array + challenge id, or NULL.
   */
  public function registrationOptions(string $user_handle, string $user_name, array $config): ?array {
    if (!$this->isAvailable() || !$this->configReady($config)) {
      return NULL;
    }
    $challenge = random_bytes(32);
    $challenge_id = bin2hex(random_bytes(16));
    $rp_id = (string) $config['rp_id'];
    $rp_name = (string) ($config['rp_name'] ?? 'File Gate');
    $timeout = (int) ($config['timeout'] ?? 60000);

    $exclude = [];
    foreach ($this->storage->loadByUserHandle($user_handle) as $row) {
      $exclude[] = PublicKeyCredentialDescriptor::create(
        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
        $this->b64decode((string) $row['credential_id']),
      );
    }

    $options = PublicKeyCredentialCreationOptions::create(
      PublicKeyCredentialRpEntity::create($rp_name, $rp_id),
      PublicKeyCredentialUserEntity::create($user_name, $user_handle, $user_name),
      $challenge,
      [
        PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
        PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
      ],
      AuthenticatorSelectionCriteria::create(
        NULL,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
      ),
      PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
      $exclude,
      $timeout,
    );

    $this->storeChallenge($challenge_id, [
      'type' => 'create',
      'challenge' => $this->b64($challenge),
      'user_handle' => $user_handle,
      'rp_id' => $rp_id,
    ]);

    $serializer = $this->serializer();
    /** @var array<string, mixed> $normalized */
    $normalized = $serializer->normalize($options);
    return [
      'options' => $normalized,
      'challenge_id' => $challenge_id,
    ];
  }

  /**
   * Completes registration and stores the credential.
   *
   * @param string $challenge_id
   *   Challenge id from registrationOptions().
   * @param string $credential_json
   *   Browser PublicKeyCredential JSON.
   * @param array $config
   *   Method / RP config.
   * @param int|null $uid
   *   Optional Drupal uid.
   * @param string $label
   *   Human label.
   *
   * @return bool
   *   TRUE on success.
   */
  public function completeRegistration(string $challenge_id, string $credential_json, array $config, ?int $uid, string $label = ''): bool {
    if (!$this->isAvailable() || !$this->configReady($config)) {
      return FALSE;
    }
    $stored = $this->takeChallenge($challenge_id);
    if ($stored === NULL || ($stored['type'] ?? '') !== 'create') {
      return FALSE;
    }
    try {
      $serializer = $this->serializer();
      $publicKeyCredential = $serializer->deserialize($credential_json, PublicKeyCredential::class, 'json');
      if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
        return FALSE;
      }
      $creationOptions = PublicKeyCredentialCreationOptions::create(
        PublicKeyCredentialRpEntity::create((string) ($config['rp_name'] ?? 'File Gate'), (string) $config['rp_id']),
        PublicKeyCredentialUserEntity::create('user', (string) $stored['user_handle'], 'user'),
        $this->b64decode((string) $stored['challenge']),
        [
          PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
          PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
        ],
      );
      $factory = new CeremonyStepManagerFactory();
      $factory->setAllowedOrigins($this->origins($config), FALSE);
      $validator = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
      $host = (string) ($config['rp_id'] ?? '');
      $source = $validator->check(
        $publicKeyCredential->response,
        $creationOptions,
        $host,
      );
      // Persist as CredentialRecord fields.
      $credential_id = $this->b64($source->publicKeyCredentialId);
      if ($this->storage->loadByCredentialId($credential_id) !== NULL) {
        return FALSE;
      }
      $this->storage->insert([
        'user_handle' => (string) $stored['user_handle'],
        'credential_id' => $credential_id,
        'public_key' => $this->b64($source->credentialPublicKey),
        'counter' => (int) $source->counter,
        'transports' => json_encode($source->transports ?? [], JSON_THROW_ON_ERROR),
        'label' => $label,
        'uid' => $uid,
      ]);
      return TRUE;
    }
    catch (\Throwable) {
      return FALSE;
    }
  }

  /**
   * Builds assertion options for a user handle (subject or uid).
   *
   * @return array{options: array<string, mixed>, challenge_id: string}|null
   *   Options for navigator.credentials.get(), or NULL.
   */
  public function assertionOptions(string $user_handle, array $config, string $grant_fingerprint): ?array {
    if (!$this->isAvailable() || !$this->configReady($config)) {
      return NULL;
    }
    $rows = $this->storage->loadByUserHandle($user_handle);
    if ($rows === []) {
      return NULL;
    }
    $challenge = random_bytes(32);
    $challenge_id = bin2hex(random_bytes(16));
    $allow = [];
    foreach ($rows as $row) {
      $transports = json_decode((string) $row['transports'], TRUE);
      if (!is_array($transports)) {
        $transports = [];
      }
      $allow[] = PublicKeyCredentialDescriptor::create(
        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
        $this->b64decode((string) $row['credential_id']),
        array_map('strval', $transports),
      );
    }
    $timeout = (int) ($config['timeout'] ?? 60000);
    $options = PublicKeyCredentialRequestOptions::create(
      $challenge,
      (string) $config['rp_id'],
      $allow,
      PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
      $timeout,
    );
    $this->storeChallenge($challenge_id, [
      'type' => 'assert',
      'challenge' => $this->b64($challenge),
      'user_handle' => $user_handle,
      'rp_id' => (string) $config['rp_id'],
      'grant' => $grant_fingerprint,
    ]);
    $serializer = $this->serializer();
    /** @var array<string, mixed> $normalized */
    $normalized = $serializer->normalize($options);
    return [
      'options' => $normalized,
      'challenge_id' => $challenge_id,
    ];
  }

  /**
   * Verifies an assertion for a prior challenge + grant fingerprint.
   *
   * @return bool
   *   TRUE when the authenticator proved possession.
   */
  public function completeAssertion(string $challenge_id, string $credential_json, array $config, string $grant_fingerprint): bool {
    if (!$this->isAvailable() || !$this->configReady($config)) {
      return FALSE;
    }
    $stored = $this->takeChallenge($challenge_id);
    if ($stored === NULL || ($stored['type'] ?? '') !== 'assert') {
      return FALSE;
    }
    if (!hash_equals((string) ($stored['grant'] ?? ''), $grant_fingerprint)) {
      return FALSE;
    }
    try {
      $serializer = $this->serializer();
      $publicKeyCredential = $serializer->deserialize($credential_json, PublicKeyCredential::class, 'json');
      if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
        return FALSE;
      }
      $credential_id = $this->b64($publicKeyCredential->rawId);
      $row = $this->storage->loadByCredentialId($credential_id);
      if ($row === NULL) {
        return FALSE;
      }
      if (!hash_equals((string) $row['user_handle'], (string) $stored['user_handle'])) {
        return FALSE;
      }
      $record = CredentialRecord::create(
        $this->b64decode((string) $row['credential_id']),
        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
        json_decode((string) $row['transports'], TRUE) ?: [],
        'none',
        EmptyTrustPath::create(),
        Uuid::fromString('00000000-0000-0000-0000-000000000000'),
        $this->b64decode((string) $row['public_key']),
        (string) $row['user_handle'],
        (int) $row['counter'],
      );
      $requestOptions = PublicKeyCredentialRequestOptions::create(
        $this->b64decode((string) $stored['challenge']),
        (string) $config['rp_id'],
        [$record->getPublicKeyCredentialDescriptor()],
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
      );
      $factory = new CeremonyStepManagerFactory();
      $factory->setAllowedOrigins($this->origins($config), FALSE);
      $validator = AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
      $updated = $validator->check(
        $record,
        $publicKeyCredential->response,
        $requestOptions,
        (string) $config['rp_id'],
        (string) $row['user_handle'],
      );
      $this->storage->updateCounter($credential_id, (int) $updated->counter);
      return TRUE;
    }
    catch (\Throwable) {
      return FALSE;
    }
  }

  /**
   * Whether RP config is sufficient.
   */
  public function configReady(array $config): bool {
    $rp_id = trim((string) ($config['rp_id'] ?? ''));
    $origins = $this->origins($config);
    return $rp_id !== '' && $origins !== [];
  }

  /**
   * Allowed origins from config or settings override.
   *
   * @return list<string>
   *   Absolute origins (https://host).
   */
  private function origins(array $config): array {
    $from_settings = $this->settings->get('file_gate.webauthn_origins');
    if (is_array($from_settings) && $from_settings !== []) {
      return array_values(array_filter(array_map('strval', $from_settings)));
    }
    $raw = $config['origins'] ?? [];
    if (is_string($raw)) {
      $raw = preg_split('/\s+/', trim($raw)) ?: [];
    }
    return array_values(array_filter(array_map('strval', (array) $raw)));
  }

  /**
   * Stores a single-use ceremony challenge.
   *
   * @param string $id
   *   Challenge id.
   * @param array<string, mixed> $data
   *   Challenge payload.
   */
  private function storeChallenge(string $id, array $data): void {
    $this->keyValueExpirableFactory->get(self::CHALLENGE_COLLECTION)
      ->setWithExpire($id, $data, self::CHALLENGE_TTL);
  }

  /**
   * Loads and deletes a challenge (single use).
   *
   * @param string $id
   *   Challenge id.
   *
   * @return array<string, mixed>|null
   *   Stored challenge, or NULL.
   */
  private function takeChallenge(string $id): ?array {
    $store = $this->keyValueExpirableFactory->get(self::CHALLENGE_COLLECTION);
    $data = $store->get($id);
    $store->delete($id);
    return is_array($data) ? $data : NULL;
  }

  /**
   * Builds the WebAuthn JSON serializer.
   */
  private function serializer(): SerializerInterface {
    $attestation = new AttestationStatementSupportManager([
      new NoneAttestationStatementSupport(),
    ]);
    return (new WebauthnSerializerFactory($attestation))->create();
  }

  /**
   * Base64url-encodes without padding.
   */
  private function b64(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
  }

  /**
   * Base64url-decodes.
   */
  private function b64decode(string $b64): string {
    $pad = 4 - (strlen($b64) % 4);
    if ($pad < 4) {
      $b64 .= str_repeat('=', $pad);
    }
    $raw = base64_decode(strtr($b64, '-_', '+/'), TRUE);
    return $raw === FALSE ? '' : $raw;
  }

}
