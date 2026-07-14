<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Default OIDC + DPoP implementation of the assurance verifier.
 *
 * Provider-agnostic: configured only with an issuer URL and an expected
 * audience, it discovers the IdP's JWKS via OIDC discovery, pins the signing
 * algorithm to the published keys (never the token header — this defeats
 * alg-confusion, which matters here because File Gate owns an HMAC secret too),
 * and validates the standard registered claims. When DPoP is enabled it also
 * verifies an RFC 9449 proof and binds it to the access token via the token's
 * `cnf.jkt` confirmation thumbprint.
 *
 * @see \Drupal\file_gate_assurance\AssuranceVerifierInterface
 */
class AssuranceVerifier implements AssuranceVerifierInterface {

  /**
   * The signature algorithms accepted for DPoP proofs (asymmetric only).
   */
  private const DPOP_ALGS = ['ES256', 'ES256K', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA'];

  /**
   * The asymmetric JWT algorithms accepted for OIDC token verification.
   */
  private const OIDC_TOKEN_ALGS = ['ES256', 'ES256K', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA'];

  /**
   * The DPoP proof freshness window, in seconds.
   */
  private const DPOP_WINDOW = 60;

  /**
   * The replay store for spent DPoP proof identifiers.
   */
  private const DPOP_COLLECTION = 'file_gate_assurance_dpop_jti';

  /**
   * Constructs the verifier.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The HTTP client (OIDC discovery + JWKS fetch).
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The cache backend (caches each issuer's JWKS).
   * @param \Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface $keyValueExpirableFactory
   *   The expirable key/value factory (DPoP replay protection).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   */
  public function __construct(
    private readonly ClientInterface $httpClient,
    private readonly CacheBackendInterface $cache,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly TimeInterface $time,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function verify(string $token, array $config, Request $request): ?array {
    $issuer = (string) ($config['issuer'] ?? '');
    $audience = (string) ($config['audience'] ?? '');
    // Fail closed on misconfiguration — an unconfigured verifier verifies
    // nothing.
    if ($token === '' || $issuer === '' || $audience === '') {
      return NULL;
    }

    $jwks = $this->loadJwks($issuer);
    if ($jwks === NULL) {
      return NULL;
    }

    $default_alg = $this->jwtHeaderAlg($token);
    if ($default_alg === NULL) {
      return NULL;
    }

    try {
      // parseKeySet pins each key's algorithm; JWT::decode then rejects "none",
      // any HMAC alg, and any token whose header alg disagrees with its key.
      $keys = JWK::parseKeySet($jwks, $default_alg);
      $leeway = JWT::$leeway;
      try {
        JWT::$leeway = max(0, (int) ($config['leeway'] ?? 60));
        $claims = JWT::decode($token, $keys);
      }
      finally {
        JWT::$leeway = $leeway;
      }
    }
    catch (\Throwable $e) {
      $this->logger->warning('Assurance: token rejected: @msg', ['@msg' => $e->getMessage()]);
      return NULL;
    }

    // Pin issuer and audience: never trust a token minted for another party.
    if (($claims->iss ?? NULL) !== $issuer) {
      return NULL;
    }
    if (!in_array($audience, (array) ($claims->aud ?? []), TRUE)) {
      return NULL;
    }

    // DPoP (opt-in): the presented token must be sender-constrained to a key
    // the client proves possession of on this very request.
    if (!empty($config['dpop'])) {
      $jkt = $this->verifyDpopProof(
        (string) $request->headers->get('DPoP', ''),
        $request->getMethod(),
        $this->htu($request),
      );
      if ($jkt === NULL) {
        return NULL;
      }
      if (($claims->cnf->jkt ?? NULL) !== $jkt) {
        // The token is not bound to the proven key: a stolen bearer token.
        return NULL;
      }
    }

    return [
      'sub' => isset($claims->sub) ? (string) $claims->sub : NULL,
      'acr' => isset($claims->acr) ? (string) $claims->acr : NULL,
      'amr' => array_map('strval', (array) ($claims->amr ?? [])),
    ];
  }

  /**
   * Loads (and caches) the issuer's JWKS via OIDC discovery.
   *
   * The issuer and its discovery document come from admin configuration — never
   * from the token — so a forged `iss` cannot point verification at an
   * attacker-controlled key set (SSRF). Protected so tests can seed a key set
   * without HTTP.
   *
   * @param string $issuer
   *   The configured OIDC issuer URL.
   *
   * @return array|null
   *   The JWKS (a ['keys' => [...]] array), or NULL on failure.
   */
  protected function loadJwks(string $issuer): ?array {
    $cid = 'file_gate_assurance:jwks:' . hash('sha256', $issuer);
    if ($cached = $this->cache->get($cid)) {
      return $cached->data;
    }
    try {
      $discovery = $this->httpGetJson(rtrim($issuer, '/') . '/.well-known/openid-configuration');
      $jwks_uri = (string) ($discovery['jwks_uri'] ?? '');
      if ($jwks_uri === '') {
        return NULL;
      }
      $jwks = $this->httpGetJson($jwks_uri);
      if (empty($jwks['keys'])) {
        return NULL;
      }
      // Cache for an hour; a rotated key surfaces as a decode failure and the
      // next miss refetches.
      $this->cache->set($cid, $jwks, $this->time->getRequestTime() + 3600);
      return $jwks;
    }
    catch (\Throwable $e) {
      $this->logger->warning('Assurance: JWKS discovery failed for @iss: @msg', [
        '@iss' => $issuer,
        '@msg' => $e->getMessage(),
      ]);
      return NULL;
    }
  }

  /**
   * Fetches and decodes a JSON document over HTTP.
   *
   * @param string $url
   *   The URL to fetch.
   *
   * @return array
   *   The decoded JSON as an array.
   *
   * @throws \RuntimeException
   *   If the response is not decodable JSON.
   */
  protected function httpGetJson(string $url): array {
    $response = $this->httpClient->request('GET', $url, [
      'timeout' => 8,
      'headers' => ['Accept' => 'application/json'],
    ]);
    $data = json_decode((string) $response->getBody(), TRUE);
    if (!is_array($data)) {
      throw new \RuntimeException('Non-JSON response from ' . $url);
    }
    return $data;
  }

  /**
   * Verifies an RFC 9449 DPoP proof and returns the proving key's thumbprint.
   *
   * @param string $proof
   *   The DPoP header value (a proof JWT).
   * @param string $htm
   *   The request HTTP method the proof must be bound to.
   * @param string $htu
   *   The request URI (no query/fragment) the proof must be bound to.
   *
   * @return string|null
   *   The RFC 7638 thumbprint (jkt) of the proof's embedded key, or NULL when
   *   the proof is missing, malformed, stale, replayed, or otherwise invalid.
   */
  private function verifyDpopProof(string $proof, string $htm, string $htu): ?string {
    if ($proof === '' || substr_count($proof, '.') !== 2) {
      return NULL;
    }
    [$header_b64] = explode('.', $proof, 2);
    $header = json_decode($this->base64UrlDecode($header_b64), TRUE);
    if (!is_array($header) || ($header['typ'] ?? '') !== 'dpop+jwt') {
      return NULL;
    }
    $alg = (string) ($header['alg'] ?? '');
    $jwk = $header['jwk'] ?? NULL;
    // Reject "none"/HMAC and any missing embedded public key up front.
    if (!in_array($alg, self::DPOP_ALGS, TRUE) || !is_array($jwk)) {
      return NULL;
    }

    try {
      // The proof is self-signed by its embedded public key; verifying against
      // that key proves possession of the corresponding private key.
      $claims = JWT::decode($proof, JWK::parseKey($jwk, $alg));
    }
    catch (\Throwable $e) {
      return NULL;
    }

    if (($claims->htm ?? '') !== $htm) {
      return NULL;
    }
    if ($this->normalizeUrl((string) ($claims->htu ?? '')) !== $htu) {
      return NULL;
    }
    $iat = (int) ($claims->iat ?? 0);
    if ($iat <= 0 || abs($this->time->getRequestTime() - $iat) > self::DPOP_WINDOW) {
      return NULL;
    }
    $jti = (string) ($claims->jti ?? '');
    if ($jti === '' || $this->dpopReplayed($jti)) {
      return NULL;
    }

    return $this->jwkThumbprint($jwk);
  }

  /**
   * Records a DPoP proof id and reports whether it was already spent.
   *
   * @param string $jti
   *   The proof's unique identifier.
   *
   * @return bool
   *   TRUE if the id was already seen (a replay); FALSE if it is fresh (and now
   *   recorded until just past the freshness window).
   */
  private function dpopReplayed(string $jti): bool {
    $store = $this->keyValueExpirableFactory->get(self::DPOP_COLLECTION);
    $key = hash('sha256', $jti);
    if ($store->has($key)) {
      return TRUE;
    }
    $store->setWithExpire($key, 1, self::DPOP_WINDOW * 2);
    return FALSE;
  }

  /**
   * Computes the RFC 7638 JWK thumbprint (base64url SHA-256).
   *
   * @param array $jwk
   *   The JSON Web Key.
   *
   * @return string|null
   *   The thumbprint, or NULL for an unsupported key type.
   */
  private function jwkThumbprint(array $jwk): ?string {
    $kty = $jwk['kty'] ?? '';
    // The canonical members, in the lexicographic order RFC 7638 mandates.
    $canonical = match ($kty) {
      'EC' => ['crv' => $jwk['crv'] ?? '', 'kty' => 'EC', 'x' => $jwk['x'] ?? '', 'y' => $jwk['y'] ?? ''],
      'RSA' => ['e' => $jwk['e'] ?? '', 'kty' => 'RSA', 'n' => $jwk['n'] ?? ''],
      'OKP' => ['crv' => $jwk['crv'] ?? '', 'kty' => 'OKP', 'x' => $jwk['x'] ?? ''],
      default => NULL,
    };
    if ($canonical === NULL) {
      return NULL;
    }
    return $this->base64UrlEncode(hash('sha256', (string) json_encode($canonical, JSON_UNESCAPED_SLASHES), TRUE));
  }

  /**
   * The request's htu: absolute URI without query or fragment (RFC 9449).
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string
   *   The normalized htu.
   */
  private function htu(Request $request): string {
    return $this->normalizeUrl($request->getSchemeAndHttpHost() . $request->getBaseUrl() . $request->getPathInfo());
  }

  /**
   * Reads and validates the JWT header algorithm.
   *
   * @param string $jwt
   *   The encoded JWT.
   *
   * @return string|null
   *   The header alg when it is an allowed asymmetric algorithm; otherwise
   *   NULL.
   */
  private function jwtHeaderAlg(string $jwt): ?string {
    if (substr_count($jwt, '.') !== 2) {
      return NULL;
    }
    [$header_b64] = explode('.', $jwt, 2);
    $header = json_decode($this->base64UrlDecode($header_b64), TRUE);
    if (!is_array($header)) {
      return NULL;
    }
    $alg = (string) ($header['alg'] ?? '');
    return in_array($alg, self::OIDC_TOKEN_ALGS, TRUE) ? $alg : NULL;
  }

  /**
   * Normalizes a URL to scheme://host[:port]/path (no query/fragment).
   *
   * @param string $url
   *   The URL.
   *
   * @return string
   *   The normalized URL, lower-cased scheme/host, default ports dropped.
   */
  private function normalizeUrl(string $url): string {
    $parts = parse_url($url);
    if (empty($parts['scheme']) || empty($parts['host'])) {
      return '';
    }
    $scheme = strtolower($parts['scheme']);
    $out = $scheme . '://' . strtolower($parts['host']);
    $defaults = ['http' => 80, 'https' => 443];
    if (isset($parts['port']) && ($defaults[$scheme] ?? NULL) !== $parts['port']) {
      $out .= ':' . $parts['port'];
    }
    return $out . ($parts['path'] ?? '');
  }

  /**
   * Base64url-encodes raw bytes (no padding).
   *
   * @param string $data
   *   The raw bytes.
   *
   * @return string
   *   The base64url string.
   */
  private function base64UrlEncode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  /**
   * Base64url-decodes a string.
   *
   * @param string $data
   *   The base64url string.
   *
   * @return string
   *   The decoded bytes (empty string on failure).
   */
  private function base64UrlDecode(string $data): string {
    $normalized = strtr($data, '-_', '+/');
    $padding = strlen($normalized) % 4;
    if ($padding > 0) {
      $normalized .= str_repeat('=', 4 - $padding);
    }
    $decoded = base64_decode($normalized, TRUE);
    return $decoded === FALSE ? '' : $decoded;
  }

}
