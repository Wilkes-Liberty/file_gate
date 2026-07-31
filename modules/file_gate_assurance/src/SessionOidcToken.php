<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance;

/**
 * Soft source of OIDC access tokens from a Drupal SSO session.
 *
 * When openid_connect is installed, tokens saved at login
 * (OpenIDConnectSession::saveAccessToken) are available same-origin without the
 * browser placing Bearer material in sessionStorage. Tokens may be stale after
 * the access lifetime — callers must still verify acr/aud via AssuranceVerifier
 * and fail closed on failure (GH #41).
 *
 * No hard dependency on openid_connect: absent service ⇒ no token.
 */
final class SessionOidcToken {

  /**
   * Constructs the helper.
   *
   * @param object|null $openidSession
   *   Optional openid_connect.session service (duck-typed).
   */
  public function __construct(
    private readonly ?object $openidSession,
  ) {}

  /**
   * Returns a session-stored access token when available.
   *
   * @return string|null
   *   Non-empty access token, or NULL.
   */
  public function accessToken(): ?string {
    if ($this->openidSession === NULL) {
      return NULL;
    }
    if (!method_exists($this->openidSession, 'retrieveAccessToken')) {
      return NULL;
    }
    try {
      $token = $this->openidSession->retrieveAccessToken(FALSE);
    }
    catch (\Throwable) {
      return NULL;
    }
    if (!is_string($token) || $token === '') {
      return NULL;
    }
    return $token;
  }

  /**
   * Whether the openid_connect session service is present.
   */
  public function isAvailable(): bool {
    return $this->openidSession !== NULL
      && method_exists($this->openidSession, 'retrieveAccessToken');
  }

}
