<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * Holds the secret id authenticated for the current server-to-server request.
 *
 * Controllers receive a Request that is not always the request-stack current
 * request (kernel tests call mint() with a hand-built Request). Auth stores the
 * secret id here so gate methods can sign with the same credential and attach
 * k= to minted URLs.
 */
final class ActiveSecret {

  /**
   * Whether set() has been called for this request cycle.
   */
  private bool $authenticated = FALSE;

  /**
   * NULL = legacy download_secret; string = named secret id.
   */
  private ?string $secretId = NULL;

  /**
   * Records the authenticated secret id (NULL for legacy).
   */
  public function set(?string $secret_id): void {
    $this->authenticated = TRUE;
    $this->secretId = ($secret_id !== NULL && $secret_id !== '') ? $secret_id : NULL;
  }

  /**
   * Returns the secret id, or NULL for legacy / not authenticated.
   */
  public function get(): ?string {
    return $this->authenticated ? $this->secretId : NULL;
  }

  /**
   * Whether authentication has set a credential for this cycle.
   */
  public function isAuthenticated(): bool {
    return $this->authenticated;
  }

  /**
   * Clears state between requests when the service is reused.
   */
  public function clear(): void {
    $this->authenticated = FALSE;
    $this->secretId = NULL;
  }

}
