<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * Identifies a usage-limited grant without its signature or bearer material.
 */
final readonly class ScopedGrant {

  /**
   * Constructs grant coordinates.
   */
  public function __construct(
    public string $jti,
    public string $fileUuid,
    public string $field,
    public ?string $grantClass,
    public int $expiresAt,
    public int $maxUses,
    public ?string $gateMethod = NULL,
  ) {}

  /**
   * Returns the coordinates as durable storage values.
   *
   * @return array{jti: string, f: string, field: string, k: ?string, exp: int, max: int, method?: string}
   *   The non-secret grant identity.
   */
  public function coordinates(): array {
    $coordinates = [
      'jti' => $this->jti,
      'f' => $this->fileUuid,
      'field' => $this->field,
      'exp' => $this->expiresAt,
      'k' => $this->grantClass,
      'max' => $this->maxUses,
    ];
    if ($this->gateMethod !== NULL) {
      $coordinates['method'] = $this->gateMethod;
    }
    return $coordinates;
  }

}
