<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * Reports observed primary metadata, usage and durable kill coverage.
 */
final readonly class ScopedGrantState {

  /**
   * Constructs a grant state observed on the native File Gate connection.
   */
  public function __construct(
    public bool $metadataPresent,
    public int $uses,
    public bool $killed,
    public ?int $killExpiresAt,
    public bool $enrolledMint,
  ) {}

}
