<?php

declare(strict_types=1);

namespace Drupal\file_gate;

/**
 * Thrown when a revoke cannot take the redemption lock in time.
 *
 * A revoke must not report success without the kill mark in place. The HTTP
 * route answers 503 with Retry-After; the MCP tool returns its fixed refusal.
 */
final class GrantRevokeLockException extends \RuntimeException {}
