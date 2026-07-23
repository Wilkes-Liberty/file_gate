<?php

declare(strict_types=1);

namespace Drupal\file_gate\Exception;

/**
 * Thrown by mint() when the field's availability window has already closed.
 *
 * A field may cap a grant's expiry with an absolute "available until"
 * timestamp. Once that timestamp is in the past, there is no live grant to
 * issue: minting one would hand the caller a link that is already expired.
 * Rather than return a dead grant (an HTTP 200 with a link that immediately
 * 403s), mint() raises this so the mint endpoint can answer 410 Gone.
 */
final class GrantWindowClosedException extends \RuntimeException {
}
