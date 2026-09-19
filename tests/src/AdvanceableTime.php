<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate;

use Drupal\Component\Datetime\Time;

/**
 * A time service a test can move forward.
 *
 * Everything that decides whether a grant or a kill mark is still alive reads
 * datetime.time: the signer, the gate method, the inventory and the expirable
 * key-value store. Moving this one clock moves them together.
 */
final class AdvanceableTime extends Time {

  /**
   * Seconds added to the real clock.
   */
  public static int $offset = 0;

  /**
   * {@inheritdoc}
   */
  public function getRequestTime(): int {
    return parent::getRequestTime() + self::$offset;
  }

  /**
   * {@inheritdoc}
   */
  public function getCurrentTime(): int {
    return parent::getCurrentTime() + self::$offset;
  }

}
