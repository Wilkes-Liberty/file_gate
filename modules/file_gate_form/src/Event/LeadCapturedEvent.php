<?php

declare(strict_types=1);

namespace Drupal\file_gate_form\Event;

use Drupal\Component\EventDispatcher\Event;
use Drupal\file\FileInterface;

/**
 * Dispatched when a visitor submits the capture form for a gated file.
 *
 * File Gate does not itself persist the lead — subscribe to this event to store
 * it wherever you handle PII and consent (Contact, Webform, a CRM), keeping
 * retention and marketing-consent decisions with the site. The submission has
 * already been validated (email format, honeypot, rate limit) when this fires.
 */
final class LeadCapturedEvent extends Event {

  /**
   * Constructs the event.
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file the submission unlocks.
   * @param string $email
   *   The submitted email address.
   * @param bool $consent
   *   Whether the consent checkbox was ticked (FALSE when not required).
   */
  public function __construct(
    public readonly FileInterface $file,
    public readonly string $email,
    public readonly bool $consent,
  ) {}

}
