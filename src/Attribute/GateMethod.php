<?php

declare(strict_types=1);

namespace Drupal\file_gate\Attribute;

use Drupal\Component\Plugin\Attribute\Plugin;
use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * Defines a gate_method plugin attribute for discovery.
 *
 * A gate method answers one question: "has this request passed the gate for
 * this file?" The module ships two: signed_url (a minted, short-lived HMAC URL)
 * and authenticated (a logged-in user). Third parties add their own (token,
 * email capture, form submission, …).
 *
 * @see \Drupal\file_gate\GateMethodInterface
 * @see \Drupal\file_gate\GateMethodManager
 * @see plugin_api
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class GateMethod extends Plugin {

  /**
   * Constructs a GateMethod attribute.
   *
   * @param string $id
   *   The plugin id.
   * @param \Drupal\Core\StringTranslation\TranslatableMarkup|null $label
   *   The human-readable label.
   * @param \Drupal\Core\StringTranslation\TranslatableMarkup|null $description
   *   A short description of how the method decides access.
   */
  public function __construct(
    public readonly string $id,
    public readonly ?TranslatableMarkup $label = NULL,
    public readonly ?TranslatableMarkup $description = NULL,
  ) {}

}
