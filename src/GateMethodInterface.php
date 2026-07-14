<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Component\Plugin\PluginInspectionInterface;
use Drupal\file\FileInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Interface for gate method plugins.
 *
 * A gate method encapsulates one strategy for proving that a request is allowed
 * to receive a gated file. It has two jobs:
 * - grants(): decide, at delivery time, whether the current request satisfies
 *   the gate for a given file;
 * - mint(): optionally pre-issue a grant (server-side) that a client can later
 *   redeem — used by URL-based methods such as signed_url. Methods that decide
 *   access live (e.g. from the session) return NULL from mint().
 */
interface GateMethodInterface extends PluginInspectionInterface {

  /**
   * The human-readable label.
   *
   * @return string
   *   The label.
   */
  public function label(): string;

  /**
   * A short description of how the method decides access.
   *
   * @return string
   *   The description.
   */
  public function description(): string;

  /**
   * Decides whether the request may receive the file.
   *
   * Implementations MUST fail closed: return FALSE unless the request
   * positively proves it has passed the gate.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file being requested.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request (query parameters, headers, session, …).
   *
   * @return bool
   *   TRUE if delivery is allowed.
   */
  public function grants(FileInterface $file, Request $request): bool;

  /**
   * Mints a grant for a file, if this method supports pre-issued grants.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file to mint a grant for.
   *
   * @return array|null
   *   Query parameters to append to the download URL — for signed_url that is
   *   ['exp' => int, 'sig' => string]. Returns NULL when the method does not
   *   use minted URLs (access is decided live in grants() instead).
   */
  public function mint(FileInterface $file): ?array;

  /**
   * Builds this method's per-field settings form.
   *
   * Rendered on the field edit form when the method is selected, so a site
   * builder configures the method's options in the UI rather than by hand in
   * exported YAML. Return an empty array for a method with no settings.
   *
   * @param array $settings
   *   The current method_settings for this field.
   *
   * @return array
   *   A Form API array of settings elements (keyed by setting name).
   */
  public function fieldSettingsForm(array $settings): array;

  /**
   * Maps submitted settings-form values back to the stored method_settings.
   *
   * Lets a method normalize what it persists (cast types, split textareas,
   * drop empties) independently of how the form is rendered.
   *
   * @param array $values
   *   The submitted values from this method's fieldSettingsForm().
   *
   * @return array
   *   The method_settings to store in the field's third-party settings.
   */
  public function fieldSettingsSubmit(array $values): array;

}
