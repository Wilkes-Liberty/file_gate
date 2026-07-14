<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\file\FileInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Optional interface for gate methods that need the mint request context.
 *
 * The plain mint contract, GateMethodInterface::mint(FileInterface), takes no
 * request or caller input by design. A method that must bind request-scoped
 * claims at mint — for example a caller-asserted subject, so a grant can later
 * be tied to one person — implements this interface instead. The controller
 * feature-detects it and passes the incoming request; methods that do not
 * implement it keep using mint(), so this is fully backward compatible.
 */
interface ContextualMintInterface {

  /**
   * Mints a grant with access to the mint request.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file to mint a grant for.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The server-to-server mint request (its authenticated body may carry
   *   caller-asserted context such as a subject identifier).
   *
   * @return array|null
   *   Query parameters to append to the download URL, or NULL — exactly as
   *   GateMethodInterface::mint().
   */
  public function mintWithContext(FileInterface $file, Request $request): ?array;

}
