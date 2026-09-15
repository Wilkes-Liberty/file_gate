<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\file\FileInterface;

/**
 * HMAC resource id shared by SignedUrl and Token: UUID plus normalized URI.
 *
 * The format is a security invariant. Two managed files that share a
 * private:// path must not share a signature, and the string signed at mint
 * must match the string validated at redeem (core reconstructs the URI from
 * the request path).
 */
trait FileResourceIdTrait {

  /**
   * The stream wrapper manager (to normalize the file URI before signing).
   */
  protected StreamWrapperManagerInterface $streamWrapperManager;

  /**
   * The signed resource id for a file: its UUID plus its normalized stream URI.
   *
   * @param \Drupal\file\FileInterface $file
   *   The file.
   *
   * @return string
   *   The resource id: "<uuid>|private://…".
   */
  protected function resourceId(FileInterface $file): string {
    return $file->uuid() . '|' . $this->streamWrapperManager->normalizeUri((string) $file->getFileUri());
  }

}
