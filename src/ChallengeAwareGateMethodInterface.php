<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\file\FileInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Optional gate-method seam for step-up / challenge responses.
 *
 * When grants() would fail but the failure is "proof missing" rather than
 * "proof invalid / grant dead", the download controller feature-detects this
 * interface and returns challenge() instead of a bare 403. Methods that do not
 * implement it keep the existing fail-closed 403 behaviour.
 */
interface ChallengeAwareGateMethodInterface {

  /**
   * Builds a step-up / challenge response when the request may still succeed.
   *
   * Called only after grants() returned FALSE. Return NULL to keep the default
   * AccessDeniedHttpException path (forged grants, spent links, etc.).
   *
   * @param \Drupal\file\FileInterface $file
   *   The gated file.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The failed download request.
   *
   * @return \Symfony\Component\HttpFoundation\Response|null
   *   A 401 challenge (HTML or JSON), a redirect to a step-up page, or NULL.
   */
  public function challenge(FileInterface $file, Request $request): ?Response;

}
