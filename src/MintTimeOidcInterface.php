<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Optional mint-time OIDC verification (assurance A2).
 *
 * Gate methods that can verify a File-Gate-audienced user token at mint
 * implement this interface. Core MintController calls it without depending
 * on the assurance submodule class hierarchy.
 */
interface MintTimeOidcInterface {

  /**
   * Verifies a mint-time OIDC token when the field requires it.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The mint request (Bearer / DPoP headers + JSON body).
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse|null
   *   Error response when verification is required and fails; NULL when the
   *   check is skipped (disabled) or succeeds.
   */
  public function assertMintTimeOidc(Request $request): ?JsonResponse;

}
