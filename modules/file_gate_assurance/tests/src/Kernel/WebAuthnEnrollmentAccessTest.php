<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate_assurance\Kernel;

use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\CsrfRequestHeaderAccessCheck;
use Drupal\Core\Routing\RouteMatch;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\file_gate_assurance\Controller\WebAuthnController;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Enrollment route access: register-only OR, CSRF header, delete permission.
 *
 * Drupal _permission + is OR. A comma would lock out the intended register
 * audience. Session POSTs without X-CSRF-Token must 403.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class WebAuthnEnrollmentAccessTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'file',
    'file_gate',
    'file_gate_assurance',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['user', 'system']);
    $this->installSchema('file_gate_assurance', ['file_gate_webauthn_credential']);
    // First account is uid 1 (all permissions). Burn it so test users are
    // ordinary accounts and the OR / deny paths can actually fail.
    $this->createUser([]);
  }

  /**
   * A user with only register permission reaches register/options with CSRF.
   *
   * Fails if routing + is flipped to a comma (AND of both permissions).
   */
  public function testRegisterOnlyUserReachesRegisterOptions(): void {
    $account = $this->createUser(['register file gate webauthn']);
    $this->assertFalse($account->hasPermission('administer file gate'));

    $access = $this->checkRegisterOptionsAccess($account, TRUE);
    $this->assertTrue(
      $access->isAllowed(),
      'Register-only user must pass routing on register/options.',
    );
  }

  /**
   * A session POST without X-CSRF-Token is 403.
   *
   * Fails if _csrf_request_header_token is dropped from the enrollment routes.
   */
  public function testMissingCsrfHeaderIsForbidden(): void {
    $account = $this->createUser(['register file gate webauthn']);

    $route = $this->container->get('router.route_provider')
      ->getRouteByName('file_gate_assurance.webauthn_register_options');
    $this->assertSame('TRUE', $route->getRequirement('_csrf_request_header_token'));

    $access = $this->checkRegisterOptionsAccess($account, FALSE);
    $this->assertTrue(
      $access->isForbidden(),
      'Missing CSRF header must deny routing access.',
    );

    $request = $this->enrollmentPostRequest(FALSE);
    $this->container->get('current_user')->setAccount($account);
    $response = $this->container->get('http_kernel')->handle($request);
    $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
  }

  /**
   * The delete action re-checks register-or-administer, not ownership alone.
   */
  public function testDeleteCredentialRequiresEnrollmentPermission(): void {
    $account = $this->createUser([]);
    $this->container->get('current_user')->setAccount($account);
    $request = Request::create(
      '/api/file-gate/webauthn/credentials/delete',
      'POST',
      [],
      [],
      [],
      [],
      (string) json_encode(['credential_id' => 'missing']),
    );
    $response = WebAuthnController::create($this->container)
      ->deleteCredential($request);
    $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
    $data = json_decode((string) $response->getContent(), TRUE);
    $this->assertSame('Permission denied.', $data['error'] ?? NULL);
  }

  /**
   * Runs permission + CSRF access on register/options for one POST.
   *
   * AccessManager::checkNamedRoute() drops request-dependent checkers, so
   * CSRF would be skipped. Pass the POST into AccessManager::check() instead.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account to test.
   * @param bool $with_csrf
   *   Whether the POST carries a valid X-CSRF-Token header.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   Combined routing access result.
   */
  private function checkRegisterOptionsAccess(AccountInterface $account, bool $with_csrf): AccessResultInterface {
    $request = $this->enrollmentPostRequest($with_csrf);
    $route = $this->container->get('router.route_provider')
      ->getRouteByName('file_gate_assurance.webauthn_register_options');
    $route_match = new RouteMatch('file_gate_assurance.webauthn_register_options', $route);
    return $this->container->get('access_manager')->check($route_match, $account, $request, TRUE);
  }

  /**
   * Builds a POST to register/options with a session cookie.
   *
   * CsrfRequestHeaderAccessCheck only runs when the account is authenticated
   * and the request carries a session cookie. Without that cookie the check
   * is skipped and a missing header would not 403.
   *
   * @param bool $with_csrf
   *   Whether to set a valid X-CSRF-Token header.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   POST request with a session cookie, optionally a CSRF header.
   */
  private function enrollmentPostRequest(bool $with_csrf): Request {
    $request = Request::create(
      '/api/file-gate/webauthn/register/options',
      'POST',
      [],
      [],
      [],
      [],
      '{}',
    );
    $request->headers->set('Content-Type', 'application/json');
    $request->headers->set('Accept', 'application/json');
    $request->setSession(new Session(new MockArraySessionStorage()));
    // Session cookie so hasSession() is true and the CSRF check runs.
    $session_name = $this->container->get('session_configuration')
      ->getOptions($request)['name'];
    $request->cookies->set($session_name, 'enrollment-access-session');
    if ($with_csrf) {
      // TOKEN_KEY is "X-CSRF-Token request header", not the header name.
      $token = $this->container->get('csrf_token')
        ->get(CsrfRequestHeaderAccessCheck::TOKEN_KEY);
      $request->headers->set('X-CSRF-Token', $token);
    }
    return $request;
  }

}
