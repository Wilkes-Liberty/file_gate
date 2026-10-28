<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Form;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\CsrfRequestHeaderAccessCheck;
use Drupal\Core\Access\CsrfTokenGenerator;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\file_gate_assurance\WebAuthn\WebAuthnCredentialStorage;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Account UI to register and remove native WebAuthn credentials.
 *
 * Self-only: the page manages the current user's keys. Another account's
 * URL is forbidden, including for administer, because the JSON APIs always
 * enroll the session account.
 *
 * Consumes the existing JSON registration APIs (options + register + delete).
 * Binding: registration user_handle defaults to the Drupal uid string; mint
 * should pass subject matching that handle (or set webauthn_user_handle on the
 * field) so grant sh= / query wh= line up. See docs/assurance-redeem.md.
 */
final class WebAuthnEnrollmentForm extends FormBase {

  /**
   * Constructs the form.
   *
   * @param \Drupal\file_gate_assurance\WebAuthn\WebAuthnCredentialStorage $storage
   *   Native WebAuthn credential storage.
   * @param \Drupal\Core\Access\CsrfTokenGenerator $csrfToken
   *   Session CSRF tokens for the enrollment JSON POSTs.
   */
  public function __construct(
    protected WebAuthnCredentialStorage $storage,
    protected CsrfTokenGenerator $csrfToken,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('file_gate_assurance.webauthn_storage'),
      // Header-token generator used by _csrf_request_header_token.
      $container->get('csrf_token'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'file_gate_assurance_webauthn_enrollment';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, ?UserInterface $user = NULL): array {
    // JSON register/delete always enroll the session account. List that
    // account's keys even if the route {user} were wrong (self-only access
    // should already have 403'd a mismatch).
    $handle = (string) $this->currentUser()->id();
    if ($user instanceof UserInterface && (string) $user->id() !== $handle) {
      // Route {user} is not the session. Access should have 403'd; still
      // do not list that account's keys.
      $handle = (string) $this->currentUser()->id();
    }

    $form['#attached']['library'][] = 'file_gate_assurance/webauthn_enrollment';
    $form['#attached']['drupalSettings']['fileGateWebauthn'] = [
      'registerOptions' => Url::fromRoute('file_gate_assurance.webauthn_register_options')->toString(),
      'register' => Url::fromRoute('file_gate_assurance.webauthn_register')->toString(),
      'delete' => Url::fromRoute('file_gate_assurance.webauthn_credential_delete')->toString(),
      // Same key CsrfRequestHeaderAccessCheck validates on X-CSRF-Token.
      'csrfToken' => $this->csrfToken->get(CsrfRequestHeaderAccessCheck::TOKEN_KEY),
    ];

    $form['intro'] = [
      '#markup' => '<p>' . $this->t('Register a security key or platform authenticator for File Gate native WebAuthn downloads. Your user handle is <code>@handle</code> — mint with matching <code>subject</code> (or configure a fixed handle on the field).', [
        '@handle' => $handle,
      ]) . '</p>',
    ];

    $creds = $this->storage->loadByUserHandle($handle);
    $rows = [];
    foreach ($creds as $cred) {
      $id = (string) ($cred['credential_id'] ?? $cred['id'] ?? '');
      $rows[] = [
        (string) ($cred['label'] ?? $this->t('Security key')),
        $id !== '' ? substr($id, 0, 16) . '…' : '—',
        [
          'data' => [
            '#type' => 'html_tag',
            '#tag' => 'button',
            '#value' => $this->t('Remove'),
            '#attributes' => [
              'class' => ['button', 'file-gate-webauthn-delete'],
              'data-credential-id' => $id,
              'type' => 'button',
            ],
          ],
        ],
      ];
    }

    $form['credentials'] = [
      '#type' => 'table',
      '#header' => [
        $this->t('Label'),
        $this->t('Credential id'),
        $this->t('Operations'),
      ],
      '#rows' => $rows,
      '#empty' => $this->t('No authenticators registered yet. Use Add security key below.'),
    ];

    $form['register'] = [
      '#type' => 'button',
      '#value' => $this->t('Add security key'),
      '#attributes' => [
        'class' => ['button', 'button--primary', 'file-gate-webauthn-register'],
        'type' => 'button',
      ],
    ];

    $form['status'] = [
      '#type' => 'html_tag',
      '#tag' => 'p',
      '#attributes' => [
        'id' => 'file-gate-webauthn-status',
        'class' => ['messages'],
        'hidden' => 'hidden',
      ],
      '#value' => '',
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    // Client-side WebAuthn ceremony; no server form submit.
  }

  /**
   * Access callback: the account may manage keys only on its own page.
   *
   * Administrators are not a second management surface. The JSON register
   * and delete APIs always act as the current user, so another user's page
   * would list that account's keys and then enroll or 404 as the viewer.
   * Fail closed: a mismatched {user} is forbidden, including administer.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account asking for the page.
   * @param \Drupal\user\UserInterface $user
   *   The account whose keys page was requested.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   Allowed only for an authenticated self with register or administer.
   */
  public static function access(AccountInterface $account, UserInterface $user): AccessResultInterface {
    if (!$account->isAuthenticated()) {
      return self::denyKeysPage($user);
    }
    // Self only. Do not special-case administer: there is no target-user
    // parameter on the enrollment APIs.
    if ((int) $account->id() !== (int) $user->id()) {
      return self::denyKeysPage($user);
    }
    if ($account->hasPermission('register file gate webauthn')
      || $account->hasPermission('administer file gate')) {
      return AccessResult::allowed()
        ->cachePerPermissions()
        ->cachePerUser()
        ->addCacheableDependency($user);
    }
    return self::denyKeysPage($user);
  }

  /**
   * Forbidden keys-page result, cached per viewer and target account.
   *
   * @param \Drupal\user\UserInterface $user
   *   The account whose keys page was requested.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   A forbidden result. Callers must not reuse the object.
   */
  private static function denyKeysPage(UserInterface $user): AccessResultInterface {
    return AccessResult::forbidden()
      ->cachePerPermissions()
      ->cachePerUser()
      ->addCacheableDependency($user);
  }

}
