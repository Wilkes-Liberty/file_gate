<?php

declare(strict_types=1);

namespace Drupal\file_gate_assurance\Form;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
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
   */
  public function __construct(
    protected WebAuthnCredentialStorage $storage,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('file_gate_assurance.webauthn_storage'),
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
    $account = $user instanceof UserInterface ? $user : $this->currentUser();
    $handle = (string) $account->id();

    $form['#attached']['library'][] = 'file_gate_assurance/webauthn_enrollment';
    $form['#attached']['drupalSettings']['fileGateWebauthn'] = [
      'registerOptions' => Url::fromRoute('file_gate_assurance.webauthn_register_options')->toString(),
      'register' => Url::fromRoute('file_gate_assurance.webauthn_register')->toString(),
      'delete' => Url::fromRoute('file_gate_assurance.webauthn_credential_delete')->toString(),
      'userHandle' => $handle,
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
   * Access callback: self with register permission, or administer.
   */
  public static function access(AccountInterface $account, UserInterface $user): AccessResultInterface {
    if (!$account->isAuthenticated()) {
      return AccessResult::forbidden()->cachePerPermissions()->cachePerUser();
    }
    if ($account->hasPermission('administer file gate')) {
      return AccessResult::allowed()->cachePerPermissions();
    }
    if ((int) $account->id() === (int) $user->id()
      && $account->hasPermission('register file gate webauthn')) {
      return AccessResult::allowed()->cachePerPermissions()->cachePerUser();
    }
    return AccessResult::forbidden()->cachePerPermissions()->cachePerUser();
  }

}
