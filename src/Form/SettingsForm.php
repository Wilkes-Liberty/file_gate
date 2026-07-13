<?php

declare(strict_types=1);

namespace Drupal\file_gate\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\Entity\ThirdPartySettingsInterface;
use Drupal\Core\Config\TypedConfigManagerInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Link;
use Drupal\file_gate\GateMethodManager;
use Drupal\file_gate\GrantSignerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configures global File Gate behaviour.
 *
 * The signing secret is deliberately NOT edited here: it must be injected from
 * the environment (settings.php) so it never lands in exported configuration.
 * This form only reports whether it is present, and manages the global defaults
 * (TTL, disposition, mint rate limiting) plus a read-only overview of which
 * fields are gated.
 */
final class SettingsForm extends ConfigFormBase {

  /**
   * Constructs the settings form.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Config\TypedConfigManagerInterface $typedConfigManager
   *   The typed config manager.
   * @param \Drupal\file_gate\GrantSignerInterface $grantSigner
   *   The grant signer (to report secret presence).
   * @param \Drupal\file_gate\GateMethodManager $gateMethodManager
   *   The gate method plugin manager (to list available methods).
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (to build the gated-fields overview).
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    TypedConfigManagerInterface $typedConfigManager,
    private readonly GrantSignerInterface $grantSigner,
    private readonly GateMethodManager $gateMethodManager,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {
    parent::__construct($config_factory, $typedConfigManager);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('config.typed'),
      $container->get('file_gate.grant_signer'),
      $container->get('plugin.manager.file_gate.gate_method'),
      $container->get('entity_type.manager'),
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['file_gate.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'file_gate_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('file_gate.settings');

    // --- Secret status (read-only) -------------------------------------------
    $form['status'] = [
      '#type' => 'details',
      '#title' => $this->t('Status'),
      '#open' => TRUE,
    ];
    $form['status']['secret'] = [
      '#type' => 'item',
      '#title' => $this->t('Signing secret'),
      '#markup' => $this->grantSigner->hasSecret()
        ? $this->t('<strong>Configured.</strong> Gating is active.')
        : $this->t('<strong>Not configured.</strong> The module is failing closed — minting returns 503 and every gated file is denied until a secret is provided.'),
      '#description' => $this->t("The secret is never stored in configuration. Inject it from the environment in <code>settings.php</code>, e.g.<br /><code>\$config['file_gate.settings']['download_secret'] = getenv('DRUPAL_FILE_GATE_SECRET');</code>"),
    ];

    // --- Defaults ------------------------------------------------------------
    $form['ttl'] = [
      '#type' => 'number',
      '#title' => $this->t('Signed-URL lifetime (TTL)'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 5,
      '#default_value' => (int) ($config->get('ttl') ?: 120),
      '#required' => TRUE,
      '#description' => $this->t('How long a minted download URL stays valid. Keep this short — it only needs to cover the moment between minting and the browser starting the download. Default: 120.'),
    ];
    $form['disposition'] = [
      '#type' => 'select',
      '#title' => $this->t('Content disposition'),
      '#options' => [
        'attachment' => $this->t('Attachment (force download)'),
        'inline' => $this->t('Inline (let the browser display, e.g. PDFs)'),
      ],
      '#default_value' => $config->get('disposition') ?: 'attachment',
      '#description' => $this->t('How gated files are delivered. "Attachment" prompts a download; "inline" lets the browser render the file in place.'),
    ];

    $form['flood'] = [
      '#type' => 'details',
      '#title' => $this->t('Mint rate limiting'),
      '#open' => FALSE,
      '#description' => $this->t('Throttles the server-to-server mint endpoint per client IP.'),
    ];
    $form['flood']['flood_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Requests'),
      '#min' => 1,
      '#default_value' => (int) ($config->get('flood_limit') ?: 50),
      '#description' => $this->t('Maximum mint requests allowed per IP within the window.'),
    ];
    $form['flood']['flood_window'] = [
      '#type' => 'number',
      '#title' => $this->t('Window'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 1,
      '#default_value' => (int) ($config->get('flood_window') ?: 60),
      '#description' => $this->t('Length of the rate-limit window.'),
    ];

    // --- Available gate methods ----------------------------------------------
    $method_items = [];
    foreach ($this->gateMethodManager->getDefinitions() as $id => $definition) {
      $method_items[] = $this->t('<strong>@label</strong> (<code>@id</code>): @description', [
        '@label' => $definition['label'] ?? $id,
        '@id' => $id,
        '@description' => $definition['description'] ?? '',
      ]);
    }
    $form['methods'] = [
      '#type' => 'details',
      '#title' => $this->t('Available gate methods'),
      '#open' => FALSE,
    ];
    $form['methods']['list'] = [
      '#theme' => 'item_list',
      '#items' => $method_items,
    ];

    // --- Gated-fields overview (read-only) -----------------------------------
    $gated = $this->gatedFieldsOverview();
    $form['gated_fields'] = [
      '#type' => 'details',
      '#title' => $this->t('Gated fields (@count)', ['@count' => count($gated)]),
      '#open' => TRUE,
    ];
    if ($gated) {
      $form['gated_fields']['table'] = [
        '#type' => 'table',
        '#header' => [
          $this->t('Field'),
          $this->t('Entity type'),
          $this->t('Bundle'),
          $this->t('Method'),
        ],
        '#rows' => $gated,
      ];
    }
    else {
      $form['gated_fields']['empty'] = [
        '#markup' => '<p>' . $this->t('No fields are gated yet. Edit a private file or image field and enable "Gate access to these files".') . '</p>',
      ];
    }

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('file_gate.settings')
      ->set('ttl', (int) $form_state->getValue('ttl'))
      ->set('disposition', $form_state->getValue('disposition'))
      ->set('flood_limit', (int) $form_state->getValue('flood_limit'))
      ->set('flood_window', (int) $form_state->getValue('flood_window'))
      ->save();
    parent::submitForm($form, $form_state);
  }

  /**
   * Builds the read-only overview of gated fields.
   *
   * One row per gated field instance, with the field name linking to its Field
   * UI settings page (where gating is toggled) when that route is available.
   *
   * @return array[]
   *   Table rows: [field (linked), entity type, bundle, gate method].
   */
  private function gatedFieldsOverview(): array {
    $rows = [];
    if (!$this->entityTypeManager->hasDefinition('field_config')) {
      return $rows;
    }
    /** @var \Drupal\field\FieldConfigInterface $field_config */
    foreach ($this->entityTypeManager->getStorage('field_config')->loadMultiple() as $field_config) {
      $storage = $field_config->getFieldStorageDefinition();
      // Gating lives on the field storage; skip fields whose storage is not
      // gated (and base fields, which are not third-party-settings-aware).
      if (!$storage instanceof ThirdPartySettingsInterface || !$storage->getThirdPartySetting('file_gate', 'gated', FALSE)) {
        continue;
      }

      // Link the field to its settings page when Field UI exposes one; fall
      // back to plain text otherwise (e.g. Field UI disabled).
      try {
        $field_cell = ['data' => Link::fromTextAndUrl($field_config->getName(), $field_config->toUrl('edit-form'))->toRenderable()];
      }
      catch (\Exception) {
        $field_cell = $field_config->getName();
      }

      $rows[] = [
        $field_cell,
        $field_config->getTargetEntityTypeId(),
        $field_config->getTargetBundle(),
        $storage->getThirdPartySetting('file_gate', 'method') ?: 'signed_url',
      ];
    }
    return $rows;
  }

}
