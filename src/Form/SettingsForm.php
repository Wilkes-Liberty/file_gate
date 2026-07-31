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
use Drupal\file_gate\SecretRegistryInterface;
use Drupal\file_gate\Service\FileGateMetrics;
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
   * @param \Drupal\file_gate\SecretRegistryInterface $secrets
   *   Secret registry (named secret status).
   * @param \Drupal\file_gate\Service\FileGateMetrics $metrics
   *   Dashboard metrics.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    TypedConfigManagerInterface $typedConfigManager,
    protected GrantSignerInterface $grantSigner,
    protected GateMethodManager $gateMethodManager,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected SecretRegistryInterface $secrets,
    protected FileGateMetrics $metrics,
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
      $container->get('file_gate.secret_registry'),
      $container->get('file_gate.metrics'),
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
      '#title' => $this->t('Legacy signing secret'),
      '#markup' => $this->grantSigner->hasSecret()
        ? $this->t('<strong>Configured.</strong> At least one secret is available (legacy and/or named).')
        : $this->t('<strong>Not configured.</strong> The module is failing closed — minting returns 503 and every gated file is denied until a secret is provided.'),
      '#description' => $this->t("Secrets are never stored in configuration. Legacy (whole corpus): <code>\$config['file_gate.settings']['download_secret'] = getenv('DRUPAL_FILE_GATE_SECRET');</code><br />Named (field-scoped): <code>\$settings['file_gate.secrets'] = ['s1' =&gt; getenv('…')];</code> with scopes below. Basic-auth username = secret id; password = value. Minted URLs carry <code>k=&lt;id&gt;</code> for named secrets."),
    ];

    // --- Named secret scopes (exportable map; values stay in settings.php) --
    $scope_lines = [];
    $scopes = $config->get('secret_scopes');
    if (is_array($scopes)) {
      foreach ($scopes as $id => $fields) {
        if (!is_string($id) || $id === '') {
          continue;
        }
        $list = is_array($fields) ? $fields : [];
        $scope_lines[] = $id . ': ' . implode(', ', array_map('strval', $list));
      }
    }
    $form['secret_scopes_text'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Named secret scopes'),
      '#default_value' => implode("\n", $scope_lines),
      '#description' => $this->t('One secret id per line: <code>opaque_id: entity_type.field_name, entity_type.other_field</code>. Values for those ids must be injected via <code>$settings["file_gate.secrets"]</code>. A named secret with a value but no (or empty) scope can mint nothing and is reported on the status report. Leave empty if you only use the legacy single secret.'),
      '#rows' => 5,
    ];

    $named_rows = [];
    foreach ($this->secrets->namedSecretIds() as $id) {
      $fields = $this->secrets->scopeFields($id);
      $named_rows[] = [
        $id,
        $fields === [] ? $this->t('None (unscoped)') : implode(', ', $fields),
        $this->secrets->isNamedSecretUnscoped($id)
          ? $this->t('ERROR: value present, no scope')
          : ($fields === [] ? $this->t('No value in settings') : $this->t('OK')),
      ];
    }
    if ($named_rows !== []) {
      $form['status']['named'] = [
        '#type' => 'table',
        '#header' => [
          $this->t('Secret id'),
          $this->t('Scoped fields'),
          $this->t('Status'),
        ],
        '#rows' => $named_rows,
        '#caption' => $this->t('Named secrets (from settings + scopes)'),
      ];
    }

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

    $form['download_flood'] = [
      '#type' => 'details',
      '#title' => $this->t('Download denial rate limiting'),
      '#open' => FALSE,
      '#description' => $this->t('Throttles failed grant attempts on the public download endpoint per client IP. Set requests to 0 to disable.'),
    ];
    $form['download_flood']['download_flood_limit'] = [
      '#type' => 'number',
      '#title' => $this->t('Denied requests'),
      '#min' => 0,
      '#default_value' => (int) ($config->get('download_flood_limit') ?? 120),
    ];
    $form['download_flood']['download_flood_window'] = [
      '#type' => 'number',
      '#title' => $this->t('Window'),
      '#field_suffix' => $this->t('seconds'),
      '#min' => 1,
      '#default_value' => (int) ($config->get('download_flood_window') ?: 60),
    ];

    $form['require_acting_account'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require acting account on every mint'),
      '#default_value' => !empty($config->get('require_acting_account')),
      '#description' => $this->t('Mint body must include <code>account</code> (user UUID) or <code>uid</code>. Can also be required per field via method settings. See docs/API.md.'),
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

    // --- Dashboard (dblog aggregates when available) -------------------------
    $summary = $this->metrics->summary(14);
    $form['dashboard'] = [
      '#type' => 'details',
      '#title' => $this->t('Dashboard (last @days days)', ['@days' => $summary['days']]),
      '#open' => TRUE,
    ];
    if (!$summary['available']) {
      $form['dashboard']['empty'] = [
        '#markup' => '<p>' . $this->t(
          'Enable the <strong>Database Logging</strong> (dblog) module to populate mint, delivery, and denial counts from the <code>file_gate</code> log channel. Charts module is not required — this table is the fallback.',
        ) . '</p>',
      ];
    }
    else {
      $form['dashboard']['totals'] = [
        '#type' => 'table',
        '#header' => [
          $this->t('Mints'),
          $this->t('Deliveries'),
          $this->t('Denials / refusals'),
          $this->t('Auth failures'),
        ],
        '#rows' => [
          [
            (string) $summary['mints'],
            (string) $summary['deliveries'],
            (string) $summary['denials'],
            (string) $summary['auth_failures'],
          ],
        ],
      ];
      if ($summary['by_method'] !== []) {
        $method_rows = [];
        foreach ($summary['by_method'] as $row) {
          $method_rows[] = [$row['method'], (string) $row['count']];
        }
        $form['dashboard']['by_method'] = [
          '#type' => 'table',
          '#caption' => $this->t('By gate method'),
          '#header' => [$this->t('Method'), $this->t('Events')],
          '#rows' => $method_rows,
        ];
      }
      if ($summary['top_files'] !== []) {
        $file_rows = [];
        foreach ($summary['top_files'] as $row) {
          $file_rows[] = [$row['uuid'], (string) $row['count']];
        }
        $form['dashboard']['top_files'] = [
          '#type' => 'table',
          '#caption' => $this->t('Top files (mint + delivery)'),
          '#header' => [$this->t('File UUID'), $this->t('Count')],
          '#rows' => $file_rows,
        ];
      }
      if ($summary['by_day'] !== []) {
        $day_rows = [];
        foreach (array_reverse($summary['by_day']) as $row) {
          $day_rows[] = [
            $row['date'],
            (string) $row['mints'],
            (string) $row['deliveries'],
            (string) $row['denials'],
          ];
        }
        $form['dashboard']['by_day'] = [
          '#type' => 'table',
          '#caption' => $this->t('Per day'),
          '#header' => [
            $this->t('Date (UTC)'),
            $this->t('Mints'),
            $this->t('Deliveries'),
            $this->t('Denials'),
          ],
          '#rows' => $day_rows,
        ];
      }
    }

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
      ->set('download_flood_limit', (int) $form_state->getValue('download_flood_limit'))
      ->set('download_flood_window', (int) $form_state->getValue('download_flood_window'))
      ->set('require_acting_account', (bool) $form_state->getValue('require_acting_account'))
      ->set('secret_scopes', $this->parseSecretScopes((string) $form_state->getValue('secret_scopes_text')))
      ->save();
    parent::submitForm($form, $form_state);
  }

  /**
   * Parses the scopes textarea into secret_id => field keys.
   *
   * @param string $text
   *   Lines of "id: field.a, field.b".
   *
   * @return array<string, list<string>>
   *   Scope map.
   */
  private function parseSecretScopes(string $text): array {
    $scopes = [];
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
      $line = trim($line);
      if ($line === '' || !str_contains($line, ':')) {
        continue;
      }
      [$id, $rest] = explode(':', $line, 2);
      $id = trim($id);
      if ($id === '') {
        continue;
      }
      $fields = [];
      foreach (explode(',', $rest) as $field) {
        $field = trim($field);
        if ($field !== '') {
          $fields[] = $field;
        }
      }
      $fields = array_values(array_unique($fields));
      sort($fields);
      $scopes[$id] = $fields;
    }
    ksort($scopes);
    return $scopes;
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
