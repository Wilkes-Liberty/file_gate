<?php

declare(strict_types=1);

namespace Drupal\file_gate_form\Plugin\GateMethod;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\Attribute\GateMethod;
use Drupal\file_gate\GateMethodBase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Grants delivery after a visitor submits a native (coupled) capture form.
 */
#[GateMethod(
  id: 'form',
  label: new TranslatableMarkup('Email / form capture (coupled)'),
  description: new TranslatableMarkup('Drupal renders a lightweight email / lead-capture form and grants the download on submission. For coupled and hybrid sites that want File Gate delivery without building their own gate. Spam-guarded (honeypot + rate limit); a lead event lets you capture submissions into Contact, Webform, or a CRM.'),
)]
final class FormGate extends GateMethodBase {

  /**
   * The private-tempstore collection holding per-session form grants.
   */
  public const GRANT_COLLECTION = 'file_gate_form';

  /**
   * The default grant lifetime after a submission, in seconds.
   */
  public const DEFAULT_TTL = 3600;

  /**
   * The private tempstore factory.
   */
  protected PrivateTempStoreFactory $tempStoreFactory;

  /**
   * The time service.
   */
  protected TimeInterface $time;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): static {
    $instance = new static($configuration, $plugin_id, $plugin_definition);
    $instance->tempStoreFactory = $container->get('tempstore.private');
    $instance->time = $container->get('datetime.time');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function grants(FileInterface $file, Request $request): bool {
    $granted = (int) $this->tempStoreFactory->get(self::GRANT_COLLECTION)->get($file->uuid());
    if ($granted <= 0) {
      return FALSE;
    }
    $ttl = (int) ($this->configuration['ttl'] ?? self::DEFAULT_TTL);
    return ($this->time->getRequestTime() - $granted) < $ttl;
  }

  /**
   * {@inheritdoc}
   */
  public function mint(FileInterface $file): ?array {
    // Access is decided live from the per-session grant recorded on submit.
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $settings): array {
    return [
      'ttl' => [
        '#type' => 'number',
        '#title' => $this->t('Access window after submission (TTL)'),
        '#field_suffix' => $this->t('seconds'),
        '#min' => 60,
        '#default_value' => (int) ($settings['ttl'] ?? self::DEFAULT_TTL),
        '#description' => $this->t('How long a submission keeps the download available. Default 3600 (1 hour).'),
      ],
      'require_consent' => [
        '#type' => 'checkbox',
        '#title' => $this->t('Require a consent checkbox'),
        '#default_value' => !empty($settings['require_consent']),
      ],
      'consent_text' => [
        '#type' => 'textfield',
        '#title' => $this->t('Consent label'),
        '#default_value' => $settings['consent_text'] ?? '',
        '#description' => $this->t('Shown next to the consent checkbox (when required).'),
      ],
      'intro_text' => [
        '#type' => 'textarea',
        '#title' => $this->t('Intro text'),
        '#default_value' => $settings['intro_text'] ?? '',
        '#description' => $this->t('Optional text shown above the form.'),
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsSubmit(array $values): array {
    $settings = [
      'ttl' => max(60, (int) ($values['ttl'] ?? self::DEFAULT_TTL)),
      'require_consent' => !empty($values['require_consent']),
    ];
    foreach (['consent_text', 'intro_text'] as $key) {
      $value = trim((string) ($values[$key] ?? ''));
      if ($value !== '') {
        $settings[$key] = $value;
      }
    }
    return $settings;
  }

}
