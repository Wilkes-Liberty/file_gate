<?php

declare(strict_types=1);

namespace Drupal\file_gate_form\Form;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\Url;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate_form\Event\LeadCapturedEvent;
use Drupal\file_gate_form\Plugin\GateMethod\FormGate;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * The native email / lead-capture form for the `form` gate method.
 *
 * Renders at /file-gate/form/{file}. A valid submission records a per-session
 * grant for the file (private tempstore) and redirects to the download; the
 * `form` gate method checks that grant. Spam is bounded by a honeypot and a
 * per-IP rate limit; the captured lead is dispatched as an event for the site
 * to persist.
 */
final class FileGateForm extends FormBase {

  /**
   * The per-IP submission rate limit and window.
   */
  private const SUBMIT_LIMIT = 10;
  private const SUBMIT_WINDOW = 3600;

  /**
   * Constructs the form.
   *
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entityRepository
   *   The entity repository (resolves the file UUID).
   * @param \Drupal\file_gate\FileGateResolver $resolver
   *   The gate resolver.
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $tempStoreFactory
   *   The private tempstore factory (records the per-session grant).
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Symfony\Contracts\EventDispatcher\EventDispatcherInterface $eventDispatcher
   *   The event dispatcher (emits the lead event).
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   */
  public function __construct(
    protected readonly EntityRepositoryInterface $entityRepository,
    protected readonly FileGateResolver $resolver,
    protected readonly PrivateTempStoreFactory $tempStoreFactory,
    protected readonly FloodInterface $flood,
    protected readonly TimeInterface $time,
    protected readonly EventDispatcherInterface $eventDispatcher,
    protected readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity.repository'),
      $container->get('file_gate.resolver'),
      $container->get('tempstore.private'),
      $container->get('flood'),
      $container->get('datetime.time'),
      $container->get('event_dispatcher'),
      $container->get('logger.channel.file_gate'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'file_gate_form_gate';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, string $file = ''): array {
    $entity = $this->loadFormGatedFile($file);
    $settings = (array) $this->resolver->getGateForFile($entity)['settings'];
    $form_state->set('file_uuid', $entity->uuid());
    $form_state->set('settings', $settings);

    if (!empty($settings['intro_text'])) {
      $form['intro'] = ['#markup' => '<p>' . $this->t('@intro', ['@intro' => $settings['intro_text']]) . '</p>'];
    }
    $form['email'] = [
      '#type' => 'email',
      '#title' => $this->t('Email address'),
      '#required' => TRUE,
    ];
    if (!empty($settings['require_consent'])) {
      $form['consent'] = [
        '#type' => 'checkbox',
        '#title' => $settings['consent_text'] ?: $this->t('I agree to be contacted about this download.'),
        '#required' => TRUE,
      ];
    }
    // Honeypot: humans never see this; bots that fill every field are rejected.
    // The field is deliberately NOT named "url"/"website"/"homepage" — those
    // map to browser-autofill / password-manager categories that would
    // populate the hidden field for a legitimate visitor and falsely trip it.
    $form['hp_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Leave this field blank'),
      '#required' => FALSE,
      '#attributes' => ['autocomplete' => 'off', 'tabindex' => '-1', 'aria-hidden' => 'true'],
      '#wrapper_attributes' => ['style' => 'position:absolute;left:-9999px;'],
    ];
    $form['actions'] = ['#type' => 'actions'];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Get download'),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    // Honeypot tripped ⇒ a bot. Reject without revealing why.
    if (trim((string) $form_state->getValue('hp_url')) !== '') {
      $form_state->setErrorByName('email', $this->t('Your submission could not be processed.'));
      return;
    }
    $ip = $this->getRequest()->getClientIp() ?? '0.0.0.0';
    if (!$this->flood->isAllowed('file_gate_form.submit', self::SUBMIT_LIMIT, self::SUBMIT_WINDOW, $ip)) {
      $form_state->setErrorByName('email', $this->t('Too many attempts. Please try again later.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $ip = $this->getRequest()->getClientIp() ?? '0.0.0.0';
    $this->flood->register('file_gate_form.submit', self::SUBMIT_WINDOW, $ip);

    $uuid = (string) $form_state->get('file_uuid');
    $file = $this->entityRepository->loadEntityByUuid('file', $uuid);
    if (!$file instanceof FileInterface) {
      return;
    }

    // Let the site persist the lead (File Gate stores nothing itself).
    $this->eventDispatcher->dispatch(new LeadCapturedEvent(
      $file,
      (string) $form_state->getValue('email'),
      (bool) $form_state->getValue('consent'),
    ));
    $this->logger->info('Capture form submitted for file @uuid.', ['@uuid' => $uuid]);

    // Record the per-session grant and hand the visitor to the download.
    $this->tempStoreFactory->get(FormGate::GRANT_COLLECTION)->set($uuid, $this->time->getRequestTime());
    $form_state->setRedirectUrl(Url::fromRoute('file_gate.download', [], ['query' => ['f' => $uuid]]));
  }

  /**
   * Loads a file by UUID, requiring it to be gated with the `form` method.
   *
   * @param string $uuid
   *   The file UUID from the route.
   *
   * @return \Drupal\file\FileInterface
   *   The file.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
   *   If the file is unknown or not gated with the form method.
   */
  private function loadFormGatedFile(string $uuid): FileInterface {
    $entity = $uuid !== '' ? $this->entityRepository->loadEntityByUuid('file', $uuid) : NULL;
    if (!$entity instanceof FileInterface) {
      throw new NotFoundHttpException();
    }
    $gate = $this->resolver->getGateForFile($entity);
    if ($gate === NULL || $gate['method'] !== 'form') {
      throw new NotFoundHttpException();
    }
    return $entity;
  }

}
