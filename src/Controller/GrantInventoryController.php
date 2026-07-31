<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\file_gate\SecretRegistryInterface;
use Drupal\file_gate\Service\FileGateAudit;
use Drupal\file_gate\Service\GrantInventory;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * List and bulk-revoke signed_url jti inventory (GH #44).
 *
 * Authenticated with the same shared secret as mint. Responses never include
 * secret material — only jti metadata.
 */
final class GrantInventoryController implements ContainerInjectionInterface {

  use SharedSecretAuthTrait;

  private const REDEMPTION_COLLECTION = 'file_gate_redemptions';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly FloodInterface $flood,
    private readonly KeyValueExpirableFactoryInterface $keyValueExpirableFactory,
    private readonly LoggerInterface $logger,
    private readonly SecretRegistryInterface $secrets,
    private readonly GrantInventory $inventory,
    private readonly FileGateAudit $audit,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('flood'),
      $container->get('keyvalue.expirable'),
      $container->get('logger.channel.file_gate'),
      $container->get('file_gate.secret_registry'),
      $container->get('file_gate.grant_inventory'),
      $container->get('file_gate.audit'),
    );
  }

  /**
   * Lists outstanding signed_url grants for a field.
   */
  public function list(Request $request): Response {
    $config = $this->configFactory->get('file_gate.settings');
    $auth = $this->authenticateSharedSecret(
      $request,
      $this->secrets,
      $this->flood,
      $this->logger,
      'file_gate.grants',
      (int) ($config->get('mint_flood_limit') ?: 50),
      (int) ($config->get('mint_flood_window') ?: 60),
    );
    if ($auth !== NULL) {
      return $auth;
    }
    $secret_id = $request->attributes->get('file_gate.secret_id');
    $secret_id = is_string($secret_id) && $secret_id !== '' ? $secret_id : NULL;

    $field = trim((string) $request->query->get('field', ''));
    if ($field === '') {
      return new JsonResponse(['error' => 'Query parameter "field" is required (entity_type.field_name).'], Response::HTTP_BAD_REQUEST);
    }
    if (!$this->secrets->allowsField($secret_id, $field)) {
      return new JsonResponse(['error' => 'Secret is not allowed for this field.'], Response::HTTP_FORBIDDEN);
    }
    $sh = trim((string) $request->query->get('sh', ''));
    $rows = $this->inventory->listForField($field, $secret_id, $sh);
    return new JsonResponse([
      'field' => $field,
      'count' => count($rows),
      'grants' => $rows,
    ]);
  }

  /**
   * Bulk-revokes signed_url jtis for a field.
   *
   * Body: field plus jtis list, or all true with optional sh filter.
   */
  public function revokeBulk(Request $request): Response {
    $config = $this->configFactory->get('file_gate.settings');
    $auth = $this->authenticateSharedSecret(
      $request,
      $this->secrets,
      $this->flood,
      $this->logger,
      'file_gate.grants_revoke',
      (int) ($config->get('mint_flood_limit') ?: 50),
      (int) ($config->get('mint_flood_window') ?: 60),
    );
    if ($auth !== NULL) {
      return $auth;
    }
    $secret_id = $request->attributes->get('file_gate.secret_id');
    $secret_id = is_string($secret_id) && $secret_id !== '' ? $secret_id : NULL;

    $data = json_decode($request->getContent(), TRUE);
    if (!is_array($data)) {
      return new JsonResponse(['error' => 'JSON body required.'], Response::HTTP_BAD_REQUEST);
    }
    $field = trim((string) ($data['field'] ?? ''));
    if ($field === '' || !$this->secrets->allowsField($secret_id, $field)) {
      return new JsonResponse(['error' => 'Valid "field" allowed for this secret is required.'], Response::HTTP_FORBIDDEN);
    }

    $sh = trim((string) ($data['sh'] ?? ''));
    $jtis = [];
    if (!empty($data['all'])) {
      foreach ($this->inventory->listForField($field, $secret_id, $sh) as $row) {
        $jtis[] = (string) $row['jti'];
      }
    }
    elseif (!empty($data['jtis']) && is_array($data['jtis'])) {
      $jtis = array_values(array_filter(array_map('strval', $data['jtis'])));
    }
    if ($jtis === []) {
      return new JsonResponse(['error' => 'Provide "jtis" or "all": true.'], Response::HTTP_BAD_REQUEST);
    }

    $ttl = max(60, (int) ($data['ttl'] ?? 86400 * 30));
    $store = $this->keyValueExpirableFactory->get(self::REDEMPTION_COLLECTION);
    $allowed = [];
    foreach ($this->inventory->listForField($field, $secret_id, $sh) as $row) {
      $allowed[(string) $row['jti']] = TRUE;
    }
    $revoked = 0;
    foreach ($jtis as $jti) {
      $jti = trim($jti);
      if ($jti === '' || empty($allowed[$jti])) {
        continue;
      }
      $store->setWithExpire($jti, PHP_INT_MAX, $ttl);
      $this->inventory->forget($jti, $field);
      $revoked++;
    }

    $this->audit->log('grants_revoke_bulk', [
      'field' => $field,
      'revoked' => $revoked,
    ]);
    $this->logger->info('Bulk-revoked @n signed_url jtis for field @field.', [
      '@n' => $revoked,
      '@field' => $field,
    ]);

    return new JsonResponse(['revoked' => $revoked], Response::HTTP_OK);
  }

}
