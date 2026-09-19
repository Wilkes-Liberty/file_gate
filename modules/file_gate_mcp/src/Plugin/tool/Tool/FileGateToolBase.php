<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel\Service\McpExfiltrationGuard;
use Drupal\tool\ExecutableResult;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Shares access, rate limiting and refusal handling for File Gate tools.
 *
 * This module's own refusals are one fixed message. Caller input, exception
 * text, secret material, file paths and download URLs never reach a result.
 */
abstract class FileGateToolBase extends McpGovernedToolBase {

  use McpEntityToolTrait;

  /**
   * Permission every tool in this module requires.
   */
  public const PERMISSION = 'use file gate mcp tools';

  /**
   * Field storage key shape: entity_type.field_name.
   */
  protected const FIELD_KEY = '/^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$/D';

  /**
   * Largest JSON result a tool returns, in bytes.
   *
   * The resolved profile's response-size cap applies when it is lower.
   */
  protected const MAX_RESULT_BYTES = 131072;

  /**
   * Sentinel's response-size resolver, when the installed version has one.
   */
  protected ?McpExfiltrationGuard $exfiltrationGuard = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->exfiltrationGuard = $container->has('mcp_sentinel.exfiltration_guard')
      ? $container->get('mcp_sentinel.exfiltration_guard')
      : NULL;
    return $instance;
  }

  /**
   * Runs the operation against the module's own services.
   *
   * @param array $values
   *   Input values.
   *
   * @return array
   *   Result without secret material, paths or URLs.
   *
   * @throws \InvalidArgumentException
   *   When an input is not acceptable. The message is never relayed.
   */
  abstract protected function run(array $values): array;

  /**
   * Additional permissions a tool requires beyond the shared one.
   *
   * @return string[]
   *   Permission names.
   */
  protected function extraPermissions(): array {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedDiscoveryAccess(AccountInterface $account): AccessResultInterface {
    return $this->checkGovernedAccess([], $account);
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedAccess(array $values, AccountInterface $account): AccessResultInterface {
    return AccessResult::allowedIfHasPermissions(
      $account,
      array_merge([self::PERMISSION], $this->extraPermissions()),
    )->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    try {
      // ToolBase::execute() does not call access(). Recheck for PHP callers.
      if (!$this->checkAccess($values, $this->currentUser)) {
        return $this->refused();
      }
      $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
      if ($profile === NULL) {
        return $this->refused();
      }
      if ($limited = $this->checkRateLimit($profile, $this->getPluginId())) {
        return $limited;
      }
      $result = $this->run($values);
      if (strlen(json_encode($result, JSON_THROW_ON_ERROR)) > $this->resultLimit($profile)) {
        return $this->refused();
      }
      return ExecutableResult::success($this->t('File Gate operation completed.'), $result);
    }
    catch (\Throwable $exception) {
      // Record the failure class only. Messages can carry caller input.
      $this->logger->warning('File Gate tool @tool failed with @type at @source:@line.', [
        '@tool' => $this->getPluginId(),
        '@type' => get_class($exception),
        '@source' => basename($exception->getFile()),
        '@line' => $exception->getLine(),
      ]);
      return $this->refused();
    }
  }

  /**
   * The smaller of this module's ceiling and the profile's response-size cap.
   */
  protected function resultLimit(McpPolicyProfileInterface $profile): int {
    $cap = $this->exfiltrationGuard === NULL
      ? 0
      : (int) $this->exfiltrationGuard->effectiveResponseSizeCap($profile);
    return $cap > 0 ? min(static::MAX_RESULT_BYTES, $cap) : static::MAX_RESULT_BYTES;
  }

  /**
   * The refusal this module's own code returns.
   */
  protected function refused(): ExecutableResult {
    return ExecutableResult::failure($this->t('File Gate operation refused. Check permissions, inputs and limits.'));
  }

  /**
   * Validates a field storage key.
   *
   * @throws \InvalidArgumentException
   */
  protected function fieldKey(mixed $value): string {
    $key = is_string($value) ? trim($value) : '';
    if (!preg_match(self::FIELD_KEY, $key)) {
      throw new \InvalidArgumentException('Invalid field key.');
    }
    return $key;
  }

}
