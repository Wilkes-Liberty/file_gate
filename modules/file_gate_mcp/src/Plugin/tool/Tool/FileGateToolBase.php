<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\tool\ExecutableResult;

/**
 * Shares access, rate limiting and refusal handling for File Gate tools.
 *
 * Every tool returns one fixed refusal message. Caller input, exception text,
 * secret material, file paths and download URLs never reach a result.
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
   */
  protected const MAX_RESULT_BYTES = 131072;

  /**
   * Input names this tool accepts.
   *
   * @return string[]
   *   Allowed input keys.
   */
  abstract protected function inputNames(): array;

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
      if (array_diff(array_keys($values), $this->inputNames())) {
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
      if (strlen(json_encode($result, JSON_THROW_ON_ERROR)) > static::MAX_RESULT_BYTES) {
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
   * The single refusal every tool returns.
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
