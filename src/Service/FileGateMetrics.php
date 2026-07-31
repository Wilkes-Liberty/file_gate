<?php

declare(strict_types=1);

namespace Drupal\file_gate\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Extension\ModuleHandlerInterface;

/**
 * Aggregates File Gate security and usage signals for the admin dashboard.
 *
 * Prefers the dblog table when the Database Logging module is enabled. When
 * dblog is absent, returns empty series so the UI can show a clear empty state
 * rather than inventing numbers.
 */
final class FileGateMetrics {

  /**
   * Constructs the metrics service.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   Database connection.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Module handler (dblog optional).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Time service.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Whether dblog is available as a data source.
   */
  public function hasDataSource(): bool {
    return $this->moduleHandler->moduleExists('dblog')
      && $this->database->schema()->tableExists('watchdog');
  }

  /**
   * Builds dashboard aggregates for the last N days.
   *
   * @param int $days
   *   Lookback window (clamped 1–90).
   *
   * @return array
   *   Keys: available, days, mints, deliveries, denials, auth_failures,
   *   by_day, top_files, by_method.
   */
  public function summary(int $days = 14): array {
    $days = max(1, min(90, $days));
    $empty = [
      'available' => FALSE,
      'days' => $days,
      'mints' => 0,
      'deliveries' => 0,
      'denials' => 0,
      'auth_failures' => 0,
      'by_day' => [],
      'top_files' => [],
      'by_method' => [],
    ];
    if (!$this->hasDataSource()) {
      return $empty;
    }

    $since = $this->time->getRequestTime() - ($days * 86400);
    $query = $this->database->select('watchdog', 'w')
      ->fields('w', ['wid', 'message', 'variables', 'timestamp', 'severity'])
      ->condition('w.type', 'file_gate')
      ->condition('w.timestamp', $since, '>=')
      ->orderBy('w.timestamp', 'DESC')
      ->range(0, 5000);
    $rows = $query->execute()->fetchAll();

    $mints = 0;
    $deliveries = 0;
    $denials = 0;
    $auth_failures = 0;
    $by_day = [];
    $file_counts = [];
    $method_counts = [];

    foreach ($rows as $row) {
      $vars = @unserialize($row->variables, ['allowed_classes' => FALSE]);
      if (!is_array($vars)) {
        $vars = [];
      }
      $message = (string) $row->message;
      $day = gmdate('Y-m-d', (int) $row->timestamp);
      if (!isset($by_day[$day])) {
        $by_day[$day] = ['date' => $day, 'mints' => 0, 'deliveries' => 0, 'denials' => 0];
      }

      if (str_starts_with($message, 'Minted ')) {
        $mints++;
        $by_day[$day]['mints']++;
        $method = (string) ($vars['@method'] ?? 'unknown');
        $method_counts[$method] = ($method_counts[$method] ?? 0) + 1;
        $uuid = (string) ($vars['@uuid'] ?? '');
        if ($uuid !== '') {
          $file_counts[$uuid] = ($file_counts[$uuid] ?? 0) + 1;
        }
      }
      elseif (str_starts_with($message, 'Delivered gated file')) {
        $deliveries++;
        $by_day[$day]['deliveries']++;
        $method = (string) ($vars['@method'] ?? 'unknown');
        // Strip parens form "(@method)" if already clean.
        $method = trim($method, " \t\n\r\0\x0B()");
        $method_counts[$method] = ($method_counts[$method] ?? 0) + 1;
        $uuid = (string) ($vars['@uuid'] ?? '');
        if ($uuid !== '') {
          $file_counts[$uuid] = ($file_counts[$uuid] ?? 0) + 1;
        }
      }
      elseif (str_contains($message, 'Denied gated download') || str_contains($message, 'Mint refused')) {
        $denials++;
        $by_day[$day]['denials']++;
      }
      elseif (str_contains($message, 'authentication failed')) {
        $auth_failures++;
        $denials++;
        $by_day[$day]['denials']++;
      }
    }

    ksort($by_day);
    arsort($file_counts);
    arsort($method_counts);

    $top_files = [];
    $i = 0;
    foreach ($file_counts as $uuid => $count) {
      $top_files[] = ['uuid' => $uuid, 'count' => $count];
      if (++$i >= 10) {
        break;
      }
    }
    $by_method = [];
    foreach ($method_counts as $method => $count) {
      $by_method[] = ['method' => $method, 'count' => $count];
    }

    return [
      'available' => TRUE,
      'days' => $days,
      'mints' => $mints,
      'deliveries' => $deliveries,
      'denials' => $denials,
      'auth_failures' => $auth_failures,
      'by_day' => array_values($by_day),
      'top_files' => $top_files,
      'by_method' => $by_method,
    ];
  }

}
