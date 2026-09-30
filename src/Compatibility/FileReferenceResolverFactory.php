<?php

declare(strict_types=1);

namespace Drupal\file_gate\Compatibility;

use Drupal\file\FileReferenceResolver as CoreFileReferenceResolver;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Selects core's resolver, or the revision-aware backport on older core.
 */
final class FileReferenceResolverFactory {

  /**
   * Creates the resolver without changing core service registrations.
   */
  public static function create(ContainerInterface $container): CoreFileReferenceResolver|FileReferenceResolver {
    if ($container->has(CoreFileReferenceResolver::class)) {
      return $container->get(CoreFileReferenceResolver::class);
    }
    return new FileReferenceResolver(
      $container->get('entity_type.manager'),
      $container->get('file.usage'),
    );
  }

}
