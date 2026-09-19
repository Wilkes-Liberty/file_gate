<?php

declare(strict_types=1);

namespace Drupal\file_gate_mcp\Plugin\tool\Tool;

use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Explains which gate applies to one file.
 */
#[Tool(
  id: 'file_gate_file_gate',
  label: new TranslatableMarkup('File Gate lookup for a file'),
  description: new TranslatableMarkup('For one file UUID or media UUID, report whether the file is gated, which field and method apply, and whether the plain /system/files URL can serve it. A gated file is served only through a minted grant, so the URL an upload or entity read returns will answer 403. Returns no file path, no URL, no grant and no method settings. Provide exactly one of file or media.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'file' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('File UUID'),
      description: new TranslatableMarkup('UUID of the file entity.'),
      required: FALSE,
      constraints: ['Uuid' => []],
    ),
    'media' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Media UUID'),
      description: new TranslatableMarkup('UUID of a media entity. Its source file is inspected.'),
      required: FALSE,
      constraints: ['Uuid' => []],
    ),
  ],
)]
final class FileLookupTool extends FileGateToolBase {

  private const UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD';

  /**
   * Gate resolver.
   */
  protected FileGateResolver $resolver;

  /**
   * Entity repository.
   */
  protected EntityRepositoryInterface $entityRepository;

  /**
   * Entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * Stream wrapper manager.
   */
  protected StreamWrapperManagerInterface $streamWrappers;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->resolver = $container->get('file_gate.resolver');
    $instance->entityRepository = $container->get('entity.repository');
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->streamWrappers = $container->get('stream_wrapper_manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function inputNames(): array {
    return ['file', 'media'];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $file_uuid = trim((string) ($values['file'] ?? ''));
    $media_uuid = trim((string) ($values['media'] ?? ''));
    if (($file_uuid === '') === ($media_uuid === '')) {
      throw new \InvalidArgumentException('Provide exactly one target.');
    }
    $uuid = $file_uuid !== '' ? $file_uuid : $media_uuid;
    if (!preg_match(self::UUID, $uuid)) {
      throw new \InvalidArgumentException('Invalid UUID.');
    }

    $media_published = NULL;
    $file = NULL;
    if ($file_uuid !== '') {
      $file = $this->entityRepository->loadEntityByUuid('file', $file_uuid);
    }
    elseif ($this->entityTypeManager->hasDefinition('media')) {
      // Duck-typed like FileTargetResolver, so this module never hard-depends
      // on Media and a site with another media implementation does not fatal.
      /** @var object|null $media */
      $media = $this->entityRepository->loadEntityByUuid('media', $media_uuid);
      if ($media !== NULL && method_exists($media, 'getSource')) {
        $media_published = method_exists($media, 'isPublished') ? (bool) $media->isPublished() : NULL;
        $fid = $media->getSource()->getSourceFieldValue($media);
        $file = $fid ? $this->entityTypeManager->getStorage('file')->load($fid) : NULL;
      }
    }
    if (!$file instanceof FileInterface) {
      return ['found' => FALSE];
    }

    $gate = $this->resolver->getGateForFile($file);
    $gated = $gate !== NULL;
    $result = [
      'found' => TRUE,
      'file' => (string) $file->uuid(),
      'scheme' => (string) $this->streamWrappers->getScheme((string) $file->getFileUri()),
      'gated' => $gated,
      'field' => $gated ? (string) $gate['field'] : NULL,
      'method' => $gated ? (string) $gate['method'] : NULL,
      'gated_fields' => $this->resolver->gatedFieldKeys($file),
      'system_files_url_serves_it' => !$gated,
      'how_to_download' => $gated
        ? 'A trusted front end mints a grant for this file and then redeems it on the download route. An MCP client cannot mint.'
        : 'Not gated. Normal file access rules apply.',
    ];
    if ($media_uuid !== '') {
      $result['media_published'] = $media_published;
      if ($gated && $media_published === FALSE) {
        $result['note'] = 'Minting by media UUID is refused while the media is unpublished.';
      }
    }
    return $result;
  }

}
