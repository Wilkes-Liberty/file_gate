<?php

declare(strict_types=1);

namespace Drupal\file_gate;

use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\file\FileInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Resolves a mint/OTP payload to a managed file.
 *
 * Shared by MintController and OtpController so file UUID, media UUID, and
 * unpublished-host handling live in one place. The media path is duck-typed
 * so this module never hard-depends on Media.
 */
final class FileTargetResolver {

  /**
   * Constructs the resolver.
   *
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entityRepository
   *   The entity repository (resolves file/media UUIDs).
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(
    private readonly EntityRepositoryInterface $entityRepository,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Resolves the request payload to a managed file.
   *
   * @param array $data
   *   The decoded JSON body: {"file": "<uuid>"} or {"media": "<uuid>"}.
   *
   * @return \Drupal\file\FileInterface|\Symfony\Component\HttpFoundation\JsonResponse
   *   The resolved file, or a JsonResponse describing why it could not be
   *   resolved (404 unknown, 409 unpublished host, 422 no file, 400 bad input).
   */
  public function resolve(array $data): FileInterface|JsonResponse {
    // By file UUID (media-agnostic path).
    if (!empty($data['file']) && is_string($data['file'])) {
      $file = $this->entityRepository->loadEntityByUuid('file', $data['file']);
      return $file instanceof FileInterface
        ? $file
        : new JsonResponse(['error' => 'File not found.'], Response::HTTP_NOT_FOUND);
    }

    // By media UUID — only when the Media module is installed. Duck-typed so
    // the module never hard-depends on Media.
    if (!empty($data['media']) && is_string($data['media']) && $this->entityTypeManager->hasDefinition('media')) {
      $media = $this->entityRepository->loadEntityByUuid('media', $data['media']);
      if ($media === NULL || !method_exists($media, 'getSource')) {
        return new JsonResponse(['error' => 'Media not found.'], Response::HTTP_NOT_FOUND);
      }
      // Never mint for unpublished host content — the URL would be handed to
      // the public for something that is not yet public.
      if (method_exists($media, 'isPublished') && !$media->isPublished()) {
        return new JsonResponse(['error' => 'Media is not published.'], Response::HTTP_CONFLICT);
      }
      $fid = $media->getSource()->getSourceFieldValue($media);
      $file = $fid ? $this->entityTypeManager->getStorage('file')->load($fid) : NULL;
      return $file instanceof FileInterface
        ? $file
        : new JsonResponse(['error' => 'Media has no file.'], Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    return new JsonResponse(['error' => 'Provide a "file" or "media" UUID.'], Response::HTTP_BAD_REQUEST);
  }

}
