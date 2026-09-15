<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Unit;

use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileTargetResolver;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Unit tests for file/media UUID resolution on the mint and OTP paths.
 */
#[Group('file_gate')]
final class FileTargetResolverTest extends UnitTestCase {

  /**
   * A file UUID resolves to the managed file.
   */
  public function testResolveByFileUuid(): void {
    $file = $this->createMock(FileInterface::class);
    $repository = $this->createMock(EntityRepositoryInterface::class);
    $repository->expects($this->once())
      ->method('loadEntityByUuid')
      ->with('file', 'file-uuid')
      ->willReturn($file);

    $result = $this->resolver($repository)->resolve(['file' => 'file-uuid']);
    $this->assertSame($file, $result);
  }

  /**
   * An unknown file UUID is 404.
   */
  public function testUnknownFileIsNotFound(): void {
    $repository = $this->createMock(EntityRepositoryInterface::class);
    $repository->method('loadEntityByUuid')->willReturn(NULL);

    $result = $this->resolver($repository)->resolve(['file' => 'missing']);
    $this->assertError($result, Response::HTTP_NOT_FOUND, 'File not found.');
  }

  /**
   * A published media UUID resolves through the source field.
   */
  public function testResolveByMediaUuid(): void {
    $file = $this->createMock(FileInterface::class);
    $media = $this->media(TRUE, '42');
    $repository = $this->createMock(EntityRepositoryInterface::class);
    $repository->method('loadEntityByUuid')->with('media', 'media-uuid')->willReturn($media);

    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->expects($this->once())->method('load')->with(42)->willReturn($file);
    $entity_types = $this->createMock(EntityTypeManagerInterface::class);
    $entity_types->method('hasDefinition')->with('media')->willReturn(TRUE);
    $entity_types->method('getStorage')->with('file')->willReturn($storage);

    $result = $this->resolver($repository, $entity_types)->resolve(['media' => 'media-uuid']);
    $this->assertSame($file, $result);
  }

  /**
   * An unpublished media host is 409.
   */
  public function testUnpublishedMediaIsConflict(): void {
    $media = $this->media(FALSE, '42');
    $repository = $this->createMock(EntityRepositoryInterface::class);
    $repository->method('loadEntityByUuid')->willReturn($media);
    $entity_types = $this->createMock(EntityTypeManagerInterface::class);
    $entity_types->method('hasDefinition')->with('media')->willReturn(TRUE);

    $result = $this->resolver($repository, $entity_types)->resolve(['media' => 'media-uuid']);
    $this->assertError($result, Response::HTTP_CONFLICT, 'Media is not published.');
  }

  /**
   * A media entity with no source file is 422.
   */
  public function testMediaWithoutFileIsUnprocessable(): void {
    $media = $this->media(TRUE, NULL);
    $repository = $this->createMock(EntityRepositoryInterface::class);
    $repository->method('loadEntityByUuid')->willReturn($media);
    $entity_types = $this->createMock(EntityTypeManagerInterface::class);
    $entity_types->method('hasDefinition')->with('media')->willReturn(TRUE);

    $result = $this->resolver($repository, $entity_types)->resolve(['media' => 'media-uuid']);
    $this->assertError($result, Response::HTTP_UNPROCESSABLE_ENTITY, 'Media has no file.');
  }

  /**
   * An unknown media UUID is 404.
   */
  public function testUnknownMediaIsNotFound(): void {
    $repository = $this->createMock(EntityRepositoryInterface::class);
    $repository->method('loadEntityByUuid')->willReturn(NULL);
    $entity_types = $this->createMock(EntityTypeManagerInterface::class);
    $entity_types->method('hasDefinition')->with('media')->willReturn(TRUE);

    $result = $this->resolver($repository, $entity_types)->resolve(['media' => 'missing']);
    $this->assertError($result, Response::HTTP_NOT_FOUND, 'Media not found.');
  }

  /**
   * Media UUID without the Media module is treated as missing input.
   */
  public function testMediaWithoutModuleIsBadRequest(): void {
    $entity_types = $this->createMock(EntityTypeManagerInterface::class);
    $entity_types->method('hasDefinition')->with('media')->willReturn(FALSE);

    $result = $this->resolver(NULL, $entity_types)->resolve(['media' => 'media-uuid']);
    $this->assertError($result, Response::HTTP_BAD_REQUEST, 'Provide a "file" or "media" UUID.');
  }

  /**
   * Neither file nor media UUID is 400.
   */
  public function testMissingTargetIsBadRequest(): void {
    $result = $this->resolver()->resolve([]);
    $this->assertError($result, Response::HTTP_BAD_REQUEST, 'Provide a "file" or "media" UUID.');
  }

  /**
   * Builds the resolver under test.
   *
   * @param \Drupal\Core\Entity\EntityRepositoryInterface|null $repository
   *   Entity repository, or a mock when omitted.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface|null $entity_types
   *   Entity type manager, or a mock when omitted.
   *
   * @return \Drupal\file_gate\FileTargetResolver
   *   The resolver.
   */
  private function resolver(
    ?EntityRepositoryInterface $repository = NULL,
    ?EntityTypeManagerInterface $entity_types = NULL,
  ): FileTargetResolver {
    return new FileTargetResolver(
      $repository ?? $this->createMock(EntityRepositoryInterface::class),
      $entity_types ?? $this->createMock(EntityTypeManagerInterface::class),
    );
  }

  /**
   * A duck-typed media host (no hard Media dependency).
   *
   * @param bool $published
   *   Whether the host is published.
   * @param string|null $fid
   *   Source file id, or NULL when the media has no file.
   *
   * @return object
   *   A media-like object with getSource() and isPublished().
   */
  private function media(bool $published, ?string $fid): object {
    $source = new class($fid) {

      public function __construct(private readonly ?string $fid) {}

      /**
       * Returns the source field fid.
       */
      public function getSourceFieldValue(object $media): ?string {
        return $this->fid;
      }

    };
    return new class($published, $source) {

      public function __construct(
        private readonly bool $published,
        private readonly object $source,
      ) {}

      /**
       * Returns the media source.
       */
      public function getSource(): object {
        return $this->source;
      }

      /**
       * Whether the host is published.
       */
      public function isPublished(): bool {
        return $this->published;
      }

    };
  }

  /**
   * Asserts a JSON error response.
   *
   * @param mixed $result
   *   The resolver return value.
   * @param int $status
   *   Expected HTTP status.
   * @param string $message
   *   Expected error string.
   */
  private function assertError(mixed $result, int $status, string $message): void {
    $this->assertInstanceOf(JsonResponse::class, $result);
    $this->assertSame($status, $result->getStatusCode());
    $payload = json_decode($result->getContent(), TRUE);
    $this->assertSame($message, $payload['error'] ?? NULL);
  }

}
