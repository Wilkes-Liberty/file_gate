<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Kernel;

use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\StreamWrapper\PrivateStream;
use Drupal\Core\StreamWrapper\StreamWrapperInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\file_gate\Controller\DownloadController;
use Drupal\file_gate\Controller\MintController;
use Drupal\media\Entity\Media;
use Drupal\media\Entity\MediaType;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Gating a private file that is delivered through a Media entity.
 *
 * File Gate is media-optional: it gates the underlying private file field, so a
 * file wrapped in a Media source field is gated exactly like a bare file field.
 * The mint (and OTP) endpoints resolve a media UUID to its source file so a
 * decoupled front end can hand File Gate a media UUID it already knows.
 */
#[Group('file_gate')]
#[RunTestsInSeparateProcesses]
final class MediaGatingTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'file',
    'image',
    'media',
    'file_gate',
  ];

  /**
   * The signing secret used in the tests.
   */
  private const SECRET = 'file-gate-test-secret';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('file');
    $this->installEntitySchema('media');
    $this->installSchema('file', ['file_usage']);
    $this->installConfig(['field', 'file', 'media', 'file_gate']);

    $this->setSetting('file_private_path', $this->siteDirectory . '/private');
    $this->container->get('stream_wrapper_manager')
      ->registerWrapper('private', PrivateStream::class, StreamWrapperInterface::WRITE_VISIBLE);

    $this->config('file_gate.settings')->set('download_secret', self::SECRET)->save();

    // The media source field is a private file field, gated with signed_url.
    FieldStorageConfig::create([
      'entity_type' => 'media',
      'field_name' => 'field_media_file',
      'type' => 'file',
      'settings' => ['uri_scheme' => 'private'],
    ])
      ->setThirdPartySetting('file_gate', 'gated', TRUE)
      ->setThirdPartySetting('file_gate', 'method', 'signed_url')
      ->save();

    MediaType::create([
      'id' => 'document',
      'label' => 'Document',
      'source' => 'file',
      'source_configuration' => ['source_field' => 'field_media_file'],
    ])->save();

    FieldConfig::create([
      'entity_type' => 'media',
      'field_name' => 'field_media_file',
      'bundle' => 'document',
    ])->save();

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
  }

  /**
   * Creates a published media entity wrapping a private file.
   *
   * @param string $filename
   *   The file name under private://.
   * @param bool $published
   *   Whether the host media entity is published.
   *
   * @return \Drupal\media\Entity\Media
   *   The saved media entity.
   */
  private function createMedia(string $filename, bool $published = TRUE): Media {
    $directory = 'private://docs';
    \Drupal::service('file_system')->prepareDirectory($directory, FileSystemInterface::CREATE_DIRECTORY);
    $uri = 'private://docs/' . $filename;
    file_put_contents($uri, 'BYTES:' . $filename);

    $file = File::create(['uri' => $uri]);
    $file->setPermanent();
    $file->save();

    $media = Media::create([
      'bundle' => 'document',
      'name' => 'Doc ' . $filename,
      'status' => $published,
      'field_media_file' => ['target_id' => $file->id()],
    ]);
    $media->save();

    return $media;
  }

  /**
   * Minting by media UUID resolves the source file and signs a download URL.
   */
  public function testMintByMediaUuidGrantsDownload(): void {
    $media = $this->createMedia('report.pdf');
    $file = File::load($media->getSource()->getSourceFieldValue($media));

    $mint = $this->mint(['media' => $media->uuid()]);
    $this->assertSame(200, $mint->getStatusCode());
    $data = json_decode((string) $mint->getContent(), TRUE);
    // The signed URL is bound to the underlying FILE uuid, not the media uuid.
    $this->assertStringContainsString('f=' . $file->uuid(), $data['path']);

    // Redeeming the minted URL streams the gated file.
    $response = $this->download($this->queryFromPath($data['path']));
    $this->assertInstanceOf(BinaryFileResponse::class, $response);
    $this->assertSame(200, $response->getStatusCode());
  }

  /**
   * Minting by media UUID refuses an unpublished host (409).
   */
  public function testMintByUnpublishedMediaDenied(): void {
    $media = $this->createMedia('draft.pdf', FALSE);
    $this->assertSame(409, $this->mint(['media' => $media->uuid()])->getStatusCode());
  }

  /**
   * The download route for the resolved file still 404s when bytes are gone.
   */
  public function testDownloadOfMediaFileMissingBytes(): void {
    $media = $this->createMedia('gone.pdf');
    $file = File::load($media->getSource()->getSourceFieldValue($media));
    // Delete the bytes but keep the managed file + gated reference.
    unlink($file->getFileUri());

    $mint = $this->mint(['media' => $media->uuid()]);
    $query = $this->queryFromPath(json_decode((string) $mint->getContent(), TRUE)['path']);

    $this->expectException(NotFoundHttpException::class);
    $this->download($query);
  }

  /**
   * Mints for a resolved-file payload via the mint controller.
   *
   * @param array $payload
   *   The JSON payload, e.g. ['media' => '<uuid>'].
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The mint response.
   */
  private function mint(array $payload) {
    $request = Request::create('/api/file-gate/mint', 'POST', [], [], [], [], json_encode($payload));
    $request->headers->set('Authorization', 'Basic ' . base64_encode('mint:' . self::SECRET));
    return MintController::create($this->container)->mint($request);
  }

  /**
   * Parses a minted download path's query string into an array.
   *
   * @param string $path
   *   The minted, root-relative download path.
   *
   * @return array
   *   The parsed query parameters.
   */
  private function queryFromPath(string $path): array {
    $query = [];
    parse_str((string) parse_url($path, PHP_URL_QUERY), $query);
    return $query;
  }

  /**
   * Redeems a download request built from a query array.
   *
   * @param array $query
   *   The download query (f, exp, sig, …).
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   The download response.
   */
  private function download(array $query) {
    return DownloadController::create($this->container)
      ->download(Request::create('/api/file-gate/download', 'GET', $query));
  }

}
