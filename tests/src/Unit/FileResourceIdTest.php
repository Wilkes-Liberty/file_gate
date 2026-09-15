<?php

declare(strict_types=1);

namespace Drupal\Tests\file_gate\Unit;

use Drupal\Core\StreamWrapper\StreamWrapperManagerInterface;
use Drupal\Tests\UnitTestCase;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileResourceIdTrait;
use PHPUnit\Framework\Attributes\Group;

/**
 * Pins the HMAC resource-id format shared by SignedUrl and Token.
 */
#[Group('file_gate')]
final class FileResourceIdTest extends UnitTestCase {

  /**
   * Resource id is uuid plus the normalized stream URI.
   */
  public function testUuidPipeNormalizedUri(): void {
    $stream = $this->createMock(StreamWrapperManagerInterface::class);
    $stream->expects($this->once())
      ->method('normalizeUri')
      ->with('private://./report.pdf')
      ->willReturn('private://report.pdf');

    $file = $this->createMock(FileInterface::class);
    $file->method('uuid')->willReturn('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    $file->method('getFileUri')->willReturn('private://./report.pdf');

    $subject = new class ($stream) {
      use FileResourceIdTrait;

      /**
       * Constructs the test double.
       *
       * @param \Drupal\Core\StreamWrapper\StreamWrapperManagerInterface $stream
       *   Stream wrapper manager used to normalize the file URI.
       */
      public function __construct(StreamWrapperManagerInterface $stream) {
        $this->streamWrapperManager = $stream;
      }

      /**
       * Exposes the shared helper.
       */
      public function id(FileInterface $file): string {
        return $this->resourceId($file);
      }

    };

    $this->assertSame(
      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee|private://report.pdf',
      $subject->id($file),
    );
  }

}
