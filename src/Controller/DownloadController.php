<?php

declare(strict_types=1);

namespace Drupal\file_gate\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityRepositoryInterface;
use Drupal\file\FileInterface;
use Drupal\file_gate\FileGateResolver;
use Drupal\file_gate\GateMethodManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\HeaderUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Streams a gated file to a request that satisfies its gate.
 *
 * This is the module's own delivery channel — deliberately NOT /system/files.
 * Streaming here (a) removes any dependence on core's permissive private-file
 * access (which grants anonymous download whenever the referencing entity is
 * viewable), and (b) never exposes the private:// path. The gate is enforced by
 * delegating to the file's configured gate method.
 */
final class DownloadController implements ContainerInjectionInterface {

  /**
   * Constructs the download controller.
   *
   * @param \Drupal\Core\Entity\EntityRepositoryInterface $entityRepository
   *   The entity repository (resolves the file UUID).
   * @param \Drupal\file_gate\FileGateResolver $resolver
   *   The gate resolver.
   * @param \Drupal\file_gate\GateMethodManager $gateMethodManager
   *   The gate method plugin manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The File Gate logger channel.
   */
  public function __construct(
    private readonly EntityRepositoryInterface $entityRepository,
    private readonly FileGateResolver $resolver,
    private readonly GateMethodManager $gateMethodManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity.repository'),
      $container->get('file_gate.resolver'),
      $container->get('plugin.manager.file_gate.gate_method'),
      $container->get('config.factory'),
      $container->get('logger.channel.file_gate'),
    );
  }

  /**
   * Validates the request's grant and streams the file.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request. Expects a "f" query parameter (the file UUID) plus whatever
   *   the gate method needs (for signed_url: "exp" and "sig").
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A binary file response on success.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
   *   If the file is unknown, missing on disk, or not gated.
   * @throws \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
   *   If the request does not satisfy the gate.
   */
  public function download(Request $request): Response {
    $uuid = (string) $request->query->get('f', '');
    if ($uuid === '') {
      throw new NotFoundHttpException();
    }

    $file = $this->entityRepository->loadEntityByUuid('file', $uuid);
    if (!$file instanceof FileInterface) {
      throw new NotFoundHttpException();
    }

    // Only files that are actually gated may be delivered through this route;
    // it must never become an open proxy for arbitrary private files.
    $gate = $this->resolver->getGateForFile($file);
    if ($gate === NULL) {
      throw new NotFoundHttpException();
    }

    $method = $this->gateMethodManager->createInstance($gate['method'], $gate['settings']);
    if (!$method->grants($file, $request)) {
      // Security event: a request reached a gated file without a valid grant
      // (missing/expired/tampered signature, or a spent one-time link).
      $this->logger->warning('Denied gated download of file @uuid (@method) from @ip: grant rejected.', [
        '@uuid' => $file->uuid(),
        '@method' => $gate['method'],
        '@ip' => $request->getClientIp() ?? 'unknown',
      ]);
      throw new AccessDeniedHttpException();
    }

    $uri = (string) $file->getFileUri();
    if (!is_file($uri)) {
      // The reference is gated and the grant is valid, but the bytes are gone.
      throw new NotFoundHttpException();
    }

    $disposition = $this->configFactory->get('file_gate.settings')->get('disposition') === 'inline'
      ? ResponseHeaderBag::DISPOSITION_INLINE
      : ResponseHeaderBag::DISPOSITION_ATTACHMENT;

    $response = new BinaryFileResponse($uri, Response::HTTP_OK, [], FALSE);
    $response->headers->set('Content-Type', $file->getMimeType() ?: 'application/octet-stream');
    // Never cache a gated response anywhere: it was authorized for exactly one
    // grant/session, not for the public. Belt-and-braces with the route's
    // no_cache option and BinaryFileResponse being non-cacheable.
    $response->headers->set('Cache-Control', 'private, no-store, max-age=0');

    $filename = $file->getFilename() ?? 'download';
    // ASCII fallback for the Content-Disposition header (RFC 6266); the UTF-8
    // filename* parameter is added automatically by makeDisposition().
    $fallback = preg_replace('/[^A-Za-z0-9._-]+/', '_', $filename) ?: 'download';
    $response->headers->set('Content-Disposition', HeaderUtils::makeDisposition($disposition, $filename, $fallback));

    // Usage/stats event: a gated file was successfully delivered.
    $this->logger->info('Delivered gated file @uuid (@method) to @ip.', [
      '@uuid' => $file->uuid(),
      '@method' => $gate['method'],
      '@ip' => $request->getClientIp() ?? 'unknown',
    ]);

    return $response;
  }

}
