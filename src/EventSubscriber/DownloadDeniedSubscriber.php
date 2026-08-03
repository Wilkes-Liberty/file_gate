<?php

declare(strict_types=1);

namespace Drupal\file_gate\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Renders a self-contained 403 for a denied gated download.
 *
 * The download controller throws AccessDeniedHttpException for a rejected
 * grant (expired, spent, or tampered signature). Left to Drupal's default
 * exception handling that renders in the ACTIVE theme — for a signed-in staff
 * member that is the admin theme, producing a full-chrome "You are not
 * authorized to access this page" that reads as a fault rather than an expired
 * link (#66). This subscriber replaces that response, on the download route
 * only, with a minimal themeless page that is identical for anonymous and
 * authenticated visitors.
 *
 * It stays a 403 and discloses no grant state: expired, spent and tampered are
 * deliberately indistinguishable to the visitor, and a dead link is never
 * offered step-up. The controller's own security logging and flood accounting
 * have already run by the time the exception reaches here.
 */
final class DownloadDeniedSubscriber implements EventSubscriberInterface {

  /**
   * The download route this subscriber is scoped to.
   */
  private const ROUTE = 'file_gate.download';

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Priority 128: ahead of Drupal's format-specific exception subscribers so
    // the response is set before they theme the 403, but below the logging
    // subscribers so the access-denied is still recorded.
    return [KernelEvents::EXCEPTION => ['onException', 128]];
  }

  /**
   * Replaces the themed 403 for a denied download with a plain page.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The exception event.
   */
  public function onException(ExceptionEvent $event): void {
    if (!$event->getThrowable() instanceof AccessDeniedHttpException) {
      return;
    }
    if ($event->getRequest()->attributes->get('_route') !== self::ROUTE) {
      return;
    }

    $title = 'This download link is no longer valid';
    $body = 'The link may have expired or already been used. Request a new link and try again.';
    $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$title}</title>
<style>
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; color: #1a1a1a; background: #fafafa; }
main { max-width: 32rem; margin: 4rem auto; }
h1 { font-size: 1.5rem; margin: 0 0 .5rem; }
p { line-height: 1.5; margin: 0; color: #444; }
</style>
</head>
<body>
<main>
<h1>{$title}</h1>
<p>{$body}</p>
</main>
</body>
</html>
HTML;

    $response = new Response($html, Response::HTTP_FORBIDDEN);
    $response->headers->set('Content-Type', 'text/html; charset=UTF-8');
    $response->headers->set('Cache-Control', 'private, no-store');
    $event->setResponse($response);
  }

}
