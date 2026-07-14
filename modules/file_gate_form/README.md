# File Gate Form

A **coupled** gate method for File Gate: Drupal itself renders a lightweight
email / lead-capture form and grants the download on submission. For traditional
(Twig-themed) and hybrid sites that want File Gate's fail-closed delivery without
building their own front-end gate.

The coupling is deliberately isolated in this optional submodule — the headless
path stays free of form/session assumptions. Enable it only if you want it.

## How it works

1. Link a gated file to `/file-gate/form/{file-uuid}` (instead of the direct
   download). The route renders the capture form.
2. On a valid submission the module records a **per-session grant** (in the
   private tempstore) for that file and redirects to the download.
3. The `form` gate method's `grants()` checks that grant, within its TTL, and
   streams the file. `mint()` returns `NULL` — access is decided live.

Gate a field with the `form` method and configure it on the field settings page
(or in YAML):

| Setting | Meaning |
|---|---|
| `ttl` | How long a submission keeps the download available, in seconds (default 3600). |
| `require_consent` | Show a required consent checkbox. |
| `consent_text` | The consent checkbox label. |
| `intro_text` | Text shown above the form. |

## Spam / abuse

The form includes a **honeypot** field and a **per-IP rate limit**. For stronger
protection, add the [CAPTCHA](https://www.drupal.org/project/captcha) module and
place it on the form via its admin UI — no code changes needed.

## Capturing leads

File Gate does **not** store submissions itself — keeping PII, consent, and
retention decisions with your site. On each valid submission the module
dispatches a `LeadCapturedEvent` (`\Drupal\file_gate_form\Event\LeadCapturedEvent`)
carrying the file, email, and consent flag. Subscribe to it to persist the lead
wherever you handle contacts — core Contact, Webform, or a CRM:

```php
use Drupal\file_gate_form\Event\LeadCapturedEvent;

final class MyLeadSubscriber implements EventSubscriberInterface {

  public static function getSubscribedEvents(): array {
    return [LeadCapturedEvent::class => 'onLead'];
  }

  public function onLead(LeadCapturedEvent $event): void {
    // $event->file, $event->email, $event->consent — store per your policy.
  }

}
```

## Notes

- Delivery is still the File Gate download route; the raw `/system/files` path
  stays denied. The form only records the grant.
- The grant is per session, so it is not shareable as a URL.
