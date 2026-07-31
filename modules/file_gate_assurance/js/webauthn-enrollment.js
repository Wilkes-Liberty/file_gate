/**
 * @file
 * Browser WebAuthn registration ceremony for File Gate enrollment UI.
 *
 * Calls the existing JSON APIs (register/options, register, credentials/delete).
 * User handle defaults to the Drupal uid string (see enrollment form settings).
 */
(function (Drupal, drupalSettings, once) {
  'use strict';

  function b64urlToBuffer(b64) {
    const pad = '='.repeat((4 - (b64.length % 4)) % 4);
    const str = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      buf[i] = str.charCodeAt(i);
    }
    return buf.buffer;
  }

  function bufferToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function setStatus(el, msg, isError) {
    if (!el) {
      return;
    }
    el.hidden = false;
    el.textContent = msg;
    el.classList.toggle('messages--error', !!isError);
    el.classList.toggle('messages--status', !isError);
  }

  async function register(cfg, statusEl) {
    if (!window.PublicKeyCredential) {
      setStatus(statusEl, Drupal.t('This browser does not support WebAuthn.'), true);
      return;
    }
    setStatus(statusEl, Drupal.t('Requesting registration options…'), false);
    const optRes = await fetch(cfg.registerOptions, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const optBody = await optRes.json().catch(function () {
      return {};
    });
    if (!optRes.ok) {
      setStatus(statusEl, optBody.error || 'HTTP ' + optRes.status, true);
      return;
    }
    const options = optBody.options || {};
    if (options.challenge) {
      options.challenge = b64urlToBuffer(options.challenge);
    }
    if (options.user && options.user.id) {
      options.user.id = b64urlToBuffer(options.user.id);
    }
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(function (c) {
        c.id = b64urlToBuffer(c.id);
        return c;
      });
    }
    setStatus(statusEl, Drupal.t('Touch your authenticator…'), false);
    const cred = await navigator.credentials.create({ publicKey: options });
    if (!cred) {
      setStatus(statusEl, Drupal.t('No credential returned.'), true);
      return;
    }
    const payload = {
      challenge_id: optBody.challenge_id,
      label: '',
      credential: {
        id: cred.id,
        rawId: bufferToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
          attestationObject: bufferToB64url(cred.response.attestationObject),
        },
      },
    };
    setStatus(statusEl, Drupal.t('Saving credential…'), false);
    const res = await fetch(cfg.register, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(function () {
      return {};
    });
    if (!res.ok) {
      setStatus(statusEl, data.error || 'HTTP ' + res.status, true);
      return;
    }
    setStatus(statusEl, Drupal.t('Security key registered. Reloading…'), false);
    window.location.reload();
  }

  async function removeCred(cfg, credentialId, statusEl) {
    setStatus(statusEl, Drupal.t('Removing…'), false);
    const res = await fetch(cfg.delete, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential_id: credentialId }),
    });
    const data = await res.json().catch(function () {
      return {};
    });
    if (!res.ok) {
      setStatus(statusEl, data.error || 'HTTP ' + res.status, true);
      return;
    }
    window.location.reload();
  }

  Drupal.behaviors.fileGateWebauthnEnrollment = {
    attach: function (context) {
      const cfg = drupalSettings.fileGateWebauthn || {};
      const statusEl = context.querySelector
        ? context.querySelector('#file-gate-webauthn-status')
        : null;
      once('file-gate-webauthn-reg', '.file-gate-webauthn-register', context).forEach(
        function (btn) {
          btn.addEventListener('click', function (e) {
            e.preventDefault();
            register(cfg, statusEl).catch(function (err) {
              setStatus(
                statusEl,
                err && err.message ? err.message : String(err),
                true,
              );
            });
          });
        },
      );
      once('file-gate-webauthn-del', '.file-gate-webauthn-delete', context).forEach(
        function (btn) {
          btn.addEventListener('click', function (e) {
            e.preventDefault();
            const id = btn.getAttribute('data-credential-id') || '';
            if (!id) {
              return;
            }
            removeCred(cfg, id, statusEl).catch(function (err) {
              setStatus(
                statusEl,
                err && err.message ? err.message : String(err),
                true,
              );
            });
          });
        },
      );
    },
  };
})(Drupal, drupalSettings, once);
