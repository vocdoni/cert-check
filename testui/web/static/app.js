'use strict';

// Certificate Authentication Checker UI. Plain JavaScript, no build step. Every string that
// comes from the API or from the URL is inserted with textContent or a text node only.
(function () {
  const PENDING_KEY = 'certcheck.pending';
  const VERSION_KEY = 'certcheck.serverVersion';
  const PENDING_MAX_AGE_MS = 5 * 60 * 1000;
  // One deadline for an API call, request and body read together. The server's write timeout is 30 s.
  const API_TIMEOUT_MS = 20 * 1000;
  const REPORT_TITLE = 'Vocdoni Certificate Authentication Checker - diagnostic report';
  const NEVER_REACHED_RESULT = 'Result: authentication step never reached the server';

  const VIEWS = ['start', 'working', 'success', 'error'];
  const HEADINGS = {
    start: 'start-heading',
    working: 'working-heading',
    success: 'success-heading',
    error: 'error-heading',
  };

  // Messages for failures that are produced here and not by the server.
  const CLIENT_MESSAGES = {
    invalid_state: 'This authentication link is no longer valid. Please start again.',
    invalid_or_expired: 'This authentication link is no longer valid. Please start again.',
    never_reached: 'The authentication step never reached our server.',
    network_error: 'We could not reach the server. Check your connection and try again.',
    timeout: 'The server took too long to answer.',
    bad_response: 'The server sent a reply this page could not understand.',
    generic: 'Something went wrong.',
  };

  const TEMPORARY = ['This looks temporary. Try again in a few minutes.'];
  const NOT_SUPPORTED = ['This type of certificate is not supported. Try another certificate.'];
  const LINK_EXPIRED = ['The link has expired. Start again.'];
  const CHOOSE_CERTIFICATE = [
    'When your browser asks, choose a certificate.',
    'Browsers only list certificates that are still valid and were issued by the selected provider. If no list appeared, check the expiry date of your certificate in the browser certificate manager.',
    'Browsers may remember an earlier choice. Close all browser windows and try again.',
  ];

  // Recovery guidance per error code. A function receives the auth port (or '').
  const GUIDANCE = {
    no_certificate: CHOOSE_CERTIFICATE,
    never_reached: (port) => CHOOSE_CERTIFICATE.concat([
      'The certificate selection may have been cancelled.',
      'The network may block port ' + (port || 'unknown') + '. Try another network.',
      'The browser may not have been able to use the certificate key.',
    ]),
    provider_mismatch: ['Select the provider that issued your certificate and try again.'],
    untrusted_issuer: NOT_SUPPORTED,
    invalid_chain: NOT_SUPPORTED,
    unsupported_profile: NOT_SUPPORTED,
    unsupported_purpose: NOT_SUPPORTED,
    weak_algorithm: NOT_SUPPORTED,
    expired: ['Renew the certificate, or check that the date and time on this device are correct.'],
    not_yet_valid: ['Renew the certificate, or check that the date and time on this device are correct.'],
    revoked: ['The certificate is revoked or suspended. Contact the organization that issued it.'],
    revocation_unavailable: TEMPORARY,
    internal: TEMPORARY,
    rate_limited: TEMPORARY,
    store_full: TEMPORARY,
    network_error: TEMPORARY,
    timeout: TEMPORARY,
    revocation_unknown: ['The issuer does not recognise this certificate. Contact the organization that issued it.'],
    identity_invalid: ['The identity data in this certificate could not be read in a supported form. Try another certificate.'],
    identity_unsupported_document: ['This certificate identifies its holder with a document other than a Spanish DNI or NIE. Try another certificate.'],
    test_certificate: ['This is a test or specimen certificate. Try a real personal certificate.'],
    invalid_or_expired: LINK_EXPIRED,
    invalid_state: LINK_EXPIRED,
  };
  const DEFAULT_GUIDANCE = ['Try again. If the problem continues, send the diagnostic report to Vocdoni support.'];

  const $ = (id) => document.getElementById(id);

  let providersState = 'idle'; // idle, loading, ready, failed
  let lastServerVersion = '';

  // ---------- small helpers ----------

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = text;
    }
    return node;
  }

  function str(value) {
    return value === undefined || value === null ? '' : String(value);
  }

  // Own-property lookup for the code tables. A code comes from the URL fragment or the API, so a
  // plain table[code] would answer "__proto__" or "constructor" with Object.prototype or Object.
  function lookup(table, key) {
    return Object.hasOwn(table, key) ? table[key] : undefined;
  }

  function list(values) {
    return Array.isArray(values) && values.length > 0 ? values.map(str).join(', ') : 'none';
  }

  function pad(n) {
    return String(n).padStart(2, '0');
  }

  function localDate(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
      return str(iso);
    }
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  function localDateTime(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) {
      return str(iso);
    }
    return localDate(iso) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function readStorage(key) {
    try {
      return sessionStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function writeStorage(key, value) {
    try {
      sessionStorage.setItem(key, value);
    } catch (e) {
      // Storage can be unavailable (private mode); the flow still works without it.
    }
  }

  function removeStorage(key) {
    try {
      sessionStorage.removeItem(key);
    } catch (e) {
      // See writeStorage.
    }
  }

  function readPending() {
    const raw = readStorage(PENDING_KEY);
    if (!raw) {
      return null;
    }
    try {
      const p = JSON.parse(raw);
      if (p && typeof p.provider === 'string' && typeof p.authHost === 'string' && typeof p.createdAt === 'number') {
        return p;
      }
    } catch (e) {
      // A damaged entry is dropped below.
    }
    removeStorage(PENDING_KEY);
    return null;
  }

  function clearPending() {
    removeStorage(PENDING_KEY);
  }

  function rememberVersion(diagnostics) {
    if (diagnostics && diagnostics.serverVersion) {
      lastServerVersion = String(diagnostics.serverVersion);
      writeStorage(VERSION_KEY, lastServerVersion);
    }
  }

  // Rejects with a TimeoutError when the server does not finish its reply in API_TIMEOUT_MS. Nothing
  // here retries: a redemption code is single use, so the user starts again instead.
  async function api(method, path, body) {
    const deadline = new AbortController();
    const init = {
      method, credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' }, signal: deadline.signal,
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const timer = setTimeout(() => deadline.abort(new DOMException('API deadline exceeded', 'TimeoutError')), API_TIMEOUT_MS);
    try {
      const res = await fetch(path, init);
      // A stalled or failed body read rejects here, under the same deadline.
      const text = await res.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        // The body is not JSON; callers treat a null body as a bad reply.
      }
      return { status: res.status, body: json };
    } finally {
      clearTimeout(timer);
    }
  }

  // The error code for a request that produced no reply: the deadline, or the network.
  function failureCode(e) {
    return e && e.name === 'TimeoutError' ? 'timeout' : 'network_error';
  }

  // ---------- reply validation ----------

  // These check the shapes the renderers read. A reply that fails them is shown as bad_response.

  function isObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  // null and undefined both stand for an absent member (Go marshals a nil pointer or slice as null).
  function isOptionalObject(v) {
    return v === undefined || v === null || isObject(v);
  }

  function isOptionalObjectList(v) {
    return v === undefined || v === null || (Array.isArray(v) && v.every(isObject));
  }

  function isApiError(e) {
    return isObject(e) && [e.code, e.message].every((v) => v === undefined || typeof v === 'string');
  }

  function isDiagnostics(d) {
    return d === undefined || d === null || (isObject(d) &&
      ['tls', 'certificate'].every((key) => isOptionalObject(d[key])) &&
      ['chain', 'profileCandidates', 'revocationAttempts'].every((key) => isOptionalObjectList(d[key])));
  }

  function isRedeemReply(body) {
    if (!isObject(body)) {
      return false;
    }
    if (body.status === 'success') {
      const r = body.result;
      return isObject(r) && isDiagnostics(r.diagnostics) &&
        ['provider', 'profile', 'identity', 'organization', 'certificate', 'revocation'].every((key) => isOptionalObject(r[key]));
    }
    return body.status === 'error' && isApiError(body.error) && isDiagnostics(body.diagnostics);
  }

  function isProviderList(providers) {
    return Array.isArray(providers) && providers.length > 0 &&
      providers.every((p) => isObject(p) && typeof p.id === 'string' && typeof p.name === 'string');
  }

  // Runs an async entry point. Whatever it throws ends in the bad_response view, so a reply that
  // breaks a renderer cannot leave the page on a view that never resolves.
  function guard(fn) {
    return async (...args) => {
      try {
        await fn(...args);
      } catch (e) {
        showClientError({ code: 'bad_response' });
      }
    };
  }

  // ---------- views ----------

  function showView(name, announcement) {
    for (const v of VIEWS) {
      $('view-' + v).hidden = v !== name;
    }
    $('status').textContent = announcement || '';
    $(HEADINGS[name]).focus();
  }

  function showWorking(text) {
    $('working-text').textContent = text;
    showView('working', text);
  }

  // ---------- start view ----------

  function updateHint() {
    $('provider-hint').hidden = $('provider').value !== 'dnie';
  }

  function providerOption(p) {
    const option = new Option(str(p.name), str(p.id));
    if (p.description) {
      option.title = str(p.description);
    }
    return option;
  }

  function fillProviders(providers) {
    const select = $('provider');
    select.replaceChildren();
    for (const p of providers.filter((x) => !x.beta)) {
      select.append(providerOption(p));
    }
    const beta = providers.filter((x) => x.beta);
    if (beta.length > 0) {
      const group = document.createElement('optgroup');
      group.label = 'Beta';
      for (const p of beta) {
        group.append(providerOption(p));
      }
      select.append(group);
    }
    updateHint();
  }

  function startMessage(text) {
    const box = $('start-message');
    box.textContent = text || '';
    box.hidden = !text;
  }

  async function loadProviders() {
    if (providersState === 'loading' || providersState === 'ready') {
      return;
    }
    providersState = 'loading';
    startMessage('');
    const select = $('provider');
    select.replaceChildren(new Option('Loading providers…', ''));
    select.disabled = true;
    $('authenticate').disabled = true;
    try {
      const reply = await api('GET', '/api/v1/providers');
      if (reply.status !== 200 || !isProviderList(reply.body)) {
        throw new Error('bad providers reply');
      }
      fillProviders(reply.body);
      providersState = 'ready';
      select.disabled = false;
      $('authenticate').disabled = false;
    } catch (e) {
      providersState = 'failed';
      select.replaceChildren(new Option('Providers unavailable', ''));
      const text = 'We could not load the list of certificate providers. Reload the page to try again.';
      startMessage(text);
      $('status').textContent = text;
    }
  }

  function showStart() {
    showView('start');
    if (providersState === 'ready') {
      $('authenticate').disabled = false;
    }
    loadProviders();
  }

  function parseAuthUrl(value) {
    try {
      const u = new URL(value);
      const loopback = u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '[::1]';
      if (u.protocol === 'https:' || (u.protocol === 'http:' && loopback)) {
        return u;
      }
    } catch (e) {
      // Not a URL; rejected below.
    }
    return null;
  }

  async function authenticate() {
    const select = $('provider');
    const provider = select.value;
    if (!provider) {
      return;
    }
    const providerName = select.selectedOptions.length > 0 ? select.selectedOptions[0].text : provider;
    $('authenticate').disabled = true;
    showWorking('Preparing…');

    let reply;
    try {
      reply = await api('POST', '/api/v1/transactions', { provider });
    } catch (e) {
      showClientError({ code: failureCode(e), provider });
      return;
    }
    const body = reply.body;
    if (reply.status === 201 && body && typeof body.authUrl === 'string') {
      const url = parseAuthUrl(body.authUrl);
      if (url) {
        const port = url.port || (url.protocol === 'https:' ? '443' : '80');
        writeStorage(PENDING_KEY, JSON.stringify({
          provider,
          providerName,
          createdAt: Date.now(),
          authHost: url.hostname,
          authPort: Number(port),
          expiresAt: str(body.expiresAt),
        }));
        location.assign(url.href);
        return;
      }
      showClientError({ code: 'bad_response', provider });
      return;
    }
    if (isObject(body) && body.status === 'error' && isApiError(body.error)) {
      showClientError({ code: str(body.error.code) || 'generic', message: str(body.error.message), provider });
      return;
    }
    showClientError({ code: 'bad_response', provider });
  }

  // ---------- success view ----------

  function addRow(dl, label, value) {
    const text = str(value);
    if (!text) {
      return;
    }
    const row = el('div');
    row.append(el('dt', '', label), el('dd', '', text));
    dl.append(row);
  }

  function organizationLabel(role) {
    if (role === 'representative') {
      return 'Represents';
    }
    if (role === 'public_employee') {
      return 'Employer';
    }
    return 'Organization';
  }

  function showSuccess(result) {
    const dl = $('result-list');
    dl.replaceChildren();
    const id = result.identity || {};
    const doc = id.document || {};
    const profile = result.profile || {};
    const cert = result.certificate || {};
    const rev = result.revocation || {};

    addRow(dl, 'Full name', id.fullName);
    addRow(dl, 'Given name(s)', id.givenNames);
    addRow(dl, 'Surname(s)', id.surnames);
    addRow(dl, 'First surname', id.firstSurname);
    addRow(dl, 'Second surname', id.secondSurname);
    addRow(dl, 'Document', [doc.type, doc.number].filter(Boolean).join(' '));
    addRow(dl, 'Birth date', id.birthDate || 'Not included in this certificate');
    if (result.organization) {
      const org = result.organization;
      const text = org.identifier ? str(org.name) + ' (' + str(org.identifier) + ')' : str(org.name);
      addRow(dl, organizationLabel(profile.holderRole), text);
    }
    addRow(dl, 'Certificate provider', (result.provider || {}).name);
    addRow(dl, 'Profile', profile.name);
    addRow(dl, 'Issuer', cert.issuer);
    addRow(dl, 'Valid until', localDate(cert.notAfter));
    addRow(dl, 'Revocation check',
      str(rev.method).toUpperCase() + ', checked ' + localDateTime(rev.checkedAt) + ', source ' + str(rev.source));

    showView('success', 'Success. Your certificate was accepted.');
  }

  // ---------- error view and report ----------

  function reportHeader(diagnosticId, time, version) {
    return [
      REPORT_TITLE,
      'Diagnostic ID: ' + (diagnosticId || 'not available'),
      'Time: ' + time,
      'Page: ' + location.origin + location.pathname,
      'User agent: ' + navigator.userAgent,
      'Server version: ' + (version || lastServerVersion || 'unknown'),
      '',
    ];
  }

  function pushOptional(lines, label, value) {
    if (value) {
      lines.push(label + ': ' + value);
    }
  }

  // The server part of the report, built only from the diagnostics object.
  function serverReportLines(error, d) {
    const lines = [];
    lines.push('Result: error ' + str(error.code || d.code) + ' - ' + str(error.message));
    pushOptional(lines, 'Failed step', str(d.failedStep));
    pushOptional(lines, 'Provider', str(d.provider));
    pushOptional(lines, 'Technical detail', str(d.technicalDetail));

    const tls = d.tls;
    if (tls) {
      lines.push('TLS: ' + str(tls.version) + ' ' + str(tls.cipherSuite) + ' SNI=' + str(tls.sni) +
        ' client certificate=' + (tls.clientCertificatePresented ? 'yes' : 'no') +
        ' chain length=' + str(tls.chainLength));
    }

    const c = d.certificate;
    if (c) {
      lines.push('Certificate:');
      lines.push('  Subject: ' + str(c.subject));
      lines.push('  Issuer: ' + str(c.issuer));
      lines.push('  Serial: ' + str(c.serialHex));
      lines.push('  Valid: ' + str(c.notBefore) + ' to ' + str(c.notAfter));
      lines.push('  SHA-256: ' + str(c.sha256));
      lines.push('  Key: ' + str(c.keyAlgorithm) + '   Signature: ' + str(c.signatureAlgorithm));
      lines.push('  Key usage: ' + list(c.keyUsage) + '   Extended key usage: ' + list(c.extKeyUsage));
      lines.push('  Policies: ' + list(c.policyOids));
      lines.push('  Critical extensions: ' + list(c.criticalExtensions));
      lines.push('  OCSP: ' + list(c.ocspUrls) + '   CA issuers: ' + list(c.caIssuerUrls) + '   CRL: ' + list(c.cdpUrls));
    }

    if (Array.isArray(d.chain) && d.chain.length > 0) {
      lines.push('Chain received:');
      d.chain.forEach((entry, i) => {
        lines.push('  [' + i + '] ' + str(entry.subject) + ' / issued by ' + str(entry.issuer));
      });
    }

    if (Array.isArray(d.profileCandidates) && d.profileCandidates.length > 0) {
      lines.push('Profile candidates:');
      for (const cand of d.profileCandidates) {
        lines.push('  ' + str(cand.profileId) + ': ' + str(cand.result));
      }
    }

    if (Array.isArray(d.revocationAttempts) && d.revocationAttempts.length > 0) {
      lines.push('Revocation attempts:');
      for (const a of d.revocationAttempts) {
        const parts = [str(a.method), str(a.url), 'HTTP ' + str(a.httpStatus), str(a.durationMs) + ' ms', str(a.outcome)];
        if (a.detail) {
          parts.push(str(a.detail));
        }
        parts.push('thisUpdate=' + (a.thisUpdate || 'none'));
        parts.push('nextUpdate=' + (a.nextUpdate || 'none'));
        parts.push('responder=' + (a.responderSubject || 'none'));
        parts.push('nonce=' + (a.nonceSent ? 'sent' : 'not sent') + '/' + (a.nonceEchoed ? 'echoed' : 'not echoed'));
        if (a.fromCache) {
          parts.push('from cache');
        }
        lines.push('  ' + parts.join(' '));
      }
    }
    return lines;
  }

  // The attempt data this page knows about (the pending entry), as report lines.
  function attemptLines(entry) {
    const lines = [];
    if (entry) {
      lines.push('Auth host: ' + entry.authHost + ':' + str(entry.authPort));
      pushOptional(lines, 'Provider', str(entry.provider));
      lines.push('Started: ' + new Date(entry.createdAt).toISOString());
    }
    return lines;
  }

  function renderError(view) {
    $('error-message').textContent = view.message;
    const guidance = $('error-guidance');
    guidance.replaceChildren();
    for (const line of view.guidance) {
      guidance.append(el('li', '', line));
    }
    $('report').textContent = view.report.join('\n') + '\n';
    $('tech').open = false;
    $('copy-feedback').textContent = '';
    showView('error', view.message);
  }

  function guidanceFor(code, port) {
    const g = lookup(GUIDANCE, code);
    if (typeof g === 'function') {
      return g(port);
    }
    return g || DEFAULT_GUIDANCE;
  }

  // An error the server reported. Full diagnostics, when present, drive the report.
  function showServerError(error, diagnostics, entry) {
    const code = str(error.code) || 'generic';
    const message = str(error.message) || lookup(CLIENT_MESSAGES, code) || CLIENT_MESSAGES.generic;
    rememberVersion(diagnostics);
    let report;
    if (diagnostics) {
      report = reportHeader(diagnostics.diagnosticId, str(diagnostics.time) || new Date().toISOString(), diagnostics.serverVersion)
        .concat(serverReportLines({ code, message }, diagnostics));
    } else {
      report = reportHeader('', new Date().toISOString(), '')
        .concat(['Result: error ' + code + ' - ' + message], attemptLines(entry));
    }
    renderError({ message, guidance: guidanceFor(code, entry ? entry.authPort : ''), report });
  }

  // An error this page produced: create failed, bad reply, expired link, never reached.
  function showClientError(opts) {
    const code = opts.code;
    const entry = opts.entry || null;
    const message = opts.message || lookup(CLIENT_MESSAGES, code) || CLIENT_MESSAGES.generic;
    let attempt = [];
    if (entry) {
      attempt = attemptLines(entry);
    } else if (opts.provider) {
      attempt = ['Provider: ' + opts.provider];
    }
    const result = code === 'never_reached' ? NEVER_REACHED_RESULT : 'Result: error ' + code + ' - ' + message;
    const report = reportHeader(opts.diagnosticId || '', new Date().toISOString(), '').concat([result], attempt);
    renderError({ message, guidance: guidanceFor(code, entry ? entry.authPort : ''), report });
  }

  async function copyReport() {
    const text = $('report').textContent;
    let note;
    try {
      await navigator.clipboard.writeText(text);
      note = 'Report copied to the clipboard.';
    } catch (e) {
      const pre = $('report');
      $('tech').open = true;
      const range = document.createRange();
      range.selectNodeContents(pre);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      pre.focus();
      note = 'Press Ctrl+C to copy';
    }
    $('copy-feedback').textContent = note;
    $('status').textContent = note;
  }

  // ---------- page load ----------

  async function redeem(code, entry) {
    showWorking('Checking your certificate…');
    let reply;
    try {
      reply = await api('POST', '/api/v1/transactions/redeem', { code });
    } catch (e) {
      clearPending();
      showClientError({ code: failureCode(e), entry });
      return;
    }
    clearPending();
    const body = reply.body;
    if (!isRedeemReply(body)) {
      showClientError({ code: 'bad_response', entry });
      return;
    }
    if (body.status === 'success') {
      rememberVersion(body.result.diagnostics);
      showSuccess(body.result);
      return;
    }
    showServerError(body.error, body.diagnostics, entry);
  }

  function showHashError(code, diag, entry) {
    const known = /^[a-z_]{1,40}$/.test(code) ? code : 'invalid_state';
    const diagnosticId = /^[0-9a-f]{8,64}$/i.test(diag || '') ? diag : '';
    clearPending();
    showClientError({ code: known, diagnosticId, entry });
  }

  async function detectPending(entry) {
    showWorking('Checking your last attempt…');
    let current = null;
    try {
      const reply = await api('GET', '/api/v1/transactions/current');
      current = reply.status === 200 ? reply.body : null;
    } catch (e) {
      current = null;
    }
    if (current && current.status === 'pending') {
      const port = typeof current.authPort === 'number' && current.authPort > 0 ? current.authPort : entry.authPort;
      const shown = Object.assign({}, entry, {
        authPort: port,
        authHost: str(current.authHost) || entry.authHost,
        provider: str(current.provider) || entry.provider,
      });
      clearPending();
      showClientError({ code: 'never_reached', entry: shown });
      return;
    }
    clearPending();
    if (current && current.status === 'completed') {
      showClientError({ code: 'invalid_or_expired', entry });
      return;
    }
    showStart();
  }

  async function init() {
    const params = new URLSearchParams(location.hash.slice(1));
    history.replaceState(null, '', '/');
    lastServerVersion = readStorage(VERSION_KEY) || lastServerVersion;

    const entry = readPending();
    const code = params.get('code');
    if (code) {
      await redeem(code, entry);
      return;
    }
    if (params.has('error')) {
      showHashError(params.get('error'), params.get('diag'), entry);
      return;
    }
    if (entry && Date.now() - entry.createdAt < PENDING_MAX_AGE_MS) {
      await detectPending(entry);
      return;
    }
    clearPending();
    showStart();
  }

  $('provider').addEventListener('change', updateHint);
  $('authenticate').addEventListener('click', guard(authenticate));
  $('again').addEventListener('click', showStart);
  $('retry').addEventListener('click', showStart);
  $('copy-report').addEventListener('click', copyReport);

  const guardedInit = guard(init);

  // A page restored from the back/forward cache keeps its old state; run the load logic again.
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      guardedInit();
    }
  });

  guardedInit();
})();
