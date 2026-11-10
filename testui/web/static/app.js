'use strict';

// Certificate Authentication Checker UI. Plain JavaScript, no build step. Every string that
// comes from the API or from the URL is inserted with textContent or a text node only, and so is
// every text from i18n.js.
(function () {
  const PENDING_KEY = 'certcheck.pending';
  const VERSION_KEY = 'certcheck.serverVersion';
  const LANG_KEY = 'certcheck.lang';
  const PENDING_MAX_AGE_MS = 5 * 60 * 1000;
  // One deadline for an API call, request and body read together. The server's write timeout is 30 s.
  const API_TIMEOUT_MS = 20 * 1000;
  // The report stays in English whatever the page language: it goes to Vocdoni support.
  const REPORT_TITLE = 'Vocdoni Certificate Authentication Checker - diagnostic report';
  const NEVER_REACHED_RESULT = 'Result: authentication step never reached the server';

  // The UI texts by language (i18n.js). With no saved choice, the browser's first language that
  // matches picks one; the other languages of Spain read Spanish, and Spanish is the fallback.
  const STRINGS = CERTCHECK_STRINGS;
  const LANGS = ['en', 'es', 'ca'];
  const FALLBACK_LANG = 'es';
  const SPANISH_TOO = ['gl', 'eu', 'ast', 'an', 'oc'];

  const VIEWS = ['start', 'working', 'success', 'error'];
  const HEADINGS = {
    start: 'start-heading',
    working: 'working-heading',
    success: 'success-heading',
    error: 'error-heading',
  };

  // The failure codes produced here and not by the server. The report gives their English message
  // where a server error gives the server's own.
  const CLIENT_CODES = ['invalid_state', 'invalid_or_expired', 'never_reached', 'network_error', 'timeout', 'bad_response', 'generic'];

  // The DNIe entry's English qualifier and clause, as the API serves them. They are shown in the
  // page language; the rest of every provider entry is official text and is shown as served.
  const DNIE_QUALIFIER = 'requires card reader';
  const DNIE_CLAUSE = 'the browser must already be able to use the card';

  // Recovery guidance per error code: the i18n.js guidance to show, in order.
  const TEMPORARY = ['temporary'];
  const NOT_SUPPORTED = ['not_supported'];
  const LINK_EXPIRED = ['link_expired'];
  const CHOOSE_CERTIFICATE = ['choose_certificate'];
  const GUIDANCE = {
    no_certificate: CHOOSE_CERTIFICATE,
    never_reached: CHOOSE_CERTIFICATE.concat(['never_reached']),
    provider_mismatch: ['provider_mismatch'],
    untrusted_issuer: NOT_SUPPORTED,
    invalid_chain: NOT_SUPPORTED,
    unsupported_profile: NOT_SUPPORTED,
    unsupported_purpose: NOT_SUPPORTED,
    weak_algorithm: NOT_SUPPORTED,
    expired: ['check_dates'],
    not_yet_valid: ['check_dates'],
    revoked: ['revoked'],
    revocation_unavailable: TEMPORARY,
    internal: TEMPORARY,
    rate_limited: TEMPORARY,
    store_full: TEMPORARY,
    network_error: TEMPORARY,
    timeout: TEMPORARY,
    revocation_unknown: ['revocation_unknown'],
    identity_invalid: ['identity_invalid'],
    identity_unsupported_document: ['identity_unsupported_document'],
    test_certificate: ['test_certificate'],
    invalid_or_expired: LINK_EXPIRED,
    invalid_state: LINK_EXPIRED,
  };
  const DEFAULT_GUIDANCE = ['default'];

  const $ = (id) => document.getElementById(id);

  let providersState = 'idle'; // idle, loading, ready, failed
  let providers = []; // the validated provider list, once ready
  let lastServerVersion = '';
  // The active dictionary, and what each view shows, so a language switch can re-render in place.
  let strings = STRINGS.es;
  let workingKey = 'working_preparing';
  let shownResult = null;
  let shownError = null; // { code, serverMessage, port }
  let copyNote = '';
  let fatal = false;

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
  // The prototype method, not the static one from ES2022: Safari before 15.4 lacks that.
  function lookup(table, key) {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
  }

  // The page text for key in the active language.
  function t(key) {
    return str(lookup(strings.text, key));
  }

  // text with each {name} replaced by values[name].
  function fill(text, values) {
    return text.replace(/\{([a-z]+)\}/g, (match, name) => str(lookup(values, name)));
  }

  function format(key, values) {
    return fill(t(key), values);
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

  // ---------- language ----------

  // The language choice outlives the session, so it lives in localStorage.
  function readSavedLanguage() {
    try {
      return localStorage.getItem(LANG_KEY);
    } catch (e) {
      return null;
    }
  }

  function saveLanguage(code) {
    try {
      localStorage.setItem(LANG_KEY, code);
    } catch (e) {
      // See writeStorage.
    }
  }

  function isLanguage(code) {
    return LANGS.indexOf(code) !== -1;
  }

  // The UI language for a browser language tag, by its primary subtag, or ''.
  function languageOf(tag) {
    const primary = str(tag).toLowerCase().split(/[-_]/)[0];
    if (isLanguage(primary)) {
      return primary;
    }
    return SPANISH_TOO.indexOf(primary) !== -1 ? 'es' : '';
  }

  // The saved choice, else the first of the browser's languages that matches, else Spanish.
  function detectLanguage() {
    const saved = readSavedLanguage();
    if (isLanguage(saved)) {
      return saved;
    }
    const preferred = navigator.languages && navigator.languages.length > 0 ? navigator.languages : [navigator.language];
    for (const tag of preferred) {
      const code = languageOf(tag);
      if (code) {
        return code;
      }
    }
    return FALLBACK_LANG;
  }

  // Makes code the active language and writes the page's fixed texts (data-i18n in index.html).
  function useLanguage(code) {
    strings = lookup(STRINGS, code);
    document.documentElement.lang = code;
    document.title = t('title');
    $('language').value = code;
    for (const node of document.querySelectorAll('[data-i18n]')) {
      node.textContent = t(node.getAttribute('data-i18n'));
    }
  }

  // The selector: saves the choice and re-renders every view in place, keeping what it shows.
  function changeLanguage() {
    const code = $('language').value;
    if (!isLanguage(code)) {
      return;
    }
    saveLanguage(code);
    try {
      useLanguage(code);
      if (fatal) {
        showFatal();
        $('language').focus();
        return;
      }
      renderProviders();
      $('working-text').textContent = t(workingKey);
      if (shownResult) {
        renderSuccess();
      }
      if (shownError) {
        renderErrorText();
      }
      $('copy-feedback').textContent = copyNote ? t(copyNote) : '';
      $('status').textContent = '';
    } catch (e) {
      showFatal();
    }
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
    // A plain abort() and a flag of our own: browsers older than abort(reason) (Chrome 98,
    // Firefox 97, Safari 15.4) ignore the reason and reject with an AbortError.
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      deadline.abort();
    }, API_TIMEOUT_MS);
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
    } catch (e) {
      throw timedOut ? new DOMException('API deadline exceeded', 'TimeoutError') : e;
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
  // breaks a renderer cannot leave the page on a view that never resolves. When that view throws
  // as well (a helper it shares is what failed), showFatal takes over.
  function guard(fn) {
    return async (...args) => {
      try {
        await fn(...args);
      } catch (e) {
        try {
          showClientError({ code: 'bad_response' });
        } catch (e2) {
          showFatal();
        }
      }
    };
  }

  // The last resort: a fixed message and a reload button in place of the views, written with plain
  // DOM calls and none of the helpers, tables or views above. The texts are plain reads from the
  // active dictionary; a language switch builds the panel again.
  function showFatal() {
    try {
      fatal = true;
      const panel = document.createElement('section');
      panel.id = 'view-fatal';
      panel.className = 'panel';
      const heading = document.createElement('h1');
      heading.id = 'error-heading'; // the error view's heading style; that view is removed below
      heading.tabIndex = -1;
      heading.textContent = strings.text.error_heading;
      const message = document.createElement('p');
      message.className = 'lede';
      message.textContent = strings.messages.bad_response;
      const reload = document.createElement('button');
      reload.className = 'pill primary';
      reload.type = 'button';
      reload.textContent = strings.text.start_again;
      reload.addEventListener('click', () => location.reload());
      panel.appendChild(heading);
      panel.appendChild(message);
      panel.appendChild(reload);
      const main = document.getElementById('main');
      main.textContent = '';
      main.appendChild(panel);
      heading.focus();
    } catch (e) {
      // Without a working DOM there is nothing left to show.
    }
  }

  // ---------- views ----------

  function showView(name, announcement) {
    for (const v of VIEWS) {
      $('view-' + v).hidden = v !== name;
    }
    $('status').textContent = announcement || '';
    $(HEADINGS[name]).focus();
  }

  function showWorking(key) {
    workingKey = key;
    $('working-text').textContent = t(key);
    showView('working', t(key));
  }

  // ---------- start view ----------

  function updateHint() {
    $('provider-hint').hidden = $('provider').value !== 'dnie';
  }

  // A provider's name or description as served, but for the DNIe entry's English part, which is
  // replaced by its text in the page language.
  function providerText(id, text, english, local) {
    return id === 'dnie' ? str(text).split(english).join(local) : str(text);
  }

  function providerOption(p) {
    const option = new Option(providerText(p.id, p.name, DNIE_QUALIFIER, t('dnie_qualifier')), str(p.id));
    if (p.description) {
      option.title = providerText(p.id, p.description, DNIE_CLAUSE, t('dnie_clause'));
    }
    return option;
  }

  // Fills the provider select in the active language, keeping the current choice.
  function fillProviders() {
    const select = $('provider');
    const chosen = select.value;
    select.replaceChildren();
    for (const p of providers.filter((x) => !x.beta)) {
      select.append(providerOption(p));
    }
    const beta = providers.filter((x) => x.beta);
    if (beta.length > 0) {
      const group = document.createElement('optgroup');
      group.label = t('beta');
      for (const p of beta) {
        group.append(providerOption(p));
      }
      select.append(group);
    }
    if (chosen) {
      select.value = chosen;
    }
    updateHint();
  }

  // The provider select and the start message for the current providersState.
  function renderProviders() {
    const failed = providersState === 'failed';
    startMessage(failed ? t('providers_failed') : '');
    if (providersState === 'ready') {
      fillProviders();
    } else if (providersState !== 'idle') {
      $('provider').replaceChildren(new Option(failed ? t('providers_unavailable') : t('providers_loading'), ''));
    }
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
    renderProviders();
    const select = $('provider');
    select.disabled = true;
    $('authenticate').disabled = true;
    try {
      const reply = await api('GET', '/api/v1/providers');
      if (reply.status !== 200 || !isProviderList(reply.body)) {
        throw new Error('bad providers reply');
      }
      providers = reply.body;
      fillProviders();
      providersState = 'ready';
      select.disabled = false;
      $('authenticate').disabled = false;
    } catch (e) {
      providersState = 'failed';
      renderProviders();
      $('status').textContent = t('providers_failed');
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
    showWorking('working_preparing');

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
      return t('row_represents');
    }
    if (role === 'public_employee') {
      return t('row_employer');
    }
    return t('row_organization');
  }

  function showSuccess(result) {
    shownResult = result;
    renderSuccess();
    showView('success', t('success_status'));
  }

  // The success rows of shownResult in the active language.
  function renderSuccess() {
    const result = shownResult;
    const dl = $('result-list');
    dl.replaceChildren();
    const id = result.identity || {};
    const doc = id.document || {};
    const profile = result.profile || {};
    const cert = result.certificate || {};
    const rev = result.revocation || {};
    const provider = result.provider || {};

    addRow(dl, t('row_full_name'), id.fullName);
    addRow(dl, t('row_given_names'), id.givenNames);
    addRow(dl, t('row_surnames'), id.surnames);
    addRow(dl, t('row_first_surname'), id.firstSurname);
    addRow(dl, t('row_second_surname'), id.secondSurname);
    addRow(dl, t('row_document'), [doc.type, doc.number].filter(Boolean).join(' '));
    addRow(dl, t('row_birth_date'), id.birthDate || t('birth_date_missing'));
    if (result.organization) {
      const org = result.organization;
      const text = org.identifier ? str(org.name) + ' (' + str(org.identifier) + ')' : str(org.name);
      addRow(dl, organizationLabel(profile.holderRole), text);
    }
    addRow(dl, t('provider_label'), providerText(provider.id, provider.name, DNIE_QUALIFIER, t('dnie_qualifier')));
    addRow(dl, t('row_profile'), profile.name);
    addRow(dl, t('row_issuer'), cert.issuer);
    addRow(dl, t('row_valid_until'), localDate(cert.notAfter));
    addRow(dl, t('row_revocation'), format('revocation_value', {
      method: str(rev.method).toUpperCase(),
      time: localDateTime(rev.checkedAt),
      source: str(rev.source),
    }));
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

  // view: { code, serverMessage, port, report }. The report is English and set once; the message
  // and guidance follow the language.
  function renderError(view) {
    shownError = view;
    renderErrorText();
    $('report').textContent = view.report.join('\n') + '\n';
    $('tech').open = false;
    copyNote = '';
    $('copy-feedback').textContent = '';
    showView('error', $('error-message').textContent);
  }

  function renderErrorText() {
    $('error-message').textContent = displayMessage(shownError.code, shownError.serverMessage);
    const guidance = $('error-guidance');
    guidance.replaceChildren();
    for (const line of guidanceFor(shownError.code, shownError.port)) {
      guidance.append(el('li', '', line));
    }
  }

  // The page's own message for a known code; else the server's English message; else the generic one.
  function displayMessage(code, serverMessage) {
    return lookup(strings.messages, code) || serverMessage || strings.messages.generic;
  }

  // The report's message: the server's own; else the English message of a client code; else the
  // English generic one.
  function reportMessage(code, serverMessage) {
    const english = STRINGS.en.messages;
    return serverMessage || (CLIENT_CODES.indexOf(code) !== -1 && lookup(english, code)) || english.generic;
  }

  function guidanceFor(code, port) {
    const lines = [];
    for (const name of lookup(GUIDANCE, code) || DEFAULT_GUIDANCE) {
      for (const line of lookup(strings.guidance, name) || []) {
        lines.push(fill(line, { port: port || t('unknown_port') }));
      }
    }
    return lines;
  }

  // An error the server reported. Full diagnostics, when present, drive the report.
  function showServerError(error, diagnostics, entry) {
    const code = str(error.code) || 'generic';
    const message = reportMessage(code, str(error.message));
    rememberVersion(diagnostics);
    let report;
    if (diagnostics) {
      report = reportHeader(diagnostics.diagnosticId, str(diagnostics.time) || new Date().toISOString(), diagnostics.serverVersion)
        .concat(serverReportLines({ code, message }, diagnostics));
    } else {
      report = reportHeader('', new Date().toISOString(), '')
        .concat(['Result: error ' + code + ' - ' + message], attemptLines(entry));
    }
    renderError({ code, serverMessage: str(error.message), port: entry ? entry.authPort : '', report });
  }

  // An error this page produced: create failed, bad reply, expired link, never reached.
  function showClientError(opts) {
    const code = opts.code;
    const entry = opts.entry || null;
    const message = reportMessage(code, opts.message);
    let attempt = [];
    if (entry) {
      attempt = attemptLines(entry);
    } else if (opts.provider) {
      attempt = ['Provider: ' + opts.provider];
    }
    const result = code === 'never_reached' ? NEVER_REACHED_RESULT : 'Result: error ' + code + ' - ' + message;
    const report = reportHeader(opts.diagnosticId || '', new Date().toISOString(), '').concat([result], attempt);
    renderError({ code, serverMessage: str(opts.message), port: entry ? entry.authPort : '', report });
  }

  async function copyReport() {
    const text = $('report').textContent;
    try {
      await navigator.clipboard.writeText(text);
      copyNote = 'copied';
    } catch (e) {
      const pre = $('report');
      $('tech').open = true;
      const range = document.createRange();
      range.selectNodeContents(pre);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      pre.focus();
      copyNote = 'copy_manually';
    }
    $('copy-feedback').textContent = t(copyNote);
    $('status').textContent = t(copyNote);
  }

  // ---------- page load ----------

  // "Start again" on the working view. The auth navigation may never replace this page (a blocked
  // port, a slow auth host, Esc), so this forgets the attempt and reloads: that also stops the
  // navigation and drops any reply still on its way. The URL is already / (init replaced the
  // fragment), so the reload redeems nothing.
  function startOver() {
    clearPending();
    location.reload();
  }

  async function redeem(code, entry) {
    showWorking('working_redeem');
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
    showWorking('working_pending');
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
    useLanguage(detectLanguage());
    // The selector starts hidden: without JavaScript it would do nothing.
    $('language').closest('.language').hidden = false;
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
  $('cancel').addEventListener('click', startOver);
  $('copy-report').addEventListener('click', copyReport);
  $('language').addEventListener('change', changeLanguage);

  const guardedInit = guard(init);

  // A page restored from the back/forward cache keeps its old state; run the load logic again.
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      guardedInit();
    }
  });

  guardedInit();
})();
