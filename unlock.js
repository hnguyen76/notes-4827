'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const form = $('unlock-form');
  const input = $('access-password');
  const message = $('gate-message');
  const baseURL = new URL('./', location.href);
  const dashboardURL = new URL(location.pathname, location.origin).href;
  const objectURLs = new Map();
  const encoder = new TextEncoder();
  let bundle = null, key = null, release = null, refreshPromise = null;

  function decodeBase64(value, min, max) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid release.');
    const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
    if (bytes.length < min || bytes.length > max) throw new Error('Invalid release.');
    return bytes;
  }

  async function readRelease() {
    const response = await fetch(new URL('release.json', baseURL), {cache:'no-store', credentials:'omit', redirect:'error'});
    if (!response.ok) throw new Error('Release unavailable.');
    const candidate = await response.json();
    if (candidate.schemaVersion !== 1 || candidate.algorithm !== 'AES-256-GCM' || candidate.compression !== 'gzip' || candidate.iterations !== 600000 || candidate.ciphertext !== 'payload.bin' || typeof candidate.version !== 'string' || !/^[a-f0-9]{32}$/.test(candidate.version)) throw new Error('Invalid release.');
    decodeBase64(candidate.salt, 16, 64);
    decodeBase64(candidate.iv, 12, 12);
    return candidate;
  }

  function validateBundle(candidate, metadata) {
    const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
    if (!isObject(candidate) || candidate.schemaVersion !== 1 || candidate.version !== metadata.version) throw new Error('Invalid workspace.');
    for (const name of ['dashboardHTML','appJS','stylesCSS','reportHTML']) if (typeof candidate[name] !== 'string' || !candidate[name].length) throw new Error('Invalid workspace.');
    for (const name of ['model','report','audit','privateManifest','refreshStatus']) if (!isObject(candidate[name])) throw new Error('Invalid workspace.');
    const model = candidate.model, manifest = candidate.privateManifest, report = candidate.report, audit = candidate.audit.metadata, status = candidate.refreshStatus;
    const modelMeta = model.metadata;
    if (!isObject(modelMeta) || !isObject(audit) || !Array.isArray(model.jobs) || !Array.isArray(model.companies) || !model.companies.length) throw new Error('Invalid workspace model.');
    if (!/^[a-f0-9]{64}$/.test(manifest.snapshotId) || !/^[a-f0-9]{64}$/.test(manifest.sourceBatchId)) throw new Error('Invalid workspace manifest.');
    if (manifest.sourceBatchId !== modelMeta.sourceBatchId || manifest.sourceBatchId !== audit.sourceBatchId || report.snapshotId !== manifest.sourceBatchId) throw new Error('Mixed source batches.');
    if (manifest.jobCount !== model.jobs.length || status.jobs !== model.jobs.length || status.status !== 'success') throw new Error('Incomplete source batch.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(modelMeta.asOf) || [manifest.asOf, report.asOf, audit.asOf, status.asOf].some((value) => value !== modelMeta.asOf)) throw new Error('Mixed snapshot dates.');
    const processedAt = Date.parse(modelMeta.processedAtUtc);
    if (!Number.isFinite(processedAt) || [manifest.generatedAt, report.generatedAt, audit.processedAtUtc, status.processedAtUtc].some((value) => Date.parse(value) !== processedAt)) throw new Error('Mixed processing timestamps.');
    if (!/^data\/[A-Za-z0-9_-]+\.json$/.test(manifest.datasetPath) || manifest.compressedDatasetPath !== manifest.datasetPath + '.gz') throw new Error('Invalid workspace paths.');
    return candidate;
  }

  async function decryptRelease(metadata, decryptionKey) {
    const response = await fetch(new URL(metadata.ciphertext, baseURL), {cache:'no-store', credentials:'omit', redirect:'error'});
    if (!response.ok) throw new Error('Release unavailable.');
    const ciphertext = await response.arrayBuffer();
    if (ciphertext.byteLength < 17 || ciphertext.byteLength > 67108864) throw new Error('Invalid encrypted workspace.');
    const plaintext = await crypto.subtle.decrypt({name:'AES-GCM', iv:decodeBase64(metadata.iv,12,12), tagLength:128}, decryptionKey, ciphertext);
    const stream = new Blob([plaintext]).stream().pipeThrough(new DecompressionStream('gzip'));
    const candidate = await new Response(stream).json();
    return validateBundle(candidate, metadata);
  }

  function privateJSON(path) {
    if (!bundle) throw new Error('Workspace locked.');
    if (path === bundle.privateManifest.datasetPath || path === bundle.privateManifest.compressedDatasetPath) return bundle.model;
    switch (path) {
      case 'report.json': return bundle.report;
      case 'data/manifest.json': return bundle.privateManifest;
      case 'data/audit.json': return bundle.audit;
      case 'data/refresh-status.json': return bundle.refreshStatus;
      default: throw new Error('Unknown private asset.');
    }
  }

  function createURL(path, content, type) {
    const url = URL.createObjectURL(new Blob([content], {type}));
    objectURLs.set(path, url);
    return url;
  }

  function assetURL(path) {
    if (!bundle) throw new Error('Workspace locked.');
    if (objectURLs.has(path)) return objectURLs.get(path);
    if (path === 'report.html') {
      const doc = new DOMParser().parseFromString(bundle.reportHTML, 'text/html');
      doc.querySelectorAll('script,base,iframe,object,embed').forEach((element) => element.remove());
      doc.querySelectorAll('[src]').forEach((element) => element.removeAttribute('src'));
      doc.querySelectorAll('link').forEach((element) => element.remove());
      for (const anchor of doc.querySelectorAll('a[href]')) {
        const href = anchor.getAttribute('href');
        if (href === './' || href === 'index.html') anchor.href = dashboardURL;
        else if (href === 'data/audit.json') {anchor.href = assetURL('data/audit.json');anchor.download = 'audit.json';}
        else if (href && href.startsWith('#')) continue;
        else anchor.removeAttribute('href');
      }
      for (const element of doc.querySelectorAll('*')) for (const attr of [...element.attributes]) if (attr.name.startsWith('on')) element.removeAttribute(attr.name);
      const printButton = doc.querySelector('.toolbar button');
      if (printButton) printButton.id = 'private-report-print';
      const printScriptURL = objectURLs.get('report-print-script') || createURL('report-print-script', "document.getElementById('private-report-print')?.addEventListener('click',()=>window.print());", 'text/javascript');
      const script = doc.createElement('script');
      script.src = printScriptURL;
      doc.body.append(script);
      const referrer = doc.createElement('meta');
      referrer.name = 'referrer';referrer.content = 'no-referrer';doc.head.append(referrer);
      return createURL(path, '<!doctype html>\n' + doc.documentElement.outerHTML, 'text/html;charset=utf-8');
    }
    if (path === bundle.privateManifest.compressedDatasetPath) throw new Error('Compressed private downloads are unavailable.');
    return createURL(path, JSON.stringify(privateJSON(path)), 'application/json;charset=utf-8');
  }

  function releaseURLs() {
    for (const url of objectURLs.values()) URL.revokeObjectURL(url);
    objectURLs.clear();
  }

  async function refresh() {
    if (!bundle || !key || !release) throw new Error('Workspace locked.');
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const candidateRelease = await readRelease();
      if (candidateRelease.version === release.version) return false;
      if (candidateRelease.salt !== release.salt || candidateRelease.iterations !== release.iterations) throw new Error('Reload and enter the current password to update this workspace.');
      const candidateBundle = await decryptRelease(candidateRelease, key);
      // Authentication and all batch checks complete before replacing the active data.
      releaseURLs();
      bundle = candidateBundle;
      release = candidateRelease;
      return true;
    })();
    try {return await refreshPromise;} finally {refreshPromise = null;}
  }

  function lock() {
    key = null;bundle = null;release = null;
    releaseURLs();
    document.body.replaceChildren();
    location.reload();
  }

  async function showWorkspace() {
    const doc = new DOMParser().parseFromString(bundle.dashboardHTML, 'text/html');
    doc.querySelectorAll('script,iframe,object,embed,base').forEach((element) => element.remove());
    if (!doc.querySelector('.app-shell') || !doc.getElementById('view-scorecard')) throw new Error('Workspace shell unavailable.');
    const styles = document.createElement('style');
    styles.id = 'private-workspace-styles';
    styles.textContent = bundle.stylesCSS;
    document.head.append(styles);
    const adapter = Object.freeze({
      readJSON: async (path) => privateJSON(path),
      readModel: async () => {if (!bundle) throw new Error('Workspace locked.');return bundle.model;},
      assetURL,
      refresh,
    });
    Object.defineProperty(window, 'SecureAssets', {value:adapter, writable:false, configurable:false});
    document.body.replaceChildren(...[...doc.body.childNodes].map((node) => document.importNode(node,true)));
    document.body.className = 'secure-unlocked';
    const lockButton = document.createElement('button');
    lockButton.id = 'secure-lock';lockButton.type = 'button';lockButton.textContent = 'Lock workspace';
    lockButton.addEventListener('click',lock);
    document.body.append(lockButton);
    const script = document.createElement('script');
    const scriptURL = createURL('workspace-script', bundle.appJS, 'text/javascript');
    script.src = scriptURL;
    await new Promise((resolve,reject) => {script.onload = resolve;script.onerror = () => reject(new Error('Workspace application unavailable.'));document.body.append(script);});
  }

  $('show-password').addEventListener('click', () => {
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    $('show-password').textContent = visible ? 'Hide' : 'Show';
    $('show-password').setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    $('show-password').setAttribute('aria-pressed', String(visible));
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if ($('unlock-button').disabled) return;
    let password = input.value;
    input.value = '';
    if (!password) {message.textContent = 'Enter the workspace password.';input.focus();return;}
    input.disabled = true;$('unlock-button').disabled = true;$('show-password').disabled = true;
    $('unlock-spinner').hidden = false;$('unlock-label').textContent = 'Opening workspace';
    form.setAttribute('aria-busy','true');message.dataset.kind = 'loading';message.textContent = 'Checking access. This may take a moment.';
    try {
      if (!window.isSecureContext || !crypto.subtle || !('DecompressionStream' in window)) throw new Error('Use a current browser over HTTPS to unlock this workspace.');
      const metadata = await readRelease();
      const passwordBytes = encoder.encode(password);
      password = null;
      const material = await crypto.subtle.importKey('raw',passwordBytes,'PBKDF2',false,['deriveKey']);
      passwordBytes.fill(0);
      const candidateKey = await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:decodeBase64(metadata.salt,16,64),iterations:metadata.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
      const candidateBundle = await decryptRelease(metadata,candidateKey);
      bundle = candidateBundle;key = candidateKey;release = metadata;
      await showWorkspace();
    } catch (error) {
      key = null;bundle = null;release = null;releaseURLs();
      if (!document.getElementById('unlock-form')) {document.body.replaceChildren();location.reload();return;}
      document.getElementById('private-workspace-styles')?.remove();
      message.dataset.kind = 'error';
      message.textContent = error.message === 'Use a current browser over HTTPS to unlock this workspace.' ? error.message : 'Unable to unlock. Check the password and try again.';
      input.disabled = false;$('unlock-button').disabled = false;$('show-password').disabled = false;
      $('unlock-spinner').hidden = true;$('unlock-label').textContent = 'Unlock workspace';
      form.setAttribute('aria-busy','false');input.focus();
    } finally {password = null;input.value = '';}
  });
  window.addEventListener('pagehide', () => {input.value = '';key = null;bundle = null;release = null;releaseURLs();});
  window.addEventListener('pageshow', (event) => {if (event.persisted) location.reload();});
})();
