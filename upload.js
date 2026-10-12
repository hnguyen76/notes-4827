'use strict';
(() => {
  // Fill in your deployed Cloudflare Worker URL after `wrangler deploy`
  // (see cloudflare/README.md). Example: https://data-upload.<subdomain>.workers.dev/upload
  const ENDPOINT = 'https://data-upload.hieumercer.workers.dev/upload';
  const MAX_BYTES = 20 * 1024 * 1024;
  const MAX_BATCH_BYTES = 40 * 1024 * 1024;
  const MULTIPART_ALLOWANCE = 64 * 1024;
  const EXPECTED_FILES = {
    scorecardCC: 'Scorecards_CC.xlsx',
    powerbiCC: 'PowerBI_CC.xlsx',
    scorecardGWPMG: 'Don_-_Scorecards_GWPMG.xls (1).xlsx',
    powerbiGWPMG: 'Don_-_PowerBI_GW.xls (1).xlsx',
    accounting: 'Don_PowerBI_Accounting.xls.xlsx',
    jobFields: 'Don_PowerBI_JobFields.xls.xlsx',
    participants: 'Don_PowerBI_Participants.xls.xlsx',
    dates: 'Don_PowerBI_Dates.xls (1).xlsx',
  };

  const $ = (id) => document.getElementById(id);
  const form = $('upload-form');
  const message = $('upload-message');
  const passwordInput = $('upload-password');
  const button = $('upload-button');
  const label = $('upload-label');
  const spinner = $('upload-spinner');

  form.querySelectorAll('input[type=file]').forEach((input) => {
    input.addEventListener('change', () => {
      const small = input.closest('.upload-slot').querySelector('.upload-filename');
      const file = input.files?.[0];
      small.textContent = file ? `${file.name} · ${(file.size / 1024).toFixed(0)} KB` : small.dataset.empty;
      small.classList.toggle('has-file', Boolean(file));
    });
  });

  $('upload-show-password').addEventListener('click', () => {
    const visible = passwordInput.type === 'password';
    passwordInput.type = visible ? 'text' : 'password';
    $('upload-show-password').textContent = visible ? 'Hide' : 'Show';
    $('upload-show-password').setAttribute('aria-pressed', String(visible));
  });

  function setBusy(busy, text) {
    button.disabled = busy;
    spinner.hidden = !busy;
    label.textContent = text;
    form.setAttribute('aria-busy', String(busy));
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (button.disabled) return;
    if (ENDPOINT.includes('YOUR-SUBDOMAIN')) {
      message.dataset.kind = 'error';
      message.textContent = 'Upload endpoint is not configured yet. Deploy the Cloudflare Worker and set ENDPOINT in upload.js.';
      return;
    }
    const inputs = [...form.querySelectorAll('input[type=file]')];
    const selection = inputs.map((input) => ({ field: input.name, file: input.files?.[0], supplemental: input.hasAttribute('data-supplemental') }));
    const missing = selection.find((entry) => !entry.supplemental && !entry.file);
    if (missing) { message.dataset.kind = 'error'; message.textContent = 'Select all four files before uploading.'; return; }
    const supplemental = selection.filter((entry) => entry.supplemental && entry.file);
    if (supplemental.length && supplemental.length !== 4) { message.dataset.kind = 'error'; message.textContent = 'Select all four supplemental exports, or leave the complete supplemental group empty.'; return; }
    const files = selection.filter((entry) => entry.file);
    const tooLarge = files.find((entry) => entry.file.size === 0 || entry.file.size > MAX_BYTES);
    if (tooLarge) { message.dataset.kind = 'error'; message.textContent = `${tooLarge.file.name} is empty or exceeds the 20 MiB file limit.`; return; }
    const wrongSlot = files.find((entry) => entry.file.name !== EXPECTED_FILES[entry.field]);
    if (wrongSlot) { message.dataset.kind = 'error'; message.textContent = `Wrong workbook in this slot. Select ${EXPECTED_FILES[wrongSlot.field]}.`; return; }
    if (files.reduce((sum, entry) => sum + entry.file.size, 0) + MULTIPART_ALLOWANCE > MAX_BATCH_BYTES) {
      message.dataset.kind = 'error'; message.textContent = 'The complete batch must fit within the 40 MiB upload limit.'; return;
    }
    const password = passwordInput.value;
    if (!password) { message.dataset.kind = 'error'; message.textContent = 'Enter the upload password.'; passwordInput.focus(); return; }

    const data = new FormData();
    for (const { field, file } of files) data.append(field, file, file.name);

    setBusy(true, 'Uploading');
    message.dataset.kind = 'loading';
    message.textContent = 'Uploading the batch to private transfer storage…';
    passwordInput.value = '';

    try {
      const response = await fetch(ENDPOINT, { method: 'POST', headers: { Authorization: `Bearer ${password}` }, body: data, credentials: 'omit' });
      let payload = null;
      try { payload = await response.json(); } catch { /* non-JSON error response */ }
      if (!response.ok) {
        throw new Error(payload?.error || `Upload failed (${response.status}).`);
      }
      message.dataset.kind = 'success';
      message.textContent = `Batch received (reference ${(payload?.batchId || '').slice(0, 19) || 'recorded'}). The dashboard rebuild, validation and publish run automatically — allow a few minutes, then reopen the dashboard.`;
      form.reset();
      form.querySelectorAll('.upload-filename').forEach((el) => { el.textContent = el.dataset.empty; el.classList.remove('has-file'); });
    } catch (error) {
      message.dataset.kind = 'error';
      message.textContent = error.message || 'Upload failed. Check the password and try again.';
    } finally {
      setBusy(false, 'Upload batch');
    }
  });
})();
