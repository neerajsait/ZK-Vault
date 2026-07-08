/**
 * index.js — SPA Vault Controller with Pure In-Memory Key Management
 *
 * ZERO-KNOWLEDGE ARCHITECTURE:
 * 1. Master encryption keys (key1, secretKey) are kept STRICTLY in JS variable memory
 *    (via vault-crypto.js's in-memory vaultKeys object).
 * 2. NO sessionStorage, NO localStorage, NO IndexedDB key storage.
 * 3. Refreshing the browser or leaving /vault wipes JS memory, requiring
 *    the user to re-enter their password to unlock the vault.
 */

import {
    deriveKeyFromPassword,
    deriveLoginVerifier,
    deriveSecretVaultKey,
    deriveSecretVerifier,
    encryptRecord,
    decryptRecord,
    generateSalt,
    validateVaultPassword,
    validateSecretCode,
    setVaultKey1,
    getVaultKey1,
    setSecretVaultKey,
    getSecretVaultKey,
    clearVaultKeys
} from './vault-crypto.js';

// Global state cache for loaded records
let cachedNormalRecords = [];
let cachedSecretRecords = [];

// Helper selectors
const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => Array.from(parent.querySelectorAll(selector));

function getCSRFToken() {
    const meta = $('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function showStatus(el, msg, isError = false, isSuccess = false) {
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
    if (isError) el.className = 'status error';
    else if (isSuccess) el.className = 'status ok';
    else el.className = 'status info';
}

function hideStatus(el) {
    if (!el) return;
    el.style.display = 'none';
    el.textContent = '';
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

async function apiFetch(url, options = {}) {
    const headers = options.headers || {};
    headers['X-CSRFToken'] = getCSRFToken();
    headers['X-Requested-With'] = 'XMLHttpRequest';
    if (options.body && !(options.body instanceof FormData) && typeof options.body === 'object') {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
    }
    options.headers = headers;
    options.credentials = 'same-origin';

    const resp = await fetch(url, options);
    if (resp.status === 401 || resp.status === 403) {
        const data = await resp.json().catch(() => ({}));
        if (data.relogin || !resp.headers.get('content-type')?.includes('application/json')) {
            clearVaultKeys();
            if (!window.location.pathname.startsWith('/login') && !window.location.pathname.startsWith('/signup')) {
                window.location.href = '/login';
            }
            return null;
        }
    }
    if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${resp.status}`);
    }
    const contentType = resp.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
        clearVaultKeys();
        if (!window.location.pathname.startsWith('/login') && !window.location.pathname.startsWith('/signup')) {
            window.location.href = '/login';
        }
        return null;
    }
    return resp.json();
}

// ═══════════════════════════════════════════════════════════════
// SPA SECTION NAVIGATION
// ═══════════════════════════════════════════════════════════════

function showSection(sectionName) {
    const key1 = getVaultKey1();
    
    // Guard: require vault key before allowing access to secret or change-password
    if (!key1 && ['secret', 'change-password'].includes(sectionName)) {
        sectionName = 'unlock';
    }

    // Toggle section visibility
    $$('.spa-section').forEach(sec => {
        sec.classList.remove('active');
    });
    const targetSec = $(`#sec-${sectionName}`);
    if (targetSec) targetSec.classList.add('active');

    // Update nav tabs styling
    $$('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.section === sectionName) {
            btn.classList.add('active');
        }
    });

    // Update tab disabled states based on lock status
    const isUnlocked = Boolean(key1);
    $('#tab-records-btn')?.classList.toggle('disabled', false);
    $('#tab-secret-btn')?.classList.toggle('disabled', !isUnlocked);
    $('#tab-change-pw-btn')?.classList.toggle('disabled', !isUnlocked);

    // Update status badge
    const badge = $('#lock-status-badge');
    if (badge) {
        if (isUnlocked) {
            badge.textContent = '● Unlocked (Decrypted)';
            badge.className = 'lock-badge unlocked';
        } else {
            badge.textContent = '● Encrypted Mode';
            badge.className = 'lock-badge locked';
        }
    }

    // Load data if switching to active sections
    if (sectionName === 'records') {
        loadRecords();
        updateQuota();
    } else if (sectionName === 'secret' && isUnlocked) {
        const secretKey = getSecretVaultKey();
        if (secretKey) {
            $('#secret-lock-container')?.classList.add('hidden');
            $('#secret-records-container')?.classList.remove('hidden');
            loadSecretRecords();
        } else {
            $('#secret-lock-container')?.classList.remove('hidden');
            $('#secret-records-container')?.classList.add('hidden');
        }
    } else if (sectionName === 'settings') {
        updateQuota();
    }
}

async function updateQuota() {
    try {
        const data = await apiFetch('/api/user_quota');
        if (!data) return;
        const usageKb = Math.round((data.storage_bytes || 0) / 1024);
        const maxMb = data.max_storage_mb || 100;
        const maxBytes = maxMb * 1024 * 1024;
        const maxRecords = data.max_records || 1000;

        const usageText = $('#quota-usage-text');
        if (usageText) usageText.textContent = `${usageKb} KB`;

        const maxStorageText = $('#max-storage-text');
        if (maxStorageText) maxStorageText.textContent = `${maxMb} MB`;

        const countText = $('#quota-count-text');
        if (countText) countText.textContent = `${data.record_count || 0}`;

        const maxRecordsText = $('#max-records-text');
        if (maxRecordsText) maxRecordsText.textContent = `${maxRecords}`;

        const fill = $('#quota-bar-fill');
        if (fill) {
            const pct = Math.min(100, Math.round(((data.storage_bytes || 0) / maxBytes) * 100));
            fill.style.width = `${pct}%`;
        }
    } catch (err) {
        // Quota fetch warning caught gracefully
    }
}

// ═══════════════════════════════════════════════════════════════
// IN-PAGE UNLOCK VAULT
// ═══════════════════════════════════════════════════════════════

function setupUnlockForm() {
    const form = $('#spa-unlock-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pwdInput = $('#vault-password-input');
        const submitBtn = $('#unlock-submit-btn');
        const statusEl = $('#unlock-status');
        const saltB64 = $('#saltB64')?.value;

        const pwd = pwdInput.value;
        if (!pwd) {
            showStatus(statusEl, 'Please enter your vault password.', true);
            return;
        }
        if (!saltB64) {
            showStatus(statusEl, 'Session error: missing salt. Please refresh.', true);
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Deriving Key…';
        showStatus(statusEl, 'Deriving encryption key in memory (Argon2id)…', false);

        try {
            // 1. Derive key1 in memory
            const key1Bytes = await deriveKeyFromPassword(pwd, saltB64);

            // 2. Derive login verifier
            const verifierB64 = await deriveLoginVerifier(key1Bytes);

            // 3. Post verifier to server
            const formData = new FormData();
            formData.append('verifier', verifierB64);

            const resp = await fetch('/unlock', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData,
                credentials: 'same-origin'
            });

            const data = await resp.json().catch(() => ({}));

            if (resp.ok && data.success) {
                // SUCCESS: Store key1 ONLY in JS variable memory!
                setVaultKey1(key1Bytes);
                pwdInput.value = '';
                showStatus(statusEl, 'Vault unlocked successfully!', false, true);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Unlock Vault';

                setTimeout(() => {
                    hideStatus(statusEl);
                    showSection('records');
                }, 400);
            } else {
                showStatus(statusEl, data.error || 'Incorrect vault password.', true);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Unlock Vault';
            }
        } catch (err) {
            showStatus(statusEl, `Unlock failed: ${err.message}`, true);
            submitBtn.disabled = false;
            submitBtn.textContent = 'Unlock Vault';
        }
    });
}

// ═══════════════════════════════════════════════════════════════
// NORMAL VAULT RECORDS DASHBOARD
// ═══════════════════════════════════════════════════════════════


async function loadRecords() {
    const list = $('#record-list');
    if (!list) return;
    const key1 = getVaultKey1();

    list.innerHTML = '<div class="loading">Fetching records…</div>';

    try {
        const data = await apiFetch('/api/records');
        if (!data || data.length === 0) {
            cachedNormalRecords = [];
            list.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 2rem;">No records found. Click "+ New Record" to create one!</p>';
            return;
        }

        if (key1) {
            const decryptedList = [];
            for (const rec of data) {
                try {
                    const decrypted = await decryptRecord(key1, rec.ciphertext);
                    decryptedList.push({
                        id: rec.id,
                        title: decrypted.title || 'Untitled',
                        notes: decrypted.notes || '',
                        files: decrypted.files || [],
                        created_at: rec.created_at,
                        isEncrypted: false
                    });
                } catch (err) {
                    decryptedList.push({
                        id: rec.id,
                        title: '⚠️ [Decryption Failed]',
                        notes: '',
                        files: [],
                        created_at: rec.created_at,
                        isEncrypted: false
                    });
                }
            }
            cachedNormalRecords = decryptedList;
            renderRecordList(decryptedList, list, false);
        } else {
            // Encrypted Mode: user entered wrong password or skipped password step
            const encryptedList = data.map(rec => ({
                id: rec.id,
                title: `🔒 Encrypted Record (${rec.id})`,
                notes: `[Raw Ciphertext Payload]\n${rec.ciphertext}`,
                ciphertext: rec.ciphertext,
                files: [],
                created_at: rec.created_at,
                isEncrypted: true
            }));
            cachedNormalRecords = encryptedList;

            const bannerHtml = `
                <div style="background: rgba(255, 170, 0, 0.12); border: 1px solid rgba(255, 170, 0, 0.35); border-radius: var(--radius); padding: 0.85rem 1.25rem; margin-bottom: 1.25rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem;">
                    <div>
                        <strong style="color: #f39c12; font-size: 0.85rem;">🔒 Vault Loaded in Encrypted Mode</strong>
                        <p style="color: var(--text-secondary); font-size: 0.78rem; margin-top: 0.2rem;">Wrong or missing master password. Viewing raw encrypted payloads. Unlock with password to decrypt.</p>
                    </div>
                    <button type="button" id="btn-switch-to-unlock" class="btn primary" style="padding: 0.4rem 0.85rem; font-size: 0.75rem;">Unlock to Decrypt</button>
                </div>
            `;
            const wrapper = document.createElement('div');
            wrapper.innerHTML = bannerHtml;
            list.innerHTML = '';
            list.appendChild(wrapper.firstElementChild);

            const recordsContainer = document.createElement('div');
            list.appendChild(recordsContainer);
            renderRecordList(encryptedList, recordsContainer, false);

            $('#btn-switch-to-unlock')?.addEventListener('click', () => showSection('unlock'));
        }
    } catch (err) {
        list.innerHTML = `<p class="error">Failed to load records: ${escapeHtml(err.message)}</p>`;
    }
}

function renderRecordList(records, container, isSecret = false) {
    if (records.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 2rem;">No matching records found.</p>';
        return;
    }

    let html = '';
    for (const rec of records) {
        const fileCount = rec.files ? rec.files.length : 0;
        const fileBadge = fileCount > 0 ? `<span style="font-size: 0.72rem; color: var(--text-muted); margin-left: 0.5rem;">📎 ${fileCount} file(s)</span>` : '';

        const actionButtons = rec.isEncrypted
            ? `<button class="btn secondary view-record">View Payload</button>
               <button class="btn secondary unlock-record" style="border-color: var(--accent); color: var(--accent);">Unlock</button>`
            : `<button class="btn secondary view-record">View</button>
               <button class="btn secondary edit-record">Edit</button>
               <button class="btn danger delete-record">Delete</button>`;

        html += `
            <div class="record-item" data-id="${rec.id}" data-is-secret="${isSecret}">
                <div class="record-info">
                    <div class="record-title">${escapeHtml(rec.title)}${fileBadge}</div>
                    <div class="record-meta">${rec.created_at ? new Date(rec.created_at).toLocaleString() : ''}</div>
                </div>
                <div class="record-actions">
                    ${actionButtons}
                </div>
            </div>
        `;
    }
    container.innerHTML = html;

    $$('.view-record', container).forEach(btn => btn.addEventListener('click', (e) => onViewRecord(e, isSecret)));
    $$('.edit-record', container).forEach(btn => btn.addEventListener('click', (e) => onEditRecord(e, isSecret)));
    $$('.delete-record', container).forEach(btn => btn.addEventListener('click', (e) => onDeleteRecord(e, isSecret)));
    $$('.unlock-record', container).forEach(btn => btn.addEventListener('click', () => showSection('unlock')));
}

// Search filtering
function setupSearch() {
    $('#search-records-input')?.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        const filtered = cachedNormalRecords.filter(r => r.title.toLowerCase().includes(q));
        renderRecordList(filtered, $('#record-list'), false);
    });

    $('#search-secret-records-input')?.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        const filtered = cachedSecretRecords.filter(r => r.title.toLowerCase().includes(q));
        renderRecordList(filtered, $('#secret-record-list'), true);
    });
}

// ═══════════════════════════════════════════════════════════════
// RECORD MODALS & ACTIONS (CREATE / EDIT / VIEW / DELETE)
// ═══════════════════════════════════════════════════════════════

let pendingFileAttachments = [];

function setupRecordModals() {
    const modal = $('#record-modal');
    const form = $('#record-form');
    const fileInput = $('#record-files');

    // Close buttons
    $('#record-modal-close-x')?.addEventListener('click', () => modal.classList.add('hidden'));
    $('#view-modal-close-x')?.addEventListener('click', () => $('#view-record-modal').classList.add('hidden'));
    $('#view-modal-close-btn')?.addEventListener('click', () => $('#view-record-modal').classList.add('hidden'));

    // File input change
    fileInput?.addEventListener('change', async (e) => {
        const files = Array.from(e.target.files);
        for (const file of files) {
            const buf = await file.arrayBuffer();
            pendingFileAttachments.push({
                filename: file.name,
                mime_type: file.type || 'application/octet-stream',
                bytes: new Uint8Array(buf)
            });
        }
        renderPendingFiles();
    });

    // Create Normal Record Button
    $('#create-record-btn')?.addEventListener('click', () => {
        openRecordModal('New Vault Record', '', '', [], false);
    });

    // Create Secret Record Button
    $('#create-secret-record-btn')?.addEventListener('click', () => {
        openRecordModal('New Secret Vault Record', '', '', [], true);
    });

    // Save Form Submit
    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const recId = $('#record-id').value;
        const isSecret = $('#record-is-secret').value === 'true';
        const title = $('#record-title').value.trim();
        const notes = $('#record-notes').value.trim();
        const statusEl = $('#modal-status');
        const saveBtn = $('#record-save-btn');

        const rawKey = isSecret ? getSecretVaultKey() : getVaultKey1();
        if (!rawKey) {
            showStatus(statusEl, 'Vault is locked. Cannot encrypt.', true);
            return;
        }

        saveBtn.disabled = true;
        showStatus(statusEl, 'Encrypting record in browser…', false);

        try {
            const ciphertext = await encryptRecord(rawKey, {
                title,
                notes,
                files: pendingFileAttachments
            });

            const endpoint = isSecret ? '/api/secret/records' : '/api/records';
            const method = recId ? 'PUT' : 'POST';
            const url = recId ? `${endpoint}/${recId}` : endpoint;

            await apiFetch(url, {
                method,
                body: { ciphertext }
            });

            modal.classList.add('hidden');
            saveBtn.disabled = false;
            hideStatus(statusEl);

            if (isSecret) loadSecretRecords();
            else {
                loadRecords();
                updateQuota();
            }
        } catch (err) {
            showStatus(statusEl, `Failed to save: ${err.message}`, true);
            saveBtn.disabled = false;
        }
    });
}

function openRecordModal(modalTitle, recId, title, notes, isSecret, files = []) {
    $('#modal-title').textContent = modalTitle;
    $('#record-id').value = recId || '';
    $('#record-is-secret').value = isSecret ? 'true' : 'false';
    $('#record-title').value = title || '';
    $('#record-notes').value = notes || '';
    $('#record-files').value = '';
    hideStatus($('#modal-status'));

    pendingFileAttachments = files || [];
    renderPendingFiles();

    $('#record-modal').classList.remove('hidden');
}

function renderPendingFiles() {
    const list = $('#file-list');
    if (!list) return;
    if (pendingFileAttachments.length === 0) {
        list.innerHTML = '';
        return;
    }
    let html = '';
    pendingFileAttachments.forEach((f, idx) => {
        html += `
            <div style="font-size: 0.78rem; color: var(--text-secondary); display: flex; justify-content: space-between; padding: 0.25rem 0;">
                <span>📎 ${escapeHtml(f.filename)} (${(f.bytes.length / 1024).toFixed(1)} KB)</span>
                <span data-idx="${idx}" class="remove-file-btn" style="color: var(--accent); cursor: pointer; font-weight: bold;">&times;</span>
            </div>
        `;
    });
    list.innerHTML = html;

    $$('.remove-file-btn', list).forEach(btn => {
        btn.addEventListener('click', (e) => {
            const idx = parseInt(e.target.dataset.idx, 10);
            pendingFileAttachments.splice(idx, 1);
            renderPendingFiles();
        });
    });
}

function onViewRecord(e, isSecret) {
    const item = e.target.closest('.record-item');
    const recId = item.dataset.id;
    const cache = isSecret ? cachedSecretRecords : cachedNormalRecords;
    const rec = cache.find(r => r.id === recId);

    if (!rec) return;

    $('#view-record-title').textContent = rec.title;
    $('#view-record-notes').textContent = rec.notes || '(No notes)';

    const filesContainer = $('#view-files-container');
    const filesList = $('#view-files-list');

    if (rec.files && rec.files.length > 0) {
        filesContainer.classList.remove('hidden');
        let html = '';
        rec.files.forEach((f, idx) => {
            html += `
                <div style="margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center; background: var(--bg-input); padding: 0.5rem; border-radius: var(--radius);">
                    <span style="font-size: 0.8rem; color: var(--white);">📄 ${escapeHtml(f.filename)}</span>
                    <button class="btn secondary download-file-btn" data-rec-id="${recId}" data-file-idx="${idx}" style="padding: 0.25rem 0.5rem; font-size: 0.72rem;">Download</button>
                </div>
            `;
        });
        filesList.innerHTML = html;

        $$('.download-file-btn', filesList).forEach(btn => {
            btn.addEventListener('click', (evt) => {
                const targetBtn = evt.currentTarget;
                const fIdx = parseInt(targetBtn.getAttribute('data-file-idx'), 10);
                const fileObj = rec.files ? rec.files[fIdx] : null;
                const rawBytes = fileObj ? (fileObj.decryptedBytes || fileObj.bytes) : null;
                if (fileObj && rawBytes) {
                    const blob = new Blob([rawBytes], { type: fileObj.mime_type || 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = fileObj.filename || 'download';
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                }
            });
        });
    } else {
        filesContainer.classList.add('hidden');
    }

    $('#view-record-modal').classList.remove('hidden');
}

function onEditRecord(e, isSecret) {
    const item = e.target.closest('.record-item');
    const recId = item.dataset.id;
    const cache = isSecret ? cachedSecretRecords : cachedNormalRecords;
    const rec = cache.find(r => r.id === recId);
    if (!rec) return;

    const files = (rec.files || []).map(f => ({
        filename: f.filename,
        mime_type: f.mime_type,
        bytes: f.decryptedBytes
    }));

    openRecordModal(isSecret ? 'Edit Secret Record' : 'Edit Record', rec.id, rec.title, rec.notes, isSecret, files);
}

async function onDeleteRecord(e, isSecret) {
    const item = e.target.closest('.record-item');
    const recId = item.dataset.id;
    if (!confirm('Are you sure you want to delete this record?')) return;

    try {
        const endpoint = isSecret ? `/api/secret/records/${recId}` : `/api/records/${recId}`;
        await apiFetch(endpoint, { method: 'DELETE' });

        if (isSecret) loadSecretRecords();
        else {
            loadRecords();
            updateQuota();
        }
    } catch (err) {
        alert(`Failed to delete: ${err.message}`);
    }
}

// ═══════════════════════════════════════════════════════════════
// SECRET VAULT CONTROLLER
// ═══════════════════════════════════════════════════════════════

function setupSecretSetupForm() {
    const setupForm = $('#secret-setup-form');
    if (!setupForm) return;

    setupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const codeInput = $('#setup-secret-code-input');
        const confirmInput = $('#setup-secret-code-confirm');
        const submitBtn = $('#secret-setup-submit-btn');
        const statusEl = $('#secret-setup-status');
        const key1 = getVaultKey1();

        if (!key1) {
            showStatus(statusEl, 'Main vault is locked.', true);
            return;
        }

        const code = codeInput.value.trim().toUpperCase();
        const confirmCode = confirmInput.value.trim().toUpperCase();

        if (code !== confirmCode) {
            showStatus(statusEl, 'Secret codes do not match.', true);
            return;
        }

        const secErrors = validateSecretCode(code);
        if (secErrors.length) {
            showStatus(statusEl, `Secret code requirement: ${secErrors.join(' ')}`, true);
            return;
        }

        submitBtn.disabled = true;
        showStatus(statusEl, 'Initializing secret vault…', false);

        try {
            // 1. Get salt from server
            const saltData = await apiFetch('/secret/setup', { method: 'GET' });
            if (!saltData || !saltData.salt) {
                throw new Error('Failed to retrieve secret salt');
            }
            const saltB64 = saltData.salt;

            // 2. Derive key2 and secret verifier
            const key2 = await deriveKeyFromPassword(code, saltB64);
            const secretVerifier = await deriveSecretVerifier(key1, key2);

            // 3. Post verifier to server
            const formData = new FormData();
            formData.append('secret_verifier', secretVerifier);

            const resp = await fetch('/secret/setup', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData,
                credentials: 'same-origin'
            });

            const resData = await resp.json().catch(() => ({}));

            if (resp.ok && resData.success) {
                const secretKey = await deriveSecretVaultKey(key1, key2);
                setSecretVaultKey(secretKey);

                if ($('#secretSaltB64')) $('#secretSaltB64').value = saltB64;

                $('#secret-setup-container')?.classList.add('hidden');
                $('#secret-records-container')?.classList.remove('hidden');
                hideStatus(statusEl);

                loadSecretRecords();
            } else {
                showStatus(statusEl, resData.error || 'Secret vault setup failed.', true);
            }
        } catch (err) {
            showStatus(statusEl, `Setup error: ${err.message}`, true);
        } finally {
            submitBtn.disabled = false;
        }
    });
}

function setupSecretVault() {
    const form = $('#secret-unlock-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const codeInput = $('#secret-code-input');
        const submitBtn = $('#secret-unlock-submit-btn');
        const statusEl = $('#secret-status');
        let secretSaltB64 = $('#secretSaltB64')?.value;
        const key1 = getVaultKey1();

        if (!key1) {
            showStatus(statusEl, 'Main vault is locked.', true);
            return;
        }
        if (!secretSaltB64) {
            try {
                const saltRes = await apiFetch('/api/secret/get_salt');
                if (saltRes && saltRes.secret_salt) {
                    secretSaltB64 = saltRes.secret_salt;
                }
            } catch (e) {
                // Ignore
            }
        }
        if (!secretSaltB64) {
            showStatus(statusEl, 'Secret vault is not set up on this account.', true);
            return;
        }

        const rawCode = codeInput.value.trim();
        const code = rawCode.toUpperCase();

        submitBtn.disabled = true;
        showStatus(statusEl, 'Deriving secret key…', false);

        try {
            const key2 = await deriveKeyFromPassword(code, secretSaltB64);
            const secretVerifier = await deriveSecretVerifier(key1, key2);

            const formData = new FormData();
            formData.append('secret_verifier', secretVerifier);

            const resp = await fetch('/secret/unlock', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData,
                credentials: 'same-origin'
            });

            if (resp.ok) {
                const secretKey = await deriveSecretVaultKey(key1, key2);
                setSecretVaultKey(secretKey);

                $('#secret-lock-container').classList.add('hidden');
                $('#secret-records-container').classList.remove('hidden');
                hideStatus(statusEl);

                loadSecretRecords();
            } else {
                showStatus(statusEl, 'Incorrect secret code.', true);
            }
        } catch (err) {
            showStatus(statusEl, `Error: ${err.message}`, true);
        } finally {
            submitBtn.disabled = false;
        }
    });
}

async function loadSecretRecords() {
    const list = $('#secret-record-list');
    if (!list) return;
    const secretKey = getSecretVaultKey();
    if (!secretKey) return;

    list.innerHTML = '<div class="loading">Fetching secret records…</div>';

    try {
        const data = await apiFetch('/api/secret/records');
        if (!data || data.length === 0) {
            cachedSecretRecords = [];
            list.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 2rem;">No secret records found.</p>';
            return;
        }

        const decryptedList = [];
        for (const rec of data) {
            try {
                const decrypted = await decryptRecord(secretKey, rec.ciphertext);
                decryptedList.push({
                    id: rec.id,
                    title: decrypted.title || 'Untitled',
                    notes: decrypted.notes || '',
                    files: decrypted.files || [],
                    created_at: rec.created_at
                });
            } catch (err) {
                decryptedList.push({
                    id: rec.id,
                    title: '⚠️ [Decryption Failed]',
                    notes: '',
                    files: [],
                    created_at: rec.created_at
                });
            }
        }

        cachedSecretRecords = decryptedList;
        renderRecordList(decryptedList, list, true);
    } catch (err) {
        list.innerHTML = `<p class="error">Failed to load secret records: ${escapeHtml(err.message)}</p>`;
    }
}

// ═══════════════════════════════════════════════════════════════
// CHANGE PASSWORD CONTROLLER
// ═══════════════════════════════════════════════════════════════

function setupChangePassword() {
    const form = $('#change-password-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const currentPw = $('#cp-current-pw').value;
        const newPw = $('#cp-new-pw').value;
        const confirmPw = $('#cp-confirm-pw').value;
        const secretCode = $('#cp-secret-code')?.value?.trim();
        const submitBtn = $('#cp-submit-btn');
        const statusEl = $('#cp-status');
        const saltB64 = $('#saltB64')?.value;

        if (newPw !== confirmPw) {
            showStatus(statusEl, 'New passwords do not match.', true);
            return;
        }
        const pwErrors = validateVaultPassword(newPw);
        if (pwErrors.length) {
            showStatus(statusEl, `Password requirement: ${pwErrors.join(' ')}`, true);
            return;
        }

        submitBtn.disabled = true;
        showStatus(statusEl, 'Re-encrypting records in browser… Please do not navigate away.', false);

        try {
            // Derive current key1 to re-read records
            const oldKey1 = await deriveKeyFromPassword(currentPw, saltB64);

            // Generate new salt and key1
            const newSaltB64 = generateSalt();
            const newKey1 = await deriveKeyFromPassword(newPw, newSaltB64);
            const newVerifierB64 = await deriveLoginVerifier(newKey1);

            // Re-encrypt normal records
            const normalRecords = await apiFetch('/api/records');
            const reencryptedNormal = [];
            for (const r of normalRecords) {
                const dec = await decryptRecord(oldKey1, r.ciphertext);
                const enc = await encryptRecord(newKey1, dec);
                reencryptedNormal.push({ id: r.id, ciphertext: enc });
            }

            // Re-encrypt secret records if applicable
            let reencryptedSecret = [];
            let oldSecretVerifier = null;
            let newSecretVerifier = null;
            let newSecretSalt = null;

            if (secretCode) {
                const oldSecretSalt = $('#secretSaltB64')?.value;
                const oldKey2 = await deriveKeyFromPassword(secretCode.toUpperCase(), oldSecretSalt);
                oldSecretVerifier = await deriveSecretVerifier(oldKey1, oldKey2);
                const oldSecretKey = await deriveSecretVaultKey(oldKey1, oldKey2);

                newSecretSalt = generateSalt();
                const newKey2 = await deriveKeyFromPassword(secretCode.toUpperCase(), newSecretSalt);
                const newSecretKey = await deriveSecretVaultKey(newKey1, newKey2);
                newSecretVerifier = await deriveSecretVerifier(newKey1, newKey2);

                const secretRecords = await apiFetch('/api/secret/records');
                for (const r of secretRecords) {
                    const dec = await decryptRecord(oldSecretKey, r.ciphertext);
                    const enc = await encryptRecord(newSecretKey, dec);
                    reencryptedSecret.push({ id: r.id, ciphertext: enc });
                }
            }

            const bodyPayload = {
                old_verifier: await deriveLoginVerifier(oldKey1),
                new_salt: newSaltB64,
                new_verifier: newVerifierB64,
                records: reencryptedNormal
            };

            if (secretCode) {
                bodyPayload.old_secret_verifier = oldSecretVerifier;
                bodyPayload.new_secret_salt = newSecretSalt;
                bodyPayload.new_secret_verifier = newSecretVerifier;
                bodyPayload.secret_records = reencryptedSecret;
            }

            // Send re-encrypted payload to backend
            await apiFetch('/api/change_password', {
                method: 'POST',
                body: bodyPayload
            });

            clearVaultKeys();
            showStatus(statusEl, 'Password changed and all records re-encrypted successfully! Redirecting to login page…', false, true);
            form.reset();

            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
        } catch (err) {
            showStatus(statusEl, `Change password failed: ${err.message}`, true);
            submitBtn.disabled = false;
        }
    });
}

// ═══════════════════════════════════════════════════════════════
// ACCOUNT SETTINGS & DELETE ACCOUNT MODAL
// ═══════════════════════════════════════════════════════════════

function setupDeleteAccountModal() {
    const modal = $('#delete-account-modal');
    const form = $('#delete-account-form');

    $('#open-delete-account-modal-btn')?.addEventListener('click', () => modal.classList.remove('hidden'));
    $('#delete-account-modal-close-x')?.addEventListener('click', () => modal.classList.add('hidden'));
    $('#delete-account-cancel-btn')?.addEventListener('click', () => modal.classList.add('hidden'));

    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pwd = $('#delete-account-password').value;
        const statusEl = $('#delete-account-status');
        const submitBtn = $('#delete-account-confirm-btn');
        const saltB64 = $('#saltB64')?.value;

        if (!pwd || !saltB64) return;

        submitBtn.disabled = true;
        showStatus(statusEl, 'Verifying master password…', false);

        try {
            const key1 = await deriveKeyFromPassword(pwd, saltB64);
            const verifierB64 = await deriveLoginVerifier(key1);

            const formData = new FormData();
            formData.append('verifier', verifierB64);

            const resp = await fetch('/delete_account', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData,
                credentials: 'same-origin'
            });

            if (resp.ok) {
                clearVaultKeys();
                window.location.href = '/login';
            } else {
                showStatus(statusEl, 'Incorrect master password.', true);
                submitBtn.disabled = false;
            }
        } catch (err) {
            showStatus(statusEl, `Error: ${err.message}`, true);
            submitBtn.disabled = false;
        }
    });
}

// ═══════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    // Only run SPA vault controller if we are on the vault page
    const isVaultPage = document.querySelector('.spa-container') || document.querySelector('#sec-records');
    if (!isVaultPage) return;

    // Retrieve transient key from sessionStorage if present (e.g. from login/signup redirect)
    try {
        const transientKeyB64 = sessionStorage.getItem('_transient_vault_key');
        if (transientKeyB64) {
            // Consume immediately — one-time use only
            sessionStorage.removeItem('_transient_vault_key');
            const bin = atob(transientKeyB64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) {
                bytes[i] = bin.charCodeAt(i);
            }
            setVaultKey1(bytes);
        }
    } catch (e) {
        console.error('Failed to load transient key from sessionStorage:', e);
    }

    // Top nav tab click handlers
    $$('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const targetSec = e.currentTarget.dataset.section;
            if (targetSec) showSection(targetSec);
        });
    });

    setupUnlockForm();
    setupSearch();
    setupRecordModals();
    setupSecretVault();
    setupSecretSetupForm();
    setupChangePassword();
    setupDeleteAccountModal();

    // Initial section display: open records section directly (decrypted if key present, else encrypted mode)
    showSection('records');
});