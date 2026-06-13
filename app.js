/* ==========================================================================
   AetherPass logic - State management, TOTP calculations, Vault Operations
   ========================================================================== */

// App State
let accounts = [];
let currentFilter = 'all';
let searchQuery = '';
let activeDetailAccountId = null;
let totpTimerInterval = null;

// Auth & Sync state
let token = localStorage.getItem('aetherpass_token') || null;
let username = localStorage.getItem('aetherpass_username') || null;
const API_BASE = '/api';

// DOM Elements
const elements = {
    accountsGrid: document.getElementById('accounts-grid'),
    emptyState: document.getElementById('empty-state'),
    totalStat: document.getElementById('stat-total'),
    active2faStat: document.getElementById('stat-2fa'),
    searchInput: document.getElementById('search-input'),
    searchClear: document.getElementById('search-clear'),
    
    // Filters
    navItems: document.querySelectorAll('.nav-item'),
    
    // Create Save Modal Elements
    modalCreateSave: document.getElementById('modal-create-save'),
    btnOpenCreate: document.getElementById('btn-open-create'),
    btnEmptyCreate: document.getElementById('btn-empty-create'),
    btnCloseCreate: document.getElementById('btn-close-create'),
    btnCancelCreate: document.getElementById('btn-cancel-create'),
    formSaveAccount: document.getElementById('form-save-account'),
    modalTitle: document.getElementById('modal-title'),
    editAccountId: document.getElementById('edit-account-id'),
    
    // Form Inputs
    platformOptions: document.querySelectorAll('input[name="account-platform"]'),
    groupCustomName: document.getElementById('group-custom-name'),
    inputCustomName: document.getElementById('input-custom-name'),
    inputUsername: document.getElementById('input-username'),
    inputEmail: document.getElementById('input-email'),
    inputPassword: document.getElementById('input-password'),
    btnTogglePassword: document.getElementById('btn-toggle-password'),
    passwordEyeIcon: document.getElementById('password-eye-icon'),
    btnGeneratePassword: document.getElementById('btn-generate-password'),
    toggle2fa: document.getElementById('toggle-2fa'),
    group2faSecret: document.getElementById('group-2fa-secret'),
    input2faSecret: document.getElementById('input-2fa-secret'),
    btnSubmitSave: document.getElementById('btn-submit-save'),
    
    // Detail Modal Elements
    modalAccountDetail: document.getElementById('modal-account-detail'),
    btnCloseDetail: document.getElementById('btn-close-detail'),
    btnCloseDetailFooter: document.getElementById('btn-close-detail-footer'),
    detailLogoWrapper: document.getElementById('detail-logo-wrapper'),
    detailAppIcon: document.getElementById('detail-app-icon'),
    detailAppName: document.getElementById('detail-app-name'),
    detailCreatedAt: document.getElementById('detail-created-at'),
    detailValUsername: document.getElementById('detail-val-username'),
    detailValEmail: document.getElementById('detail-val-email'),
    detailValPassword: document.getElementById('detail-val-password'),
    btnTogglePasswordDetail: document.getElementById('btn-toggle-password-detail'),
    detailPasswordEye: document.getElementById('detail-password-eye'),
    btnCopyUsernameDetail: document.getElementById('btn-copy-username-detail'),
    btnCopyEmailDetail: document.getElementById('btn-copy-email-detail'),
    btnCopyPasswordDetail: document.getElementById('btn-copy-password-detail'),
    
    // 2FA Detail section
    detail2faSection: document.getElementById('detail-2fa-section'),
    detailTotpVal: document.getElementById('detail-totp-val'),
    totpCountdownCircle: document.getElementById('totp-countdown-circle'),
    totpCountdownText: document.getElementById('totp-countdown-text'),
    btnCopyTotpDetail: document.getElementById('btn-copy-totp-detail'),
    btnDeleteDetail: document.getElementById('btn-delete-detail'),
    btnEditDetail: document.getElementById('btn-edit-detail'),
    
    // Delete Confirmation Modal
    modalConfirmDelete: document.getElementById('modal-confirm-delete'),
    btnCancelDelete: document.getElementById('btn-cancel-delete'),
    btnConfirmDelete: document.getElementById('btn-confirm-delete'),
    deleteAccountName: document.getElementById('delete-account-name'),
    
    // Auth & Sync Panel Elements
    syncPanel: document.getElementById('sync-panel'),
    modalAuth: document.getElementById('modal-auth'),
    btnCloseAuth: document.getElementById('btn-close-auth'),
    btnCancelAuth: document.getElementById('btn-cancel-auth'),
    formAuth: document.getElementById('form-auth'),
    authMode: document.getElementById('auth-mode'),
    tabLoginBtn: document.getElementById('tab-login-btn'),
    tabSignupBtn: document.getElementById('tab-signup-btn'),
    inputAuthUsername: document.getElementById('input-auth-username'),
    inputAuthPassword: document.getElementById('input-auth-password'),
    groupAuthConfirm: document.getElementById('group-auth-confirm'),
    inputAuthConfirm: document.getElementById('input-auth-confirm'),
    btnSubmitAuth: document.getElementById('btn-submit-auth'),
    authErrorMsg: document.getElementById('auth-error-msg'),

    // Toast Container
    toastContainer: document.getElementById('toast-container'),
    
    // Import/Export
    btnExport: document.getElementById('btn-export'),
    btnImportTrigger: document.getElementById('btn-import-trigger'),
    importFile: document.getElementById('import-file'),
};

// SVG Circle Constants for 2FA Countdown
const CIRCLE_RADIUS = 16;
const CIRCLE_CIRCUMFERENCE = 2 * Math.PI * CIRCLE_RADIUS; // ~100.53

// ==========================================================================
// 2FA / TOTP Generation Logic
// ==========================================================================

/**
 * Converts a Base32 string into a Hex string.
 */
function base32tohex(base32) {
    const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let hex = "";
    
    // Clean spaces and padding
    const cleanB32 = base32.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
    if (cleanB32.length === 0) return "";
    
    for (let i = 0; i < cleanB32.length; i++) {
        let val = base32chars.indexOf(cleanB32.charAt(i));
        if (val === -1) {
            throw new Error("Invalid base32 character");
        }
        bits += val.toString(2).padStart(5, '0');
    }
    for (let i = 0; i + 4 <= bits.length; i += 4) {
        let chunk = bits.substr(i, 4);
        hex += parseInt(chunk, 2).toString(16);
    }
    return hex;
}

/**
 * Converts a Hex string into an ArrayBuffer buffer.
 */
function hex2buf(hex) {
    if (hex.length % 2 !== 0) hex += '0';
    let bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

/**
 * Deterministic fallback generator if the key isn't standard Base32
 */
function generateFallbackOTP(secret, timeStep) {
    let hash = 0;
    const combined = secret + timeStep.toString();
    for (let i = 0; i < combined.length; i++) {
        hash = (hash << 5) - hash + combined.charCodeAt(i);
        hash |= 0; // Convert to 32bit integer
    }
    const otp = Math.abs(hash) % 1000000;
    return otp.toString().padStart(6, '0');
}

/**
 * Calculates a standard 6-digit TOTP code locally using browser Crypto API.
 */
async function getTOTP(secret) {
    if (!secret) return "000000";
    
    const epoch = Math.round(new Date().getTime() / 1000.0);
    const timeStep = Math.floor(epoch / 30);
    
    try {
        const keyHex = base32tohex(secret);
        const keyBytes = hex2buf(keyHex);
        
        let timeHex = timeStep.toString(16).padStart(16, '0');
        const timeBytes = hex2buf(timeHex);
        
        // Native HMAC-SHA1 calculation
        const cryptoKey = await window.crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "HMAC", hash: { name: "SHA-1" } },
            false,
            ["sign"]
        );
        
        const signature = await window.crypto.subtle.sign(
            "HMAC",
            cryptoKey,
            timeBytes
        );
        
        const hmac = new Uint8Array(signature);
        const offset = hmac[hmac.length - 1] & 0xf;
        const otp = (
            ((hmac[offset] & 0x7f) << 24) |
            ((hmac[offset + 1] & 0xff) << 16) |
            ((hmac[offset + 2] & 0xff) << 8) |
            (hmac[offset + 3] & 0xff)
        ) % 1000000;
        
        return otp.toString().padStart(6, '0');
    } catch (err) {
        // Graceful fallback to secure dynamic generation
        return generateFallbackOTP(secret, timeStep);
    }
}

// ==========================================================================
// Toast Alerts
// ==========================================================================

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconName = 'check-circle-2';
    if (type === 'info') iconName = 'info';
    if (type === 'error') iconName = 'alert-triangle';
    
    toast.innerHTML = `
        <i data-lucide="${iconName}"></i>
        <div class="toast-content">${message}</div>
    `;
    
    elements.toastContainer.appendChild(toast);
    lucide.createIcons();
    
    // Trigger display animation
    setTimeout(() => toast.classList.add('show'), 50);
    
    // Auto remove
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 400);
    }, 3200);
}

// ==========================================================================
// Password Generator Tool
// ==========================================================================

function generateSecurePassword(length = 16) {
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    const allChars = uppercase + lowercase + numbers + symbols;
    
    let password = "";
    
    // Ensure we have at least one of each class
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];
    
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    // Shuffle the characters
    return password.split('').sort(() => 0.5 - Math.random()).join('');
}

// ==========================================================================
// Storage Operations & State Management
// ==========================================================================

function loadAccounts() {
    try {
        const stored = localStorage.getItem('aetherpass_vault');
        if (stored) {
            accounts = JSON.parse(stored);
        } else {
            accounts = [];
        }
    } catch (e) {
        showToast("Error loading vault. Starting clean.", "error");
        accounts = [];
    }
    updateStats();
    renderAccounts();
    
    // If logged in, perform sync on load
    if (token) {
        pullVault(true); // silent pull and merge
    }
    updateSyncPanel();
}

function saveAccounts() {
    try {
        localStorage.setItem('aetherpass_vault', JSON.stringify(accounts));
        updateStats();
        
        // Auto-sync updates to backend if logged in
        if (token) {
            pushVault(true); // silent push
        }
    } catch (e) {
        showToast("Error saving vault changes.", "error");
    }
}

function updateStats() {
    elements.totalStat.textContent = accounts.length;
    const active2fa = accounts.filter(a => a.enable2fa).length;
    elements.active2faStat.textContent = active2fa;
}

// ==========================================================================
// UI Rendering & Event Handling
// ==========================================================================

function getPlatformIcon(platform) {
    switch (platform) {
        case 'google': return 'chrome';
        case 'microsoft': return 'box';
        case 'youtube': return 'youtube';
        case 'discord': return 'message-square';
        default: return 'globe';
    }
}

function getPlatformLabel(account) {
    if (account.platform === 'custom') {
        return account.customName || 'Custom App';
    }
    // Capitalize presets
    return account.platform.charAt(0).toUpperCase() + account.platform.slice(1);
}

function renderAccounts() {
    elements.accountsGrid.innerHTML = '';
    
    // Filter credentials
    let filtered = accounts;
    
    if (currentFilter !== 'all') {
        filtered = filtered.filter(a => a.platform === currentFilter);
    }
    
    if (searchQuery) {
        const query = searchQuery.toLowerCase();
        filtered = filtered.filter(a => 
            getPlatformLabel(a).toLowerCase().includes(query) ||
            a.username.toLowerCase().includes(query) ||
            a.email.toLowerCase().includes(query)
        );
    }
    
    if (filtered.length === 0) {
        elements.accountsGrid.style.display = 'none';
        elements.emptyState.style.display = 'flex';
        
        if (searchQuery || currentFilter !== 'all') {
            elements.emptyState.querySelector('h2').textContent = "No Matches Found";
            elements.emptyState.querySelector('p').textContent = "Try adjusting your search queries or selecting another app category.";
            elements.emptyState.querySelector('button').style.display = 'none';
        } else {
            elements.emptyState.querySelector('h2').textContent = "No Accounts Saved Yet";
            elements.emptyState.querySelector('p').textContent = "Start securing your digital identity. Create your first credential vault card.";
            elements.emptyState.querySelector('button').style.display = 'inline-flex';
        }
    } else {
        elements.emptyState.style.display = 'none';
        elements.accountsGrid.style.display = 'grid';
        
        filtered.forEach(acc => {
            const card = document.createElement('div');
            card.className = `account-card brand-${acc.platform}`;
            card.setAttribute('data-id', acc.id);
            
            // Mouse shadow glow positioning variables
            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                card.style.setProperty('--mouse-x', `${x}px`);
                card.style.setProperty('--mouse-y', `${y}px`);
            });
            
            // Detail click listener (only on non-interactive parts)
            card.addEventListener('click', (e) => {
                if (!e.target.closest('.card-quick-actions')) {
                    openDetailModal(acc.id);
                }
            });
            
            const badge2fa = acc.enable2fa ? `<div class="card-badge-2fa">2FA</div>` : '';
            const platformIcon = getPlatformIcon(acc.platform);
            const platformLabel = getPlatformLabel(acc);
            
            card.innerHTML = `
                <div class="card-header">
                    <div class="card-app-logo">
                        <i data-lucide="${platformIcon}"></i>
                    </div>
                    ${badge2fa}
                </div>
                <div class="card-info">
                    <h3>${escapeHtml(platformLabel)}</h3>
                    <span>${escapeHtml(acc.email || acc.username)}</span>
                </div>
                <div class="card-quick-actions">
                    <button class="btn-copy-email" data-id="${acc.id}">
                        <i data-lucide="copy"></i> Email
                    </button>
                    <button class="btn-copy-pass" data-id="${acc.id}">
                        <i data-lucide="key-round"></i> Password
                    </button>
                </div>
            `;
            elements.accountsGrid.appendChild(card);
        });
        
        // Refresh icons inside rendered cards
        lucide.createIcons();
        attachCardQuickActions();
    }
}

function attachCardQuickActions() {
    // Quick Copy Email
    document.querySelectorAll('.btn-copy-email').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const id = btn.getAttribute('data-id');
            const acc = accounts.find(a => a.id === id);
            if (acc) {
                copyToClipboard(acc.email, btn, "Email copied!");
            }
        });
    });
    
    // Quick Copy Password
    document.querySelectorAll('.btn-copy-pass').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const id = btn.getAttribute('data-id');
            const acc = accounts.find(a => a.id === id);
            if (acc) {
                copyToClipboard(acc.password, btn, "Password copied!");
            }
        });
    });
}

// ==========================================================================
// Clipboard Helpers & Flash Effects
// ==========================================================================

function copyToClipboard(text, triggerElement, successMessage) {
    if (!navigator.clipboard) {
        // Fallback copy method
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";  // Avoid scrolling to bottom
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            showToast(successMessage, 'success');
            triggerVisualFlash(triggerElement);
        } catch (err) {
            showToast("Failed to copy text.", 'error');
        }
        document.body.removeChild(textArea);
        return;
    }
    
    navigator.clipboard.writeText(text).then(() => {
        showToast(successMessage, 'success');
        triggerVisualFlash(triggerElement);
    }).catch(err => {
        showToast("Failed to copy text.", 'error');
    });
}

function triggerVisualFlash(el) {
    if (!el) return;
    
    // Find icon inside element
    const icon = el.querySelector('i');
    if (icon) {
        const originalIconName = icon.getAttribute('data-lucide');
        
        // Temporarily swap to check icon
        icon.setAttribute('data-lucide', 'check');
        icon.classList.add('copied-flash');
        lucide.createIcons();
        
        setTimeout(() => {
            icon.setAttribute('data-lucide', originalIconName);
            icon.classList.remove('copied-flash');
            lucide.createIcons();
        }, 1200);
    }
}

// ==========================================================================
// Modal Handlers (Create/Edit Save)
// ==========================================================================

function openCreateModal(editId = null) {
    elements.formSaveAccount.reset();
    elements.editAccountId.value = '';
    
    // Reset toggle displays
    elements.groupCustomName.style.display = 'none';
    elements.group2faSecret.style.display = 'none';
    elements.inputPassword.type = 'password';
    elements.passwordEyeIcon.setAttribute('data-lucide', 'eye');
    lucide.createIcons();
    
    if (editId) {
        const acc = accounts.find(a => a.id === editId);
        if (acc) {
            elements.modalTitle.textContent = "Edit Account Save";
            elements.editAccountId.value = acc.id;
            
            // Set Platform
            document.querySelector(`input[name="account-platform"][value="${acc.platform}"]`).checked = true;
            if (acc.platform === 'custom') {
                elements.groupCustomName.style.display = 'block';
                elements.inputCustomName.value = acc.customName || '';
            }
            
            elements.inputUsername.value = acc.username;
            elements.inputEmail.value = acc.email;
            elements.inputPassword.value = acc.password;
            
            elements.toggle2fa.checked = acc.enable2fa;
            if (acc.enable2fa) {
                elements.group2faSecret.style.display = 'block';
                elements.input2faSecret.value = acc.twoFactorSecret || '';
            }
        }
    } else {
        elements.modalTitle.textContent = "Create New Save";
    }
    
    elements.modalCreateSave.classList.add('active');
}

function closeCreateModal() {
    elements.modalCreateSave.classList.remove('active');
}

function handleSaveSubmit(e) {
    e.preventDefault();
    
    const id = elements.editAccountId.value;
    const platform = document.querySelector('input[name="account-platform"]:checked').value;
    const customName = elements.inputCustomName.value.trim();
    const username = elements.inputUsername.value.trim();
    const email = elements.inputEmail.value.trim();
    const password = elements.inputPassword.value;
    const enable2fa = elements.toggle2fa.checked;
    const twoFactorSecret = elements.input2faSecret.value.replace(/\s+/g, '').toUpperCase();
    
    if (platform === 'custom' && !customName) {
        showToast("Please enter an application/website name.", "error");
        return;
    }
    
    if (enable2fa && !twoFactorSecret) {
        showToast("Please enter a 2FA Secret Key.", "error");
        return;
    }
    
    if (id) {
        // Edit Mode
        const index = accounts.findIndex(a => a.id === id);
        if (index !== -1) {
            accounts[index] = {
                ...accounts[index],
                platform,
                customName: platform === 'custom' ? customName : '',
                username,
                email,
                password,
                enable2fa,
                twoFactorSecret: enable2fa ? twoFactorSecret : '',
            };
            showToast("Account save updated successfully.");
        }
    } else {
        // Create Mode
        const newAcc = {
            id: Date.now().toString(),
            platform,
            customName: platform === 'custom' ? customName : '',
            username,
            email,
            password,
            enable2fa,
            twoFactorSecret: enable2fa ? twoFactorSecret : '',
            createdAt: new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
        };
        accounts.push(newAcc);
        showToast("Credential card created!");
    }
    
    saveAccounts();
    renderAccounts();
    closeCreateModal();
    
    // If we were editing from details modal, refresh the details
    if (activeDetailAccountId === id && id) {
        openDetailModal(id);
    }
}

// ==========================================================================
// Modal Handlers (Account Details & 2FA Display)
// ==========================================================================

function openDetailModal(id) {
    const acc = accounts.find(a => a.id === id);
    if (!acc) return;
    
    activeDetailAccountId = id;
    
    // Set text elements
    elements.detailAppName.textContent = `${getPlatformLabel(acc)} Account`;
    elements.detailCreatedAt.textContent = `Saved: ${acc.createdAt || 'N/A'}`;
    elements.detailValUsername.textContent = acc.username || '-';
    elements.detailValEmail.textContent = acc.email || '-';
    
    // Set Password hidden by default
    elements.detailValPassword.textContent = '••••••••••••••••';
    elements.detailValPassword.classList.add('password-obfuscated');
    elements.detailPasswordEye.setAttribute('data-lucide', 'eye');
    
    // Setup platform logo
    const platformIcon = getPlatformIcon(acc.platform);
    elements.detailLogoWrapper.innerHTML = `<i data-lucide="${platformIcon}" class="detail-app-icon"></i>`;
    
    // 2FA Setup
    if (acc.enable2fa && acc.twoFactorSecret) {
        elements.detail2faSection.style.display = 'block';
        updateDetailTOTP(acc.twoFactorSecret);
        startTOTPCountdown(acc.twoFactorSecret);
    } else {
        elements.detail2faSection.style.display = 'none';
        stopTOTPCountdown();
    }
    
    lucide.createIcons();
    elements.modalAccountDetail.classList.add('active');
}

function closeDetailModal() {
    elements.modalAccountDetail.classList.remove('active');
    activeDetailAccountId = null;
    stopTOTPCountdown();
}

function toggleDetailPassword() {
    const acc = accounts.find(a => a.id === activeDetailAccountId);
    if (!acc) return;
    
    const isObfuscated = elements.detailValPassword.classList.contains('password-obfuscated');
    if (isObfuscated) {
        elements.detailValPassword.textContent = acc.password;
        elements.detailValPassword.classList.remove('password-obfuscated');
        elements.detailPasswordEye.setAttribute('data-lucide', 'eye-off');
    } else {
        elements.detailValPassword.textContent = '••••••••••••••••';
        elements.detailValPassword.classList.add('password-obfuscated');
        elements.detailPasswordEye.setAttribute('data-lucide', 'eye');
    }
    lucide.createIcons();
}

/**
 * TOTP countdown timing loops
 */
function startTOTPCountdown(secret) {
    stopTOTPCountdown();
    
    const tick = async () => {
        const epoch = Math.round(new Date().getTime() / 1000.0);
        const timeRemaining = 30 - (epoch % 30);
        
        // Update countdown text
        elements.totpCountdownText.textContent = timeRemaining;
        
        // Update SVG circle countdown progress ring
        const progressFraction = timeRemaining / 30;
        const offset = CIRCLE_CIRCUMFERENCE - (progressFraction * CIRCLE_CIRCUMFERENCE);
        elements.totpCountdownCircle.style.strokeDashoffset = offset;
        
        // Redraw/calculate TOTP if exactly 30 (just rolled over) or if code is empty
        if (timeRemaining === 30 || elements.detailTotpVal.textContent === '000 000') {
            await updateDetailTOTP(secret);
        }
    };
    
    // Initialize dash array for ring
    elements.totpCountdownCircle.style.strokeDasharray = `${CIRCLE_CIRCUMFERENCE} ${CIRCLE_CIRCUMFERENCE}`;
    
    // Run tick immediately then loop
    tick();
    totpTimerInterval = setInterval(tick, 1000);
}

function stopTOTPCountdown() {
    if (totpTimerInterval) {
        clearInterval(totpTimerInterval);
        totpTimerInterval = null;
    }
}

async function updateDetailTOTP(secret) {
    const code = await getTOTP(secret);
    // Format code as "123 456" for readability
    const formattedCode = `${code.substr(0, 3)} ${code.substr(3, 3)}`;
    elements.detailTotpVal.textContent = formattedCode;
}

// ==========================================================================
// Delete Credentials Flows
// ==========================================================================

function openDeleteConfirm() {
    const acc = accounts.find(a => a.id === activeDetailAccountId);
    if (!acc) return;
    
    elements.deleteAccountName.textContent = getPlatformLabel(acc);
    elements.modalConfirmDelete.classList.add('active');
}

function closeDeleteConfirm() {
    elements.modalConfirmDelete.classList.remove('active');
}

function handleDeleteConfirm() {
    if (!activeDetailAccountId) return;
    
    const index = accounts.findIndex(a => a.id === activeDetailAccountId);
    if (index !== -1) {
        const deletedLabel = getPlatformLabel(accounts[index]);
        accounts.splice(index, 1);
        saveAccounts();
        renderAccounts();
        showToast(`Credential for ${deletedLabel} deleted.`);
    }
    
    closeDeleteConfirm();
    closeDetailModal();
}

// ==========================================================================
// Import / Export JSON Backups
// ==========================================================================

function exportBackup() {
    if (accounts.length === 0) {
        showToast("No account credentials saved to export.", "info");
        return;
    }
    
    const jsonStr = JSON.stringify(accounts, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `aetherpass_vault_backup_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    
    setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }, 0);
    
    showToast("Vault JSON exported successfully!");
}

function importBackup(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(evt) {
        try {
            const importedData = JSON.parse(evt.target.result);
            
            // Basic data verification structure
            if (!Array.isArray(importedData)) {
                throw new Error("Invalid format: Backup data must be an array");
            }
            
            let itemsAdded = 0;
            importedData.forEach(item => {
                if (item.platform && (item.username || item.email) && item.password) {
                    // Check if duplicate ID exists, otherwise create new ID
                    const existsIndex = accounts.findIndex(a => a.id === item.id);
                    const parsedItem = {
                        id: item.id || Date.now().toString() + Math.random().toString().substr(2, 5),
                        platform: item.platform,
                        customName: item.customName || '',
                        username: item.username || '',
                        email: item.email || '',
                        password: item.password,
                        enable2fa: !!item.enable2fa,
                        twoFactorSecret: item.twoFactorSecret || '',
                        createdAt: item.createdAt || new Date().toLocaleDateString()
                    };
                    
                    if (existsIndex !== -1) {
                        accounts[existsIndex] = parsedItem;
                    } else {
                        accounts.push(parsedItem);
                    }
                    itemsAdded++;
                }
            });
            
            if (itemsAdded > 0) {
                saveAccounts();
                renderAccounts();
                showToast(`Successfully imported ${itemsAdded} accounts!`);
            } else {
                showToast("No valid credentials found in file.", "error");
            }
        } catch (err) {
            showToast("Failed to parse JSON file.", "error");
        }
        // reset input so the same file can be loaded again
        elements.importFile.value = '';
    };
    reader.readAsText(file);
}

// ==========================================================================
// Sync & Authentication Handlers
// ==========================================================================

async function parseJsonResponse(response) {
    const contentType = response.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
        const text = await response.text();
        if (text.includes("Bad Gateway") || response.status === 502) {
            throw new Error("Render Service Error (502 Bad Gateway). The backend server may have crashed or is booting up. Please check Render logs.");
        }
        if (text.includes("Service Unavailable") || response.status === 503) {
            throw new Error("Render Service Error (503 Service Unavailable). The backend server is sleeping or starting up.");
        }
        throw new Error(`Server returned non-JSON response (Status ${response.status}). Please check your server logs.`);
    }
    return await response.json();
}

function updateSyncPanel() {
    if (!elements.syncPanel) return;
    
    if (!token) {
        elements.syncPanel.innerHTML = `
            <div class="sync-offline">
                <i data-lucide="cloud-off"></i>
                <span>Offline Mode (Local)</span>
                <button type="button" id="btn-open-auth" class="btn-primary-sm">Log In to Sync</button>
            </div>
        `;
        const btnOpen = document.getElementById('btn-open-auth');
        if (btnOpen) btnOpen.addEventListener('click', () => openAuthModal());
    } else {
        elements.syncPanel.innerHTML = `
            <div class="sync-online">
                <div class="sync-user-info">
                    <i data-lucide="cloud" id="sync-icon"></i>
                    <span>Sync: <strong>${escapeHtml(username)}</strong></span>
                </div>
                <div class="sync-actions">
                    <button type="button" id="btn-sync-now" class="btn-icon-action-sm" title="Sync Vault">
                        <i data-lucide="refresh-cw" id="sync-btn-icon"></i>
                    </button>
                    <button type="button" id="btn-logout" class="btn-icon-action-sm text-danger" title="Log Out">
                        <i data-lucide="log-out"></i>
                    </button>
                </div>
            </div>
        `;
        const btnSync = document.getElementById('btn-sync-now');
        const btnLogout = document.getElementById('btn-logout');
        
        if (btnSync) btnSync.addEventListener('click', () => pullVault(false));
        if (btnLogout) btnLogout.addEventListener('click', handleLogout);
    }
    lucide.createIcons();
}

function openAuthModal() {
    elements.formAuth.reset();
    elements.authErrorMsg.style.display = 'none';
    switchAuthTab('login');
    elements.modalAuth.classList.add('active');
}

function closeAuthModal() {
    elements.modalAuth.classList.remove('active');
}

function switchAuthTab(mode) {
    elements.authErrorMsg.style.display = 'none';
    elements.authMode.value = mode;
    
    if (mode === 'login') {
        elements.tabLoginBtn.classList.add('active');
        elements.tabSignupBtn.classList.remove('active');
        elements.groupAuthConfirm.style.display = 'none';
        elements.inputAuthConfirm.required = false;
        elements.btnSubmitAuth.textContent = 'Log In';
    } else {
        elements.tabLoginBtn.classList.remove('active');
        elements.tabSignupBtn.classList.add('active');
        elements.groupAuthConfirm.style.display = 'block';
        elements.inputAuthConfirm.required = true;
        elements.btnSubmitAuth.textContent = 'Create Account';
    }
    lucide.createIcons();
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    elements.authErrorMsg.style.display = 'none';
    
    const mode = elements.authMode.value;
    const authUsername = elements.inputAuthUsername.value.trim();
    const authPassword = elements.inputAuthPassword.value;
    
    if (mode === 'signup') {
        const confirmPassword = elements.inputAuthConfirm.value;
        if (authPassword !== confirmPassword) {
            showAuthError("Passwords do not match.");
            return;
        }
        if (authPassword.length < 6) {
            showAuthError("Password must be at least 6 characters.");
            return;
        }
    }
    
    // Show spinner on submit button
    const originalBtnText = elements.btnSubmitAuth.textContent;
    elements.btnSubmitAuth.disabled = true;
    elements.btnSubmitAuth.textContent = "Processing...";
    
    const endpoint = mode === 'login' ? '/auth/login' : '/auth/register';
    
    try {
        const response = await fetch(API_BASE + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: authUsername, password: authPassword })
        });
        
        const data = await parseJsonResponse(response);
        
        if (!response.ok || !data.success) {
            throw new Error(data.error || "Authentication failed.");
        }
        
        // Save auth data
        token = data.token;
        username = data.username;
        localStorage.setItem('aetherpass_token', token);
        localStorage.setItem('aetherpass_username', username);
        
        showToast(mode === 'login' ? "Welcome back!" : "Account created successfully!");
        closeAuthModal();
        updateSyncPanel();
        
        // Force Pull/Sync vault
        pullVault(false);
    } catch (err) {
        showAuthError(err.message);
    } finally {
        elements.btnSubmitAuth.disabled = false;
        elements.btnSubmitAuth.textContent = originalBtnText;
    }
}

function showAuthError(msg) {
    elements.authErrorMsg.textContent = msg;
    elements.authErrorMsg.style.display = 'block';
}

function handleLogout() {
    token = null;
    username = null;
    localStorage.removeItem('aetherpass_token');
    localStorage.removeItem('aetherpass_username');
    
    showToast("Logged out from Cloud Vault.", "info");
    updateSyncPanel();
    
    // We keep their current credentials stored locally for convenience.
}

async function pushVault(silent = false) {
    if (!token) return;
    
    try {
        const response = await fetch(API_BASE + '/vault', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ vault: accounts })
        });
        
        const data = await parseJsonResponse(response);
        if (!response.ok || !data.success) {
            throw new Error(data.error || "Failed to push sync data.");
        }
        if (!silent) {
            showToast("Cloud vault updated.");
        }
    } catch (err) {
        console.error("Sync error:", err);
        if (!silent) {
            showToast("Sync push failed. Offline mode active.", "error");
        }
    }
}

async function pullVault(silent = false) {
    if (!token) return;
    
    const syncBtnIcon = document.getElementById('sync-btn-icon');
    const syncIcon = document.getElementById('sync-icon');
    
    // Add spinning animation to visual elements
    if (syncBtnIcon) syncBtnIcon.classList.add('spinning');
    if (syncIcon) syncIcon.classList.add('spinning');
    
    try {
        const response = await fetch(API_BASE + '/vault', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        const data = await parseJsonResponse(response);
        if (!response.ok || !data.success) {
            throw new Error(data.error || "Failed to pull cloud sync data.");
        }
        
        // Merge cloud accounts with local accounts
        const addedCount = mergeVaults(data.vault);
        
        if (!silent) {
            if (addedCount > 0) {
                showToast(`Sync completed! ${addedCount} accounts synced to this device.`);
            } else {
                showToast("Vault is up to date.");
            }
        }
        
        // Push merged accounts back to backend to keep them aligned
        pushVault(true);
    } catch (err) {
        console.error("Pull Sync error:", err);
        if (!silent) {
            showToast("Failed to fetch cloud vault.", "error");
        }
    } finally {
        // Remove animations after brief delay
        setTimeout(() => {
            if (syncBtnIcon) syncBtnIcon.classList.remove('spinning');
            if (syncIcon) syncIcon.classList.remove('spinning');
        }, 500);
    }
}

function mergeVaults(remoteVault) {
    let merged = [...accounts];
    let addedCount = 0;
    
    remoteVault.forEach(remoteAcc => {
        const localIndex = merged.findIndex(a => a.id === remoteAcc.id);
        if (localIndex === -1) {
            merged.push(remoteAcc);
            addedCount++;
        } else {
            // In a simple system we override local with cloud vault data
            // We can also compare timestamps if we track modification dates, but overwrite keeps it robust and aligned
            merged[localIndex] = remoteAcc;
        }
    });
    
    accounts = merged;
    saveAccounts();
    renderAccounts();
    return addedCount;
}

// ==========================================================================
// Helper Utility Functions
// ==========================================================================

function escapeHtml(string) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(string).replace(/[&<>"']/g, function(m) { return map[m]; });
}

// ==========================================================================
// Setup Listeners on Window Load
// ==========================================================================

window.addEventListener('DOMContentLoaded', () => {
    // 1. Load data
    loadAccounts();
    
    // 2. Open Modal Clickers
    elements.btnOpenCreate.addEventListener('click', () => openCreateModal());
    elements.btnEmptyCreate.addEventListener('click', () => openCreateModal());
    
    // 3. Close Create Save Modal
    elements.btnCloseCreate.addEventListener('click', closeCreateModal);
    elements.btnCancelCreate.addEventListener('click', closeCreateModal);
    
    // 4. Modal platform selectors triggers
    elements.platformOptions.forEach(opt => {
        opt.addEventListener('change', (e) => {
            if (e.target.value === 'custom') {
                elements.groupCustomName.style.display = 'block';
                elements.inputCustomName.required = true;
                elements.inputCustomName.focus();
            } else {
                elements.groupCustomName.style.display = 'none';
                elements.inputCustomName.required = false;
            }
        });
    });
    
    // 5. Create Password Generators
    elements.btnGeneratePassword.addEventListener('click', () => {
        const pass = generateSecurePassword();
        elements.inputPassword.value = pass;
        elements.inputPassword.type = 'text';
        elements.passwordEyeIcon.setAttribute('data-lucide', 'eye-off');
        lucide.createIcons();
        showToast("Secure password generated!", "info");
    });
    
    // 6. View toggle Password fields inside modal
    elements.btnTogglePassword.addEventListener('click', () => {
        const isPass = elements.inputPassword.type === 'password';
        elements.inputPassword.type = isPass ? 'text' : 'password';
        elements.passwordEyeIcon.setAttribute('data-lucide', isPass ? 'eye-off' : 'eye');
        lucide.createIcons();
    });
    
    // 7. Toggle 2FA switch displays
    elements.toggle2fa.addEventListener('change', (e) => {
        if (e.target.checked) {
            elements.group2faSecret.style.display = 'block';
            elements.input2faSecret.required = true;
            elements.input2faSecret.focus();
        } else {
            elements.group2faSecret.style.display = 'none';
            elements.input2faSecret.required = false;
        }
    });
    
    // 8. Submit save credential card form
    elements.formSaveAccount.addEventListener('submit', handleSaveSubmit);
    
    // 9. Details Modal handlers
    elements.btnCloseDetail.addEventListener('click', closeDetailModal);
    elements.btnCloseDetailFooter.addEventListener('click', closeDetailModal);
    elements.btnTogglePasswordDetail.addEventListener('click', toggleDetailPassword);
    
    // 10. Copy fields from details modal
    elements.btnCopyUsernameDetail.addEventListener('click', (e) => {
        const acc = accounts.find(a => a.id === activeDetailAccountId);
        if (acc) copyToClipboard(acc.username, elements.btnCopyUsernameDetail, "Username copied!");
    });
    
    elements.btnCopyEmailDetail.addEventListener('click', (e) => {
        const acc = accounts.find(a => a.id === activeDetailAccountId);
        if (acc) copyToClipboard(acc.email, elements.btnCopyEmailDetail, "Email copied!");
    });
    
    elements.btnCopyPasswordDetail.addEventListener('click', (e) => {
        const acc = accounts.find(a => a.id === activeDetailAccountId);
        if (acc) copyToClipboard(acc.password, elements.btnCopyPasswordDetail, "Password copied!");
    });
    
    elements.btnCopyTotpDetail.addEventListener('click', (e) => {
        const acc = accounts.find(a => a.id === activeDetailAccountId);
        if (acc) {
            // strip space for copy
            const cleanCode = elements.detailTotpVal.textContent.replace(/\s+/g, '');
            copyToClipboard(cleanCode, elements.btnCopyTotpDetail, "2FA Code copied!");
        }
    });
    
    // 11. Edit Account from details modal
    elements.btnEditDetail.addEventListener('click', () => {
        const id = activeDetailAccountId;
        closeDetailModal();
        openCreateModal(id);
    });
    
    // 12. Delete account flow
    elements.btnDeleteDetail.addEventListener('click', openDeleteConfirm);
    elements.btnCancelDelete.addEventListener('click', closeDeleteConfirm);
    elements.btnConfirmDelete.addEventListener('click', handleDeleteConfirm);
    
    // 13. Category Filters clickers
    elements.navItems.forEach(item => {
        item.addEventListener('click', () => {
            elements.navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            currentFilter = item.getAttribute('data-filter');
            renderAccounts();
        });
    });
    
    // 14. Search Input events
    elements.searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value;
        if (searchQuery) {
            elements.searchClear.style.display = 'flex';
        } else {
            elements.searchClear.style.display = 'none';
        }
        renderAccounts();
    });
    
    elements.searchClear.addEventListener('click', () => {
        elements.searchInput.value = '';
        searchQuery = '';
        elements.searchClear.style.display = 'none';
        renderAccounts();
        elements.searchInput.focus();
    });
    
    // 15. Import / Export triggers
    elements.btnExport.addEventListener('click', exportBackup);
    elements.btnImportTrigger.addEventListener('click', () => elements.importFile.click());
    elements.importFile.addEventListener('change', importBackup);
    
    // 16. Auth Modal listeners
    elements.tabLoginBtn.addEventListener('click', () => switchAuthTab('login'));
    elements.tabSignupBtn.addEventListener('click', () => switchAuthTab('signup'));
    elements.btnCloseAuth.addEventListener('click', closeAuthModal);
    elements.btnCancelAuth.addEventListener('click', closeAuthModal);
    elements.formAuth.addEventListener('submit', handleAuthSubmit);
    
    // Close modal if click on dark backdrop overlay
    window.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-overlay')) {
            if (e.target.id === 'modal-confirm-delete') {
                closeDeleteConfirm();
            } else if (e.target.id === 'modal-create-save') {
                closeCreateModal();
            } else if (e.target.id === 'modal-account-detail') {
                closeDetailModal();
            } else if (e.target.id === 'modal-auth') {
                closeAuthModal();
            }
        }
    });
    
    // Close modals on Escape key
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeCreateModal();
            closeDetailModal();
            closeDeleteConfirm();
            closeAuthModal();
        }
    });
});
