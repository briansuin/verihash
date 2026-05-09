import { SelectDirectory, SaveConfig, StartWatchdog, TriggerMint, GetDID, LoadConfig, GetWorkspaceFiles, GetLedger, ExportCredentialJSON, RestoreDataFromSync, GenerateHTMLReport, RevokeCredential, VerifyChain, VerifyCredential, SaveToFile, GetWalletStatus, UnlockWallet, InitWallet, MigrateWallet, GetMnemonic, LockVault, ToggleAutoStart, IsAutoStartEnabled, ImportMnemonic, UpdateIgnoredPatterns, SaveSessionIgnores, ResolveDroppedPath, BroadcastVC, GetBroadcastStatus, ResetBroadcastVC, DeleteBroadcastVC, GetProfileIndex, GetProfileInfo, SaveProfileInfo, GetAppVersion, CheckForUpdate, ApplyUpdate, WipeIdentity, RestartApp } from '../wailsjs/go/main/App';
import { EventsOn, WindowGetSize, WindowSetSize, OnFileDrop } from '../wailsjs/runtime/runtime';

document.addEventListener('DOMContentLoaded', async () => {

    // ======== WALLET LOCK SCREEN ========
    // Must resolve before any other UI interaction
    const walletOverlay = document.getElementById('wallet-overlay');
    const walletSubtitle = document.getElementById('wallet-subtitle');

    function showWalletScreen(screenId, subtitle) {
        walletOverlay.style.display = 'flex';
        walletSubtitle.innerText = subtitle;
        ['wallet-screen-unlock', 'wallet-screen-init', 'wallet-screen-migrate', 'wallet-screen-mnemonic', 'wallet-screen-restore'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = (id === screenId) ? 'block' : 'none';
        });
    }
    function hideWalletOverlay() {
        walletOverlay.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => { walletOverlay.style.display = 'none'; }, 300);
    }

    // Inject a quick fadeOut keyframe if not present
    if (!document.getElementById('wallet-fadeout-style')) {
        const s = document.createElement('style');
        s.id = 'wallet-fadeout-style';
        s.textContent = '@keyframes fadeOut { from{opacity:1} to{opacity:0} }';
        document.head.appendChild(s);
    }

    async function handleWalletAction(btn, statusEl, asyncFn) {
        btn.disabled = true;
        statusEl.className = 'wallet-status';
        statusEl.innerText = 'Processing...';
        try {
            const result = JSON.parse(await asyncFn());
            if (result.error) {
                statusEl.className = 'wallet-status err';
                statusEl.innerText = '\u2715 ' + result.error;
            } else {
                statusEl.className = 'wallet-status';
                statusEl.innerText = '\u2713 Success!';
                setTimeout(hideWalletOverlay, 500);
            }
        } catch (e) {
            statusEl.className = 'wallet-status err';
            statusEl.innerText = '\u2715 Error: ' + e;
        } finally {
            btn.disabled = false;
        }
    }

    // Check wallet state on startup
    const walletState = await GetWalletStatus();
    if (walletState === 'encrypted') {
        showWalletScreen('wallet-screen-unlock', 'VAULT LOCKED');
        const btn = document.getElementById('btn-wallet-unlock');
        const status = document.getElementById('wallet-unlock-status');
        const pwd = document.getElementById('wallet-unlock-pwd');
        pwd.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); });
        btn.addEventListener('click', () => handleWalletAction(btn, status, () => {
            return UnlockWallet(pwd.value);
        }));
        pwd.focus();
    } else if (walletState === 'new') {
        const mnemonic = await GetMnemonic();
        showWalletScreen('wallet-screen-mnemonic', 'SEED RECOVERY PHRASE');

        const mnemonicDisplay = document.getElementById('mnemonic-display');
        mnemonicDisplay.innerHTML = '';
        mnemonic.split(' ').forEach((word, index) => {
            const wordEl = document.createElement('div');
            wordEl.className = 'mnemonic-word';
            wordEl.setAttribute('data-index', (index + 1) + '.');
            wordEl.innerText = word;
            mnemonicDisplay.appendChild(wordEl);
        });

        const checkSaved = document.getElementById('check-mnemonic-saved');
        const btnNext = document.getElementById('btn-mnemonic-next');
        checkSaved.addEventListener('change', () => {
            btnNext.disabled = !checkSaved.checked;
        });

        btnNext.addEventListener('click', () => {
            showWalletScreen('wallet-screen-init', 'INITIALIZE VAULT');
            const btn = document.getElementById('btn-wallet-init');
            const status = document.getElementById('wallet-init-status');
            const pwd = document.getElementById('wallet-init-pwd');
            const confirm = document.getElementById('wallet-init-pwd-confirm');
            btn.addEventListener('click', () => handleWalletAction(btn, status, () => {
                return InitWallet(pwd.value, confirm.value);
            }));
            pwd.focus();
        });

        const btnShowRestore = document.getElementById('btn-show-restore');
        const btnBackToNew = document.getElementById('btn-back-to-new');
        if (btnShowRestore) btnShowRestore.addEventListener('click', () => showWalletScreen('wallet-screen-restore', 'RESTORE FROM RECOVERY PHRASE'));
        if (btnBackToNew) btnBackToNew.addEventListener('click', () => showWalletScreen('wallet-screen-mnemonic', 'SEED RECOVERY PHRASE'));

        const btnRestoreInit = document.getElementById('btn-wallet-restore');
        if (btnRestoreInit) {
            btnRestoreInit.addEventListener('click', async () => {
                const mnemonicRaw = document.getElementById('wallet-restore-mnemonic').value;
                const mnemonic = mnemonicRaw.trim().replace(/\s+/g, ' ').toLowerCase();
                const pwd = document.getElementById('wallet-restore-pwd').value;
                const confirm = document.getElementById('wallet-restore-pwd-confirm').value;
                const status = document.getElementById('wallet-restore-status');
                
                status.className = 'wallet-status err';
                if (!mnemonic) { status.innerText = '\u2715 Please enter recovery phrase'; return; }
                if (pwd.length < 8) { status.innerText = '\u2715 Password must be at least 8 chars'; return; }
                if (pwd !== confirm) { status.innerText = '\u2715 Passwords do not match'; return; }
                
                btnRestoreInit.disabled = true;
                status.className = 'wallet-status';
                status.innerText = 'Restoring identity...';
                try {
                    const resultJSON = await ImportMnemonic(mnemonic, pwd, confirm);
                    const result = JSON.parse(resultJSON);
                    if (result.error) {
                        status.className = 'wallet-status err';
                        status.innerText = '\u2715 ' + result.error;
                    } else {
                        status.className = 'wallet-status ok';
                        status.innerText = '\u2713 Identity Restored! Restarting node...';
                        setTimeout(() => location.reload(), 1500);
                    }
                } catch (e) {
                    status.className = 'wallet-status err';
                    status.innerText = '\u2715 Error: ' + e;
                } finally {
                    btnRestoreInit.disabled = false;
                }
            });
        }
    } else if (walletState === 'plaintext') {
        showWalletScreen('wallet-screen-migrate', 'SECURITY UPGRADE REQUIRED');
        const btn = document.getElementById('btn-wallet-migrate');
        const status = document.getElementById('wallet-migrate-status');
        const pwd = document.getElementById('wallet-migrate-pwd');
        const confirm = document.getElementById('wallet-migrate-pwd-confirm');
        btn.addEventListener('click', () => handleWalletAction(btn, status, () => {
            return MigrateWallet(pwd.value, confirm.value);
        }));
        pwd.focus();
    }
    // 'unlocked' state: overlay stays hidden, proceed normally

    // References
    const aiEngineSelect = document.getElementById('ai-engine');
    const cloudConfigGroup = document.getElementById('cloud-config-group');
    const modelNameInput = document.getElementById('model-name');
    const apiKeyInput = document.getElementById('api-key');

    const workspaceStack = document.getElementById('workspace-stack');
    const btnSelectDir = document.getElementById('btn-select-dir');
    const nodeDid = document.getElementById('node-did');

    const telemetryPanel = document.getElementById('telemetry-panel');
    const workspaceView = document.getElementById('workspace-view');
    const activeWorkspaceName = document.getElementById('active-workspace-name');
    const fileTreeContainer = document.getElementById('file-tree-container');
    const btnSelectAll = document.getElementById('btn-select-all');
    const btnDeselectAll = document.getElementById('btn-deselect-all');
    const btnIgnoreSelected = document.getElementById('btn-ignore-selected');
    const btnIgnoreDir = document.getElementById('btn-ignore-dir');
    const dirIgnoreDropdown = document.getElementById('dir-ignore-dropdown');
    const dirIgnoreList = document.getElementById('dir-ignore-list');

    const consoleOutput = document.getElementById('console-output');
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.getElementById('status-text');
    const btnMint = document.getElementById('btn-mint');
    const body = document.getElementById('app-body');
    const matrixCanvas = document.getElementById('matrix-canvas');
    const sidebar = document.getElementById('sidebar');
    const btnSidebarToggle = document.getElementById('btn-sidebar-toggle');

    // Custom dropdown references (must be declared here --  used in boot sequence)
    const cyberSelect = document.getElementById('cyber-select');
    const cyberTrigger = document.getElementById('cyber-select-trigger');
    const cyberLabel = document.getElementById('cyber-select-label');
    const cyberDropdown = document.getElementById('cyber-select-dropdown');

    // Ledger & Tab references
    const viewWorkbench = document.getElementById('view-workbench');
    const viewLedger = document.getElementById('view-ledger');
    const tabWorkbench = document.getElementById('tab-workbench');
    const tabLedger = document.getElementById('tab-ledger');
    const ledgerContainer = document.getElementById('ledger-container');
    const credentialDrawer = document.getElementById('credential-drawer');
    const drawerVcId = document.getElementById('drawer-vc-id');
    const drawerAiInsight = document.getElementById('drawer-ai-insight');
    const drawerFilePaths = document.getElementById('drawer-file-paths');
    const btnRefreshLedger = document.getElementById('btn-refresh-ledger');
    const btnVerifyChain = document.getElementById('btn-verify-chain');
    const btnCloseDrawer = document.getElementById('btn-close-drawer');
    const btnRevokeCredential = document.getElementById('btn-revoke-credential');
    const revokeStatus = document.getElementById('revoke-status');
    const btnBroadcastGist = document.getElementById('btn-broadcast-gist');
    const broadcastStatus = document.getElementById('broadcast-status');
    // Chain status bar elements
    const chainStatusBar = document.getElementById('chain-status-bar');
    const chainStatusIcon = document.getElementById('chain-status-icon');
    const chainStatusLabel = document.getElementById('chain-status-label');
    const chainStats = document.getElementById('chain-stats');
    let activeVcId = null;
    let activeProjectContext = ''; // Track current workspace name

    // Cloud sync DOM refs (must be declared before boot sequence so renderSyncDirs works)
    const syncDirsContainer = document.getElementById('sync-dirs-container');
    const btnAddSyncDir = document.getElementById('btn-add-sync-dir');

    // Ignore Patterns refs
    const ignorePatternsContainer = document.getElementById('ignore-patterns-container');
    const btnAddIgnore = document.getElementById('btn-add-ignore');
    const inputIgnorePattern = document.getElementById('input-ignore-pattern');

    // M/D State
    let workspaces = [];
    let cloudSyncDirs = [];
    let ignoredPatterns = [];
    let sessionIgnores = {}; // Per-workspace persistent UI filter tree states
    let collapsedDirs = {};  // Per-workspace filter-tree UI toggle states
    let activeWorkspaces = new Set(); // Multi-select: Set of selected workspace paths
    let lastClickedWsIndex = -1;      // For Shift+click range selection

    // Boot Sequence
    try {
        const did = await GetDID();
        nodeDid.innerText = did;

        const cfg = await LoadConfig();
        if (cfg.workspaces) workspaces = cfg.workspaces;
        if (cfg.cloud_sync_dirs) cloudSyncDirs = cfg.cloud_sync_dirs;
        if (cfg.ignored_patterns) ignoredPatterns = cfg.ignored_patterns;
        if (cfg.session_ignores) sessionIgnores = cfg.session_ignores;
        if (cfg.ai_engine) {
            aiEngineSelect.value = cfg.ai_engine;
            // Sync custom dropdown label from saved config
            const savedOpt = document.querySelector(`#cyber-select-dropdown [data-value="${cfg.ai_engine}"]`);
            if (savedOpt && cyberLabel) {
                cyberLabel.innerText = savedOpt.innerText;
                document.querySelectorAll('.cyber-select-option').forEach(o => o.classList.remove('active'));
                savedOpt.classList.add('active');
            }
        }
        if (cfg.model_name) modelNameInput.value = cfg.model_name;
        if (cfg.api_key) apiKeyInput.value = cfg.api_key;
        if (cfg.base_url) {
            const baseUrlInput = document.getElementById('base-url');
            if (baseUrlInput) baseUrlInput.value = cfg.base_url;
        }
        // GitHub PAT: show masked hint if configured
        const patInput = document.getElementById('input-github-pat');
        const patStatus = document.getElementById('broadcast-gist-status');
        if (cfg.github_pat && patInput) {
            patInput.placeholder = '●●●●●●●●●●●● (PAT configured)';
            if (patStatus) { patStatus.innerText = '✓ CONFIGURED'; patStatus.style.color = '#00ffcc'; }
        }

        renderWorkspaces();
        renderSyncDirs();
        renderIgnorePatterns();
        // Manually apply engine-specific UI state before triggering change,
        // so syncConfig does not overwrite correct values with UI defaults.
        if (cfg.ai_engine && cfg.ai_engine !== 'ollama') {
            cloudConfigGroup.style.display = 'block';
        }
        // Dispatch change to sync security badge, status dot, and placeholder hints
        aiEngineSelect.dispatchEvent(new Event('change'));
        if (workspaces.length > 0) {
            StartWatchdog();
        }
    } catch (e) { console.error("Boot error: ", e); }

    const btnWorkspaceToggle = document.getElementById('btn-workspace-toggle');
    const mainWorkspace = document.getElementById('main-workspace');
    if (btnWorkspaceToggle) {
        btnWorkspaceToggle.addEventListener('click', async () => {
            const isHidden = mainWorkspace.style.display === 'none';
            const sResizer = document.getElementById('sidebar-resizer');
            try {
                const size = await WindowGetSize();
                if (isHidden) {
                    mainWorkspace.style.display = '';
                    if (sResizer) sResizer.style.display = '';
                    document.body.classList.remove('mini-mode');
                    btnWorkspaceToggle.innerText = '[ < ]';
                    btnSidebarToggle.style.display = ''; // Show sidebar toggle
                    WindowSetSize(1120, size.h);
                } else {
                    mainWorkspace.style.display = 'none';
                    if (sResizer) sResizer.style.display = 'none';
                    document.body.classList.add('mini-mode');
                    btnWorkspaceToggle.innerText = '[ > ]';
                    btnSidebarToggle.style.display = 'none'; // Hide sidebar toggle
                    WindowSetSize(340, size.h);
                }
            } catch(e) { console.error(e); }
        });
    }

    // Visual Mechanics
    btnSidebarToggle.addEventListener('click', async () => {
        sidebar.classList.toggle('collapsed');
        const isCollapsed = sidebar.classList.contains('collapsed');
        try {
            const size = await WindowGetSize();
            if (isCollapsed) {
                btnSidebarToggle.innerText = '[ < ]';
                if (btnWorkspaceToggle) btnWorkspaceToggle.style.display = 'none'; // Hide workspace toggle
                WindowSetSize(800, size.h);
            } else {
                btnSidebarToggle.innerText = '[ > ]';
                if (btnWorkspaceToggle) btnWorkspaceToggle.style.display = ''; // Show workspace toggle
                WindowSetSize(1120, size.h);
            }
        } catch (err) { }
    });

    if (btnSelectAll && btnDeselectAll) {
        btnSelectAll.addEventListener('click', () => {
            const checkboxes = fileTreeContainer.querySelectorAll('.file-checkbox');
            checkboxes.forEach(cb => cb.checked = true);
        });

        btnDeselectAll.addEventListener('click', () => {
            const checkboxes = fileTreeContainer.querySelectorAll('.file-checkbox');
            checkboxes.forEach(cb => cb.checked = false);
        });

        if (btnIgnoreDir && dirIgnoreDropdown) {
            btnIgnoreDir.addEventListener('click', (e) => {
                e.stopPropagation();
                dirIgnoreDropdown.style.display = dirIgnoreDropdown.style.display === 'none' ? 'block' : 'none';
            });
            document.addEventListener('click', (e) => {
                if (dirIgnoreDropdown.style.display === 'block' && !dirIgnoreDropdown.contains(e.target)) {
                    dirIgnoreDropdown.style.display = 'none';
                }
            });
        }
    }

    EventsOn("log", (data) => {
        appendLog(data.msg, data.type);
    });

    function appendLog(msg, type = '') {
        const div = document.createElement('div');
        div.className = type;
        div.innerText = msg;
        consoleOutput.appendChild(div);
        // Double-insurance scroll: scrollTop for the container, scrollIntoView for the element
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
        div.scrollIntoView({ block: 'end', behavior: 'auto' });
    }

    // Config Sync Mechanism
    async function syncConfig() {
        const engine = aiEngineSelect.value;
        const key = apiKeyInput ? apiKeyInput.value : '';
        const model = modelNameInput ? modelNameInput.value : '';
        const baseUrlInput = document.getElementById('base-url');
        const baseUrl = baseUrlInput ? baseUrlInput.value : '';
        // Pass empty string for PAT — SaveConfig preserves the existing value when empty
        await SaveConfig(workspaces, engine, model, key, baseUrl, cloudSyncDirs, '');
    }

    // AI Engine change handler --  supports all 5 providers
    aiEngineSelect.addEventListener('change', (e) => {
        const engine = e.target.value;
        const securityBadge = document.getElementById('ai-security-badge');
        const baseUrlGroup = document.getElementById('base-url-group');

        if (engine === 'ollama') {
            cloudConfigGroup.style.display = 'none';
            statusDot.className = 'status-dot active-ollama';
            statusText.innerText = 'OLLAMA LINKED';
            if (securityBadge) { securityBadge.innerText = '[ 100% OFF-GRID ]'; securityBadge.style.color = '#00ffcc'; }
        } else {
            cloudConfigGroup.style.display = 'block';
            statusDot.className = 'status-dot active-gemini';
            if (securityBadge) { securityBadge.innerText = '[ CLOUD API ]'; securityBadge.style.color = '#ff9900'; }

            // Show engine-specific hints
            const hints = {
                gemini: { label: 'GEMINI LINKED', placeholder: 'e.g. gemini-2.5-flash' },
                claude: { label: 'CLAUDE LINKED', placeholder: 'e.g. claude-3-5-sonnet-latest' },
                deepseek: { label: 'DEEPSEEK LINKED', placeholder: 'e.g. deepseek-chat' },
                kimi: { label: 'KIMI LINKED', placeholder: 'e.g. moonshot-v1-8k' },
                siliconflow: { label: 'SILICONFLOW LINKED', placeholder: 'e.g. deepseek-ai/DeepSeek-V3' },
                qwen: { label: 'QWEN LINKED', placeholder: 'e.g. qwen-turbo' },
                minimax: { label: 'MINIMAX LINKED', placeholder: 'e.g. MiniMax-Text-01' },
                mistral: { label: 'MISTRAL LINKED', placeholder: 'e.g. mistral-large-latest' },
                openai: { label: 'OPENAI LINKED', placeholder: 'e.g. gpt-4o-mini' },
                custom: { label: 'CUSTOM ENDPOINT', placeholder: 'your-model-name' },
            };
            const h = hints[engine] || hints.gemini;
            statusText.innerText = h.label;
            if (modelNameInput) modelNameInput.placeholder = h.placeholder;

            // Show base URL field only for custom endpoints
            if (baseUrlGroup) {
                baseUrlGroup.style.display = (engine === 'custom') ? 'block' : 'none';
            }
        }
        syncConfig();
    });
    if (apiKeyInput) apiKeyInput.addEventListener('change', syncConfig);
    if (modelNameInput) modelNameInput.addEventListener('change', syncConfig);
    const baseUrlInput2 = document.getElementById('base-url');
    if (baseUrlInput2) baseUrlInput2.addEventListener('change', syncConfig);

    // ======== CLOUD SYNC MECHANICS ========

    function renderSyncDirs() {
        if (!syncDirsContainer) return;
        syncDirsContainer.innerHTML = '';
        if (cloudSyncDirs.length === 0) {
            syncDirsContainer.innerHTML = '<div style="color: #666; font-size: 0.75rem; font-style: italic;">No cloud mirrors bound.</div>';
            return;
        }
        cloudSyncDirs.forEach((dir, i) => {
            const block = document.createElement('div');
            block.className = 'workspace-block';
            block.style.display = 'flex';
            block.style.justifyContent = 'space-between';
            block.style.alignItems = 'center';
            block.style.padding = '8px 10px';
            block.style.position = 'relative'; // For tooltip positioning
            block.innerHTML = `
                <div class="workspace-path" title="Click to copy full path" style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; margin-right:10px; cursor:pointer; color:var(--primary); transition:all 0.2s;">☁ ${dir}</div>
                <div class="workspace-tooltip" style="bottom: 100%; left: 10px; margin-bottom: 5px;">${dir}</div>
                <button class="cyber-btn sm danger" data-index="${i}" style="font-size: 0.55rem; padding: 2px 6px;">[ UNBIND ]</button>
            `;

            const pathEl = block.querySelector('.workspace-path');
            pathEl.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(dir);
                    const originalText = pathEl.innerText;
                    pathEl.innerText = '\u2713 COPIED!';
                    pathEl.style.color = '#fff';
                    setTimeout(() => {
                        pathEl.innerText = originalText;
                        pathEl.style.color = 'var(--primary)';
                    }, 1000);
                } catch (err) {
                    console.error('Copy failed:', err);
                }
            });

            const unbindBtn = block.querySelector('button');
            unbindBtn.addEventListener('click', () => {
                cloudSyncDirs.splice(i, 1);
                renderSyncDirs();
                syncConfig();
            });
            syncDirsContainer.appendChild(block);
        });
    }

    if (btnAddSyncDir) {
        btnAddSyncDir.addEventListener('click', async () => {
            const dir = await SelectDirectory();
            if (!dir) return;
            // Add to list and update UI immediately (non-blocking)
            if (!cloudSyncDirs.includes(dir)) {
                cloudSyncDirs.push(dir);
                renderSyncDirs();
                syncConfig();
            }
            // DB snapshot will be synced to the new dir by Go backend on next mint/revoke
            // No historic repair needed — the entire DB is synced as verihash_ledger.db
        });
    }

    // ======== IGNORE PATTERNS MECHANICS ========
    function renderIgnorePatterns() {
        if (!ignorePatternsContainer) return;
        ignorePatternsContainer.innerHTML = '';
        if (ignoredPatterns.length === 0) {
            ignorePatternsContainer.innerHTML = '<div style="color: #666; font-size: 0.75rem; font-style: italic;">No manual exclusions set.</div>';
            return;
        }
        ignoredPatterns.forEach((pattern, i) => {
            const tag = document.createElement('div');
            tag.className = 'ignore-tag';
            // Use inline styles since I couldn't put them in css file previously without errors
            tag.style.cssText = 'display: flex; align-items: center; background: rgba(0, 255, 204, 0.08); border: 1px solid rgba(0, 255, 204, 0.3); color: var(--primary); font-size: 0.72rem; padding: 4px 8px; border-radius: 3px;';
            tag.innerHTML = `
                <span>${pattern}</span>
                <span class="remove-tag" data-index="${i}" style="margin-left:8px; cursor:pointer; color:rgba(0,255,204,0.5); font-size:0.9rem;">&times;</span>
            `;
            const removeBtn = tag.querySelector('.remove-tag');
            removeBtn.addEventListener('click', async () => {
                ignoredPatterns.splice(i, 1);
                await UpdateIgnoredPatterns(ignoredPatterns);
                renderIgnorePatterns();
                if (activeWorkspaces.size > 0) await renderFileTree([...activeWorkspaces][0]);
            });
            ignorePatternsContainer.appendChild(tag);
        });
    }

    if (btnAddIgnore) {
        const addPattern = async () => {
            const val = inputIgnorePattern.value.trim();
            if (val && !ignoredPatterns.includes(val)) {
                ignoredPatterns.push(val);
                inputIgnorePattern.value = '';
                await UpdateIgnoredPatterns(ignoredPatterns);
                renderIgnorePatterns();
                if (activeWorkspaces.size > 0) await renderFileTree([...activeWorkspaces][0]);
            }
        };
        btnAddIgnore.addEventListener('click', addPattern);
        inputIgnorePattern.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') addPattern();
        });
    }

    // ======== GITHUB PAT SAVE ========
    const btnSaveGitHubPAT = document.getElementById('btn-save-github-pat');
    if (btnSaveGitHubPAT) {
        btnSaveGitHubPAT.addEventListener('click', async () => {
            const patInput = document.getElementById('input-github-pat');
            const feedback = document.getElementById('github-pat-feedback');
            const patStatus = document.getElementById('broadcast-gist-status');
            const pat = patInput ? patInput.value.trim() : '';
            if (!pat) {
                if (feedback) { feedback.innerText = 'Enter a valid GitHub PAT.'; feedback.style.color = '#ff6666'; }
                return;
            }
            btnSaveGitHubPAT.disabled = true;
            btnSaveGitHubPAT.innerText = '[ SAVING... ]';
            try {
                const engine = aiEngineSelect.value;
                const key = apiKeyInput ? apiKeyInput.value : '';
                const model = modelNameInput ? modelNameInput.value : '';
                const baseUrlInput = document.getElementById('base-url');
                const baseUrl = baseUrlInput ? baseUrlInput.value : '';
                await SaveConfig(workspaces, engine, model, key, baseUrl, cloudSyncDirs, pat);
                if (feedback) { feedback.innerText = '✓ PAT saved. GitHub Gist channel is now active.'; feedback.style.color = '#00ffcc'; }
                if (patStatus) { patStatus.innerText = '✓ CONFIGURED'; patStatus.style.color = '#00ffcc'; }
                patInput.value = '';
                patInput.placeholder = '●●●●●●●●●●●● (PAT configured)';
            } catch (e) {
                if (feedback) { feedback.innerText = '✗ Error: ' + e; feedback.style.color = '#ff6666'; }
            } finally {
                btnSaveGitHubPAT.disabled = false;
                btnSaveGitHubPAT.innerText = '[ SAVE ]';
            }
        });
    }

    // ======== PUBLIC PROFILE MECHANICS ========

    // In-memory state for custom key-value fields
    let profileCustomFields = {}; // { key: value, ... }

    function renderProfileCustomFields() {
        const container = document.getElementById('profile-custom-fields');
        const empty = document.getElementById('profile-custom-empty');
        if (!container) return;
        container.innerHTML = '';
        const keys = Object.keys(profileCustomFields);
        if (empty) empty.style.display = keys.length === 0 ? 'block' : 'none';
        keys.forEach(key => {
            const row = document.createElement('div');
            row.style.cssText = 'display: flex; gap: 6px; align-items: center;';
            row.innerHTML = `
                <input type="text" class="profile-custom-key" value="${key}"
                    placeholder="key (e.g. email)"
                    style="flex: 0.4; padding: 5px 8px; font-size: 0.75rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(0,255,204,0.25); color: var(--primary); outline: none; font-family: var(--font-mono);">
                <input type="text" class="profile-custom-val" value="${profileCustomFields[key]}"
                    placeholder="value"
                    style="flex: 1; padding: 5px 8px; font-size: 0.75rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(0,255,204,0.25); color: var(--primary); outline: none; font-family: var(--font-mono);">
                <button class="cyber-btn sm profile-custom-remove" data-key="${key}"
                    style="font-size: 0.6rem; padding: 2px 6px; border-color: rgba(255,80,80,0.4); color: rgba(255,100,100,0.8); flex-shrink:0;">[ ✕ ]</button>
            `;
            // Live update on change
            row.querySelector('.profile-custom-key').addEventListener('change', (e) => {
                const newKey = e.target.value.trim();
                if (!newKey || newKey === key) return;
                const val = profileCustomFields[key];
                delete profileCustomFields[key];
                profileCustomFields[newKey] = val;
                renderProfileCustomFields();
            });
            row.querySelector('.profile-custom-val').addEventListener('change', (e) => {
                profileCustomFields[key] = e.target.value.trim();
            });
            row.querySelector('.profile-custom-remove').addEventListener('click', () => {
                delete profileCustomFields[key];
                renderProfileCustomFields();
            });
            container.appendChild(row);
        });
    }

    const btnAddProfileField = document.getElementById('btn-add-profile-field');
    if (btnAddProfileField) {
        btnAddProfileField.addEventListener('click', () => {
            // Generate a unique placeholder key
            let newKey = 'field_' + (Object.keys(profileCustomFields).length + 1);
            while (profileCustomFields[newKey] !== undefined) newKey += '_new';
            profileCustomFields[newKey] = '';
            renderProfileCustomFields();
            // Focus the newly added key input
            const container = document.getElementById('profile-custom-fields');
            if (container) {
                const inputs = container.querySelectorAll('.profile-custom-key');
                if (inputs.length > 0) inputs[inputs.length - 1].focus();
            }
        });
    }

    const btnSaveProfile = document.getElementById('btn-save-profile');
    if (btnSaveProfile) {
        btnSaveProfile.addEventListener('click', async () => {
            const nameEl = document.getElementById('profile-name');
            const websiteEl = document.getElementById('profile-website');
            const feedback = document.getElementById('profile-save-feedback');
            const name = nameEl ? nameEl.value.trim() : '';
            const website = websiteEl ? websiteEl.value.trim() : '';

            // Collect live values from rendered rows before saving
            const container = document.getElementById('profile-custom-fields');
            if (container) {
                const rows = container.querySelectorAll('div');
                rows.forEach(row => {
                    const keyEl = row.querySelector('.profile-custom-key');
                    const valEl = row.querySelector('.profile-custom-val');
                    if (keyEl && valEl) {
                        const k = keyEl.value.trim();
                        const v = valEl.value.trim();
                        if (k) profileCustomFields[k] = v;
                    }
                });
            }

            btnSaveProfile.disabled = true;
            btnSaveProfile.innerText = '[ SAVING... ]';
            try {
                const customJSON = JSON.stringify(profileCustomFields);
                const result = JSON.parse(await SaveProfileInfo(name, website, customJSON));
                if (result.error) {
                    if (feedback) { feedback.innerText = '✗ ' + result.error; feedback.style.color = '#ff6666'; }
                } else {
                    if (feedback) { feedback.innerText = '✓ Profile saved. Index Gist will update shortly.'; feedback.style.color = '#00ffcc'; }
                    setTimeout(() => { if (feedback) feedback.innerText = ''; }, 4000);
                }
            } catch (e) {
                if (feedback) { feedback.innerText = '✗ Error: ' + e; feedback.style.color = '#ff6666'; }
            } finally {
                btnSaveProfile.disabled = false;
                btnSaveProfile.innerText = '[ SAVE PROFILE ]';
            }
        });
    }

    // (Profile loading is handled inside openIdentityModal below)

    // M/D Workspace Mechanics — Ctrl+click, Shift+click, single-click (Windows style)

    function renderWorkspaces() {
        workspaceStack.innerHTML = '';
        workspaces.forEach((ws, idx) => {
            const card = document.createElement('div');
            // Primary active = solid border; secondary multi-active = dashed border
            const isFirst = activeWorkspaces.size > 0 && ws === [...activeWorkspaces][0];
            const isInSet = activeWorkspaces.has(ws);
            let cardClass = 'workspace-card';
            if (isInSet) {
                cardClass += isFirst ? ' active' : ' multi-active';
            }
            card.className = cardClass;
            const baseName = ws.split(/[\/\\]/).pop();
            card.innerHTML = `
                <div class="path-text">.../${baseName}</div>
                <div class="workspace-tooltip">${ws}</div>
                <button class="btn-remove">&times;</button>
            `;
            card.addEventListener('click', (e) => {
                if (e.target.classList.contains('btn-remove')) {
                    workspaces = workspaces.filter(w => w !== ws);
                    activeWorkspaces.delete(ws);
                    if (lastClickedWsIndex >= workspaces.length) lastClickedWsIndex = workspaces.length - 1;
                    syncConfig();
                    renderWorkspaces();
                    updateView();
                    return;
                }

                if (e.ctrlKey || e.metaKey) {
                    // Ctrl+click: toggle this workspace in the set
                    if (activeWorkspaces.has(ws)) {
                        activeWorkspaces.delete(ws);
                    } else {
                        activeWorkspaces.add(ws);
                    }
                    lastClickedWsIndex = idx;
                } else if (e.shiftKey && lastClickedWsIndex !== -1) {
                    // Shift+click: range select from lastClickedWsIndex to idx
                    const lo = Math.min(lastClickedWsIndex, idx);
                    const hi = Math.max(lastClickedWsIndex, idx);
                    // Keep the anchor, add the range
                    for (let i = lo; i <= hi; i++) {
                        activeWorkspaces.add(workspaces[i]);
                    }
                } else {
                    // Plain click: select only this one
                    if (activeWorkspaces.size === 1 && activeWorkspaces.has(ws)) {
                        // Click on the sole active card → deselect
                        activeWorkspaces.clear();
                    } else {
                        activeWorkspaces.clear();
                        activeWorkspaces.add(ws);
                    }
                    lastClickedWsIndex = idx;
                }
                renderWorkspaces();
                updateView();
            });
            workspaceStack.appendChild(card);
        });
    }

    const actionFooter = document.getElementById('action-footer');
    const inputProjectName = document.getElementById('input-project-name');

    async function updateView() {
        if (activeWorkspaces.size === 0) {
            telemetryPanel.style.display = 'block';
            workspaceView.style.display = 'none';
            if (actionFooter) actionFooter.style.display = 'none';
            if (inputProjectName) inputProjectName.value = ''; // clear on deselect
        } else {
            telemetryPanel.style.display = 'none';
            workspaceView.style.display = 'block';
            if (actionFooter) actionFooter.style.display = 'flex';
            const wsArray = [...activeWorkspaces];
            if (wsArray.length === 1) {
                activeWorkspaceName.innerText = wsArray[0].split(/[\/\\]/).pop();
            } else {
                const names = wsArray.map(p => p.split(/[\/\\]/).pop());
                activeWorkspaceName.innerText = `[CROSS-PROJECT] × ${wsArray.length}: ${names.join(' + ')}`;
            }
            await renderFileTreeMulti(wsArray);
        }
    }


    // Multi-workspace file tree: loads each workspace in parallel and renders grouped sections
    async function renderFileTreeMulti(wsArray) {
        fileTreeContainer.innerHTML = '<div style="color:#888;">Fetching files from ' + wsArray.length + ' workspace(s)...</div>';
        try {
            // Parallel fetch all workspaces
            const allResults = await Promise.all(wsArray.map(ws => GetWorkspaceFiles(ws)));

            fileTreeContainer.innerHTML = '';

            let totalFiles = 0;
            for (let wi = 0; wi < wsArray.length; wi++) {
                const ws = wsArray[wi];
                const files = allResults[wi] || [];

                // --- Group header (always shown when multi-ws, or when single for consistency) ---
                if (wsArray.length > 1) {
                    const groupHeader = document.createElement('div');
                    groupHeader.className = 'workspace-group-header';
                    const baseName = ws.split(/[\/\\]/).pop();
                    groupHeader.innerHTML = `<i class="group-icon">📁</i> ${baseName.toUpperCase()}`;
                    fileTreeContainer.appendChild(groupHeader);
                }

                if (!files || files.length === 0) {
                    const emptyMsg = document.createElement('div');
                    emptyMsg.style.cssText = 'color:#666; font-size:0.75rem; padding: 4px 10px 8px; font-style:italic;';
                    emptyMsg.innerText = 'No files found in this workspace.';
                    fileTreeContainer.appendChild(emptyMsg);
                    continue;
                }

                // --- Render file items for this workspace ---
                // Reuse the single-workspace rendering logic, scoped to each ws
                renderWorkspaceFileItems(ws, files);
                totalFiles += files.length;
            }

            if (totalFiles === 0) {
                fileTreeContainer.innerHTML = '<div style="color:#888; font-size:0.8rem;">No files found in selected workspaces.</div>';
            }

            // Always populate the filter tree using the primary (first) workspace
            // The filter/session-ignore system is per-workspace and uses the first selected ws
            if (wsArray.length > 0) {
                await renderFileTree(wsArray[0]);
            }
        } catch (e) {
            fileTreeContainer.innerHTML = `<div class="err">Error loading tree: ${e}</div>`;
        }
    }

    // Renders file checkboxes for a single workspace into fileTreeContainer (appended, not replaced)
    function renderWorkspaceFileItems(ws, files) {
        const normalizedWs = ws.replace(/\\/g, '/');
        const localIgnores = sessionIgnores[ws] || [];

        files.forEach(file => {
            let relPath = file;
            if (file.toLowerCase().startsWith(normalizedWs.toLowerCase())) {
                relPath = file.substring(normalizedWs.length);
            }
            relPath = relPath.replace(/^[\/\\]/, '');
            if (!relPath) relPath = file.replace(/\\/g, '/').split('/').pop();

            // Apply session ignores (per workspace)
            const parts = relPath.split('/');
            let currentDir = '';
            let shouldIgnore = false;
            for (let i = 0; i < parts.length - 1; i++) {
                currentDir = currentDir ? (currentDir + '/' + parts[i]) : parts[i];
                if (localIgnores.includes('DIR:' + currentDir)) shouldIgnore = true;
                else if (localIgnores.includes('EXCEPT:' + currentDir)) shouldIgnore = false;
            }
            if (localIgnores.includes(file)) shouldIgnore = true;
            else if (localIgnores.includes('EXCEPT:' + relPath)) shouldIgnore = false;
            if (shouldIgnore) return;

            const item = document.createElement('label');
            item.className = 'file-tree-item';
            item.innerHTML = `
                <input type="checkbox" class="file-checkbox" value="${file}">
                <span class="file-path">${relPath}</span>
            `;
            fileTreeContainer.appendChild(item);
        });
    }

    async function renderFileTree(ws) {
        fileTreeContainer.innerHTML = '<div style="color:#888;">Fetching modifications...</div>';
        try {
            const files = await GetWorkspaceFiles(ws);
            fileTreeContainer.innerHTML = '';
            if (!files || files.length === 0) {
                fileTreeContainer.innerHTML = '<div style="color:#888; font-size:0.8rem;">No recent modifications detected.</div>';
                return;
            }
            const normalizedWs = ws.replace(/\\/g, '/');
            const localIgnores = sessionIgnores[ws] || [];

            // 1. Gather All Directories and Files (Nodes)
            const allNodes = new Set();
            files.forEach(file => {
                let relPath = file;
                if (file.toLowerCase().startsWith(normalizedWs.toLowerCase())) {
                    relPath = file.substring(normalizedWs.length);
                }
                relPath = relPath.replace(/^[\/\\]/, '');
                // Single-file workspace: ws === file, so relPath is empty → use basename
                if (!relPath) relPath = file.replace(/\\/g, '/').split('/').pop();
                
                const parts = relPath.split('/');
                let currentDir = "";
                // loop up to parts.length - 1 because the last part is the filename
                for (let i = 0; i < parts.length - 1; i++) {
                    currentDir = currentDir ? (currentDir + '/' + parts[i]) : parts[i];
                    allNodes.add('DIR:' + currentDir);
                }
                // Add the file as well
                allNodes.add('FILE:' + relPath + '|' + file);
            });

            // 2. Refresh the Dropdown Menu with Active Tree
            if (dirIgnoreList) {
                dirIgnoreList.innerHTML = '';
                if (allNodes.size === 0) {
                    dirIgnoreList.innerHTML = '<div style="color:#666; font-style:italic;">No files/dirs found.</div>';
                } else {
                    const sortedNodes = Array.from(allNodes).sort((a,b) => {
                        let aRel = a.startsWith('DIR:') ? a.substring(4) : a.substring(5, a.indexOf('|'));
                        let bRel = b.startsWith('DIR:') ? b.substring(4) : b.substring(5, b.indexOf('|'));
                        
                        let aParts = aRel.split('/');
                        let bParts = bRel.split('/');
                        
                        let minLen = Math.min(aParts.length, bParts.length);
                        for (let i = 0; i < minLen; i++) {
                            if (aParts[i] !== bParts[i]) {
                                // Depth mismatch identifies if one is a leaf (FILE) vs intermediate (DIR)
                                let aIsDir = (i < aParts.length - 1) || a.startsWith('DIR:');
                                let bIsDir = (i < bParts.length - 1) || b.startsWith('DIR:');
                                
                                if (!aIsDir && bIsDir) return -1; // File floats above Directory
                                if (aIsDir && !bIsDir) return 1;
                                
                                return aParts[i].localeCompare(bParts[i]);
                            }
                        }
                        return aParts.length - bParts.length;
                    });
                    
                    if (!collapsedDirs[ws]) {
                        collapsedDirs[ws] = [];
                        allNodes.forEach(nodeRaw => {
                            if (nodeRaw.startsWith('DIR:')) collapsedDirs[ws].push(nodeRaw.substring(4));
                        });
                    }
                    const localCollapsed = collapsedDirs[ws];
                    
                    sortedNodes.forEach(nodeRaw => {
                        const isNodeDir = nodeRaw.startsWith('DIR:');
                        let nodePath = "";
                        let fullPath = "";
                        let stateKey = "";
                        
                        if (isNodeDir) {
                            nodePath = nodeRaw.substring(4);
                            stateKey = nodeRaw;
                        } else {
                            const sepPos = nodeRaw.indexOf('|');
                            nodePath = nodeRaw.substring(5, sepPos);
                            fullPath = nodeRaw.substring(sepPos + 1);
                            stateKey = fullPath; // explicit absolute path ignore for files
                        }

                        // --- COLLAPSE CHECK (SKIP CHILDREN) ---
                        let isHiddenByCollapse = false;
                        for (let colDir of localCollapsed) {
                            if (nodePath.startsWith(colDir + '/')) {
                                isHiddenByCollapse = true;
                                break;
                            }
                        }
                        if (isHiddenByCollapse) return;

                        let parentIgnored = false;
                        const dirParts = nodePath.split('/');
                        let currentPath = "";
                        const loopLimit = isNodeDir ? dirParts.length - 1 : dirParts.length - 1;
                        for (let i = 0; i < loopLimit; i++) {
                            currentPath = currentPath ? (currentPath + '/' + dirParts[i]) : dirParts[i];
                            if (localIgnores.includes('DIR:' + currentPath)) parentIgnored = true;
                            if (localIgnores.includes('EXCEPT:' + currentPath)) parentIgnored = false;
                        }
                        
                        let isChecked = parentIgnored;
                        if (localIgnores.includes(stateKey)) isChecked = true;
                        if (localIgnores.includes('EXCEPT:' + nodePath)) isChecked = false;

                        // Mathematically perfect Indeterminate check: We look ahead at all actual descendants in sortedNodes
                        // If any descendant has an EXPLICIT rule that contradicts this directory's isChecked state, or if any descendant 
                        // resolves to a different effective state, our visual is indeterminate.
                        let isIndeterminate = false;
                        if (isNodeDir) {
                            let hasCheckedChild = false;
                            let hasUncheckedChild = false;
                            
                            // We can quickly parse allNodes to see if descendants resolve differently
                            allNodes.forEach(childRaw => {
                                const isChildDir = childRaw.startsWith('DIR:');
                                let childPath = isChildDir ? childRaw.substring(4) : childRaw.substring(5, childRaw.indexOf('|'));
                                
                                if (childPath.startsWith(nodePath + '/')) {
                                    // Calculate child's effective state
                                    let cParentIgnored = false;
                                    const cParts = childPath.split('/');
                                    let cCur = "";
                                    for (let i = 0; i < (isChildDir ? cParts.length - 1 : cParts.length - 1); i++) {
                                        cCur = cCur ? (cCur + '/' + cParts[i]) : cParts[i];
                                        if (localIgnores.includes('DIR:' + cCur)) cParentIgnored = true;
                                        if (localIgnores.includes('EXCEPT:' + cCur)) cParentIgnored = false;
                                    }
                                    let cStateKey = isChildDir ? 'DIR:' + childPath : childRaw.substring(childRaw.indexOf('|') + 1);
                                    let cChecked = cParentIgnored;
                                    if (localIgnores.includes(cStateKey)) cChecked = true;
                                    if (localIgnores.includes('EXCEPT:' + childPath)) cChecked = false;
                                    
                                    if (cChecked) hasCheckedChild = true;
                                    else hasUncheckedChild = true;
                                }
                            });
                            
                            if (hasCheckedChild && hasUncheckedChild) {
                                isIndeterminate = true;
                            }
                        }

                        const isException = parentIgnored && !isChecked;
                        const opacity = isChecked ? '0.4' : '1';
                        const fontColor = isException ? 'var(--primary)' : 'rgba(204,204,204,' + opacity + ')';
                        
                        // Calculate indent visually based on slash count
                        const depth = (nodePath.match(/\//g) || []).length;
                        const indent = depth * 10;
                        
                        const row = document.createElement('label');
                        row.style.cssText = `display: flex; align-items: center; gap: 6px; cursor: pointer; padding: 2px 0 2px ${indent}px; color: ${fontColor}; transition: 0.2s all;`;
                        
                        // Show just the basename of the node
                        const baseName = nodePath.split('/').pop();
                        const icon = isNodeDir ? '\ud83d\udcc1' : '\ud83d\udcc4'; // Folder vs Document emoji
                        const displayTitle = isNodeDir ? baseName.toUpperCase() : baseName;
                        const prefix = isException ? `\u2514 [EXC] ` : `\u2514 `;
                        
                        const isCollapsed = localCollapsed.includes(nodePath);
                        const toggleHtml = isNodeDir 
                            ? `<span class="tree-toggle" style="color: var(--primary); font-size: 0.7rem; font-weight: bold; width: 12px; display: inline-block; text-align: center;" title="Toggle folder contents">${isCollapsed ? '▸' : '▾'}</span>`
                            : `<span style="width: 12px; display: inline-block;"></span>`;
                        
                        row.innerHTML = `
                            <input type="checkbox" style="accent-color: #00ffcc; cursor: pointer; flex-shrink: 0;" ${isChecked ? 'checked' : ''}>
                            <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.65rem;" title="/${nodePath}">${prefix}${toggleHtml} ${icon} ${displayTitle}</span>
                        `;

                        const cb = row.querySelector('input');
                        if (isIndeterminate) {
                            cb.indeterminate = true;
                            // Adding a custom style class in case Windows default checkbox masks it
                            cb.classList.add('indeterminate-true');
                        }

                        cb.addEventListener('change', async (e) => {
                            if (!sessionIgnores[ws]) sessionIgnores[ws] = [];
                            let ignores = sessionIgnores[ws];
                            
                            const exceptKeyUse = 'EXCEPT:' + nodePath;
                            
                            if (cb.checked) {
                                if (parentIgnored) {
                                    ignores = ignores.filter(i => i !== exceptKeyUse);
                                } else {
                                    ignores.push(stateKey);
                                }
                            } else {
                                if (parentIgnored) {
                                    ignores.push(exceptKeyUse);
                                } else {
                                    ignores = ignores.filter(i => i !== stateKey);
                                }
                            }
                            sessionIgnores[ws] = ignores;
                            await SaveSessionIgnores(ws, ignores);
                            
                            // Keep menu open while checking/unchecking
                            e.stopPropagation();
                            await renderFileTree(ws);
                        });
                        
                        // Tree Collapser event
                        if (isNodeDir) {
                            const toggler = row.querySelector('.tree-toggle');
                            if (toggler) {
                                toggler.addEventListener('click', async (e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    if (localCollapsed.includes(nodePath)) {
                                        collapsedDirs[ws] = localCollapsed.filter(p => p !== nodePath);
                                    } else {
                                        collapsedDirs[ws].push(nodePath);
                                    }
                                    await renderFileTree(ws);
                                });
                            }
                        }

                        dirIgnoreList.appendChild(row);
                    });
                }
            }

            // 3. Render visible files
            files.forEach(file => {
                // Determine clean relative path trimming the workspace root
                let relPath = file;
                if (file.toLowerCase().startsWith(normalizedWs.toLowerCase())) {
                    relPath = file.substring(normalizedWs.length);
                }
                relPath = relPath.replace(/^[\/\\]/, '');
                // Single-file workspace: ws === file, so relPath is empty → use basename
                if (!relPath) relPath = file.replace(/\\/g, '/').split('/').pop();

                // Skip files if ANY of their parent directories are currently ignored (evaluating deepest rule)
                const parts = relPath.split('/');
                let currentDir = "";
                let shouldIgnore = false;
                for (let i = 0; i < parts.length - 1; i++) {
                    currentDir = currentDir ? (currentDir + '/' + parts[i]) : parts[i];
                    if (localIgnores.includes('DIR:' + currentDir)) {
                        shouldIgnore = true;
                    } else if (localIgnores.includes('EXCEPT:' + currentDir)) {
                        shouldIgnore = false;
                    }
                }
                
                // Explicit file ignore overrides directory rules
                if (localIgnores.includes(file)) {
                    shouldIgnore = true;
                } else if (localIgnores.includes('EXCEPT:' + relPath)) {
                    shouldIgnore = false;
                }

                if (shouldIgnore) return;

                const item = document.createElement('label');
                item.className = 'file-tree-item';

                // Default is unchecked for targeted selection UX
                item.innerHTML = `
                    <input type="checkbox" class="file-checkbox" value="${file}">
                    <span class="file-path">${relPath}</span>
                `;
                fileTreeContainer.appendChild(item);
            });
        } catch (e) {
            fileTreeContainer.innerHTML = `<div class="err">Error loading tree: ${e}</div>`;
        }
    }

    // Addition Handlers
    OnFileDrop(async (x, y, paths) => {
        if (paths && paths.length > 0) {
            for (const droppedPath of paths) {
                addWorkspace(droppedPath);
            }
        }
    }, true);

    btnSelectDir.addEventListener('click', async () => {
        const dir = await SelectDirectory();
        if (dir) addWorkspace(dir);
    });

    async function addWorkspace(dir) {
        if (!workspaces.includes(dir)) {
            workspaces.unshift(dir);
            await syncConfig();
            appendLog(`[SYSTEM] Workspace Hooked: ${dir}`, 'sys');
            StartWatchdog();
            renderWorkspaces();
        }
    }

    // Contextual Minting — supports single and multi-workspace
    btnMint.addEventListener('click', async () => {
        if (btnMint.classList.contains('disabled')) return;

        if (activeWorkspaces.size === 0) {
            alert("Error: Please select a Workspace Card from the right panel to specify the Minting Context.");
            return;
        }

        const selectedFiles = [];
        const checkboxes = fileTreeContainer.querySelectorAll('.file-checkbox:checked');
        checkboxes.forEach(cb => selectedFiles.push(cb.value));

        if (selectedFiles.length === 0) {
            alert("Error: No files selected in the current context view.");
            return;
        }

        btnMint.classList.add('disabled');
        btnMint.querySelector('.btn-text').innerText = 'COMPUTING...';
        statusDot.classList.add('pulsing');
        body.classList.add('minting-mode');
        startMatrixRain();

        // Capture current active workspaces then clear selection for UI reset
        const mintingWsArray = [...activeWorkspaces];
        const workspacePathParam = mintingWsArray.join('|');
        const contextLabel = mintingWsArray.map(p => p.split(/[\/\\]/).pop()).join(' + ');
        // Read optional user-supplied project name
        const projectNameVal = (inputProjectName ? inputProjectName.value.trim() : '') || '';

        try {
            activeWorkspaces.clear();
            renderWorkspaces();
            updateView();
            appendLog(`\n[ORACLE] Forging Cross-Project Credential [${contextLabel}] with ${selectedFiles.length} file(s)...`, 'sys');

            const resultJSON = await TriggerMint(selectedFiles, workspacePathParam, projectNameVal);
            try {
                const vc = JSON.parse(resultJSON);
                if (vc.error) {
                    appendLog(`[ORACLE ERROR] ${vc.error}`, 'err');
                } else {
                    appendLog('\n\u2605\u2605\u2605 SESSION CREDENTIAL MINTED \u2605\u2605\u2605', 'sys');
                    appendLog(`[VC_ID]  ${vc.id}`, 'sys');
                    appendLog(`[ISSUER] ${vc.issuer?.substring(0, 60)}...`, 'sys');
                    appendLog(`[DATE]   ${vc.issuanceDate}`, 'sys');
                    appendLog(`[FILES]  ${vc.credentialSubject?.proofOfWork?.files?.length || 0} files anchored`, 'sys');
                    appendLog('\n\u2192 View full credential in [ THE_LEDGER ] tab', 'sys');
                }
            } catch {
                appendLog('\n\u2605\u2605\u2605 SESSION CREDENTIAL MINTED \u2605\u2605\u2605', 'sys');
                appendLog(resultJSON.substring(0, 300) + '...', 'sys');
            }
        } catch (err) {
            appendLog(`[FATAL] Minting failed: ${err}`, 'err');
        } finally {
            stopMatrixRain();
            body.classList.remove('minting-mode');
            btnMint.classList.remove('disabled');
            btnMint.querySelector('.btn-text').innerText = 'MINT_CREDENTIAL';
            statusDot.classList.remove('pulsing');
        }
    });


    // Matrix
    let rainInterval;
    function startMatrixRain() {
        matrixCanvas.style.opacity = '0.15';
        const ctx = matrixCanvas.getContext('2d');
        matrixCanvas.width = window.innerWidth;
        matrixCanvas.height = window.innerHeight;
        const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%\"'#&_(),.;:?!\\|{}<>[]^~";
        const fontSize = 14;
        const columns = matrixCanvas.width / fontSize;
        const drops = [];
        for (let x = 0; x < columns; x++) drops[x] = 1;
        function draw() {
            ctx.fillStyle = 'rgba(11, 14, 20, 0.1)';
            ctx.fillRect(0, 0, matrixCanvas.width, matrixCanvas.height);
            ctx.fillStyle = '#00FFCC';
            ctx.font = fontSize + 'px monospace';
            for (let i = 0; i < drops.length; i++) {
                const text = letters.charAt(Math.floor(Math.random() * letters.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                if (drops[i] * fontSize > matrixCanvas.height && Math.random() > 0.95) drops[i] = 0;
                drops[i]++;
            }
        }
        rainInterval = setInterval(draw, 33);
    }

    function stopMatrixRain() {
        clearInterval(rainInterval);
        matrixCanvas.style.opacity = '0';
    }

    window.addEventListener('resize', () => {
        matrixCanvas.width = window.innerWidth;
        matrixCanvas.height = window.innerHeight;
    });

    // ======== P1: DID ONE-CLICK COPY ========
    const btnCopyDid = document.getElementById('btn-copy-did');
    const copyToast = document.getElementById('copy-toast');
    if (btnCopyDid) {
        btnCopyDid.addEventListener('click', async () => {
            const did = nodeDid.innerText;
            try {
                await navigator.clipboard.writeText(did);
            } catch {
                // Fallback for WebView2 where clipboard API may need permission
                const ta = document.createElement('textarea');
                ta.value = did;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }
            copyToast.style.display = 'block';
            setTimeout(() => { copyToast.style.display = 'none'; }, 1800);
        });
    }

    // ======== P1: FLUSH STACK ========
    const btnFlushStack = document.getElementById('btn-flush-stack');
    if (btnFlushStack) {
        btnFlushStack.addEventListener('click', () => {
            if (workspaces.length === 0) return;
            if (!confirm('Clear all workspace bindings?')) return;
            workspaces = [];
            activeWorkspaces.clear();
            syncConfig();
            renderWorkspaces();
            updateView();
        });
    }

    // ======== P2: CUSTOM CYBER SELECT ========
    // (variables declared at top to avoid TDZ in boot sequence)

    if (cyberTrigger) {
        cyberTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            cyberSelect.classList.toggle('open');
        });

        document.addEventListener('click', () => {
            cyberSelect.classList.remove('open');
        });

        cyberDropdown.querySelectorAll('.cyber-select-option').forEach(opt => {
            opt.addEventListener('click', (e) => {
                e.stopPropagation();
                const val = opt.dataset.value;
                cyberLabel.innerText = opt.innerText;
                cyberDropdown.querySelectorAll('.cyber-select-option').forEach(o => o.classList.remove('active'));
                opt.classList.add('active');
                cyberSelect.classList.remove('open');
                // Sync to the hidden native select and trigger its change event
                aiEngineSelect.value = val;
                aiEngineSelect.dispatchEvent(new Event('change'));
            });
        });
    }

    // ======== P2: ENGINE CONNECTIVITY RADAR ========
    const engineDot = document.getElementById('engine-dot');
    const engineStatusText = document.getElementById('engine-status-text');

    async function checkEngineStatus(engine) {
        if (!engineDot || !engineStatusText) return;
        engineDot.className = 'engine-dot checking';
        engineStatusText.innerText = 'Checking...';

        if (engine === 'ollama') {
            try {
                const start = Date.now();
                const res = await fetch('http://localhost:11434', { signal: AbortSignal.timeout(3000) });
                const ms = Date.now() - start;
                engineDot.className = 'engine-dot online';
                engineStatusText.innerText = `LOCAL node online \u2022 ms`;
            } catch {
                engineDot.className = 'engine-dot offline';
                engineStatusText.innerText = 'LOCAL node offline -- start Ollama';
            }
        } else {
            // For cloud, we just verify API key is set
            const key = apiKeyInput ? apiKeyInput.value.trim() : '';
            if (key.length > 10) {
                engineDot.className = 'engine-dot online';
                engineStatusText.innerText = 'CLOUD API key configured';
            } else {
                engineDot.className = 'engine-dot offline';
                engineStatusText.innerText = 'API key not set';
            }
        }
    }

    // Hook status check into engine change event
    aiEngineSelect.addEventListener('change', (e) => {
        checkEngineStatus(e.target.value);
    });
    // Initial check on boot
    setTimeout(() => checkEngineStatus(aiEngineSelect.value), 1200);

    // ======== P3: SETTINGS GEAR -- IDENTITY MODAL ========
    const btnSettings = document.getElementById('btn-settings');
    const identityModal = document.getElementById('identity-modal');
    const btnModalClose = document.getElementById('btn-modal-close');
    function openIdentityModal() {
        identityModal.classList.add('open');
        // Load public profile fields each time modal opens
        GetProfileInfo().then(raw => {
            try {
                const info = JSON.parse(raw);
                const nameEl = document.getElementById('profile-name');
                const websiteEl = document.getElementById('profile-website');
                if (nameEl) nameEl.value = info.name || '';
                if (websiteEl) websiteEl.value = info.website || '';
                profileCustomFields = info.custom || {};
                renderProfileCustomFields();
                const linkBadge = document.getElementById('profile-index-link-badge');
                const linkEl = document.getElementById('profile-index-link');
                if (info.index_gist_url && linkBadge && linkEl) {
                    linkEl.href = info.index_gist_url;
                    linkBadge.style.display = 'inline';
                }
            } catch (e) { console.warn('Profile load error:', e); }
        }).catch(e => console.warn('GetProfileInfo error:', e));
    }
    function closeIdentityModal() {
        identityModal.classList.remove('open');
    }

    if (btnSettings) btnSettings.addEventListener('click', openIdentityModal);
    if (btnModalClose) btnModalClose.addEventListener('click', closeIdentityModal);

    // Toggle Auto-Start logic
    const chkAutoStart = document.getElementById('chk-autostart');
    IsAutoStartEnabled().then(enabled => {
        if (chkAutoStart) chkAutoStart.checked = enabled;
    });
    if (chkAutoStart) {
        chkAutoStart.addEventListener('change', async (e) => {
            try {
                await ToggleAutoStart(e.target.checked);
            } catch (err) {
                console.error("AutoStart Toggle failed:", err);
                chkAutoStart.checked = !e.target.checked; // Revert visually
            }
        });
    }

    // Lock Vault logic
    const btnLock = document.getElementById('btn-lock');
    if (btnLock) {
        btnLock.addEventListener('click', async () => {
            await LockVault();
            location.reload(); // Native reload gracefully enters locked state
        });
    }

    // Close on overlay click
    if (identityModal) {
        identityModal.addEventListener('click', (e) => {
            if (e.target === identityModal) closeIdentityModal();
        });
    }

    // ======== P3: SIDEBAR DRAG RESIZE ========
    const sidebarResizer = document.getElementById('sidebar-resizer');
    const sidebarEl = document.getElementById('sidebar');
    if (sidebarResizer && sidebarEl) {
        let isResizing = false;
        sidebarResizer.addEventListener('mousedown', (e) => {
            isResizing = true;
            sidebarResizer.classList.add('dragging');
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
        });
        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;
            const appRect = document.querySelector('.app-layout').getBoundingClientRect();
            const newWidth = appRect.right - e.clientX;
            const clamped = Math.max(220, Math.min(500, newWidth));
            sidebarEl.style.width = clamped + 'px';
        });
        document.addEventListener('mouseup', () => {
            if (!isResizing) return;
            isResizing = false;
            sidebarResizer.classList.remove('dragging');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        });
    }

    // ======== TAB SWITCHING ========
    function switchView(view) {
        if (view === 'ledger') {
            viewWorkbench.style.display = 'none';
            viewLedger.style.display = 'flex';
            tabWorkbench.classList.remove('active');
            tabLedger.classList.add('active');
            renderLedger();
        } else {
            viewLedger.style.display = 'none';
            viewWorkbench.style.display = 'flex';
            tabLedger.classList.remove('active');
            tabWorkbench.classList.add('active');
        }
    }
    tabWorkbench.addEventListener('click', () => switchView('workbench'));
    tabLedger.addEventListener('click', () => switchView('ledger'));
    btnRefreshLedger.addEventListener('click', renderLedger);
    if (btnVerifyChain) btnVerifyChain.addEventListener('click', renderChainStatus);

    // ======== CHAIN STATUS RENDERER ========
    async function renderChainStatus() {
        if (!chainStatusBar) return;
        chainStatusBar.className = 'chain-status-bar';
        chainStatusIcon.className = 'chain-status-icon checking';
        chainStatusIcon.innerText = '\u29d7'; // hourglass
        chainStatusLabel.innerText = 'Verifying chain integrity...';
        chainStats.innerText = '';
        try {
            const raw = await VerifyChain();
            const r = JSON.parse(raw);
            if (r.intact) {
                chainStatusBar.classList.add('intact');
                chainStatusIcon.className = 'chain-status-icon intact';
                chainStatusIcon.innerText = '\u26d3'; // chains
                chainStatusLabel.innerText = 'CHAIN INTACT';
                const parts = [];
                if (r.total_blocks > 0) {
                    parts.push(`${r.active_blocks} ACTIVE`);
                    if (r.revoked_blocks > 0) parts.push(`${r.revoked_blocks} REVOKED`);
                    parts.push(`${r.total_blocks} TOTAL BLOCKS`);
                }
                chainStats.innerText = parts.length ? '\u00b7 ' + parts.join(' \u00b7 ') + ' \u00b7 ' + r.message : r.message;
            } else {
                chainStatusBar.classList.add('broken');
                chainStatusIcon.className = 'chain-status-icon broken';
                chainStatusIcon.innerText = '\u26a0'; // warning
                chainStatusLabel.innerText = 'CHAIN INTEGRITY FAILURE';
                const breakInfo = r.break_at_vc_id
                    ? `break at: ${r.break_at_vc_id.substring(9, 25)}...`
                    : '';
                chainStats.innerText = r.message + (breakInfo ? ' \u00b7 ' + breakInfo : '');
            }
        } catch (e) {
            chainStatusIcon.className = 'chain-status-icon broken';
            chainStatusIcon.innerText = '\u26a0'; // warning
            chainStatusLabel.innerText = 'VERIFY ERROR';
            chainStats.innerText = String(e);
        }
    }


    // ======== LEDGER RENDERING ========
    async function renderLedger() {
        ledgerContainer.innerHTML = '<div style="color:#888; font-size:0.8rem; padding:20px 0;">Querying credential archive...</div>';
        const viewportLayer = document.querySelector('#view-ledger .viewport-layer');
        if (viewportLayer) viewportLayer.style.display = '';
        credentialDrawer.style.display = 'none';
        credentialDrawer.style.flex = '';
        credentialDrawer.style.minHeight = '';
        activeVcId = null;
        // Kick off chain verification in parallel
        renderChainStatus();
        try {
            const entries = await GetLedger();
            ledgerContainer.innerHTML = '';
            if (!entries || entries.length === 0) {
                ledgerContainer.innerHTML = '<div style="color:#888; font-size:0.8rem; padding:20px 0;">[ LEDGER EMPTY ] --  No credentials have been minted yet.</div>';
                return;
            }
            entries.forEach(entry => {
                const row = document.createElement('div');
                row.className = 'ledger-entry';
                row.dataset.vcId = entry.vc_id;

                const ts = new Date(entry.timestamp * 1000);
                const dateStr = ts.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' });
                const timeStr = ts.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });

                const projectName = entry.project_context
                    ? entry.project_context.split(/[\/\\]/).pop()
                    : 'Unknown Project';

                const insightPreview = entry.ai_insight
                    ? entry.ai_insight.substring(0, 80) + (entry.ai_insight.length > 80 ? '...' : '')
                    : 'No AI insight recorded.';

                const fileCount = entry.file_paths
                    ? entry.file_paths.split(',').filter(f => f.trim()).length
                    : 0;

                row.innerHTML = `
                    <div class="ledger-ts">${dateStr}<br>${timeStr}</div>
                    <div>
                        <div class="ledger-project">${projectName}</div>
                        <div class="ledger-insight-preview">${insightPreview}</div>
                        ${entry.vc_hash ? `<div class="ledger-vc-hash">\u00bb  ${entry.vc_hash.substring(0, 32)}...</div>` : ''}
                        <div class="ledger-broadcast-badges" id="badges-${entry.vc_id.replace(/[^a-z0-9]/gi,'_')}" style="margin-top: 4px; display: flex; gap: 4px; flex-wrap: wrap;"></div>
                    </div>
                    <div class="ledger-badge">${fileCount} files</div>
                `;

                row.addEventListener('click', () => openDrawer(entry));
                ledgerContainer.appendChild(row);

                // Async-load broadcast status badges (fire-and-forget)
                const badgeContainerId = 'badges-' + entry.vc_id.replace(/[^a-z0-9]/gi, '_');
                GetBroadcastStatus(entry.vc_id).then(pubs => {
                    const container = document.getElementById(badgeContainerId);
                    if (!container || !pubs || pubs.length === 0) return;
                    pubs.forEach(pub => {
                        const badge = document.createElement('span');
                        const icons = { pending: '⏳', publishing: '📡', success: '✅', failed: '❌', revoked: '🚫' };
                        const icon = icons[pub.status] || '?';
                        const label = pub.channel.toUpperCase();
                        badge.style.cssText = 'font-size: 0.58rem; padding: 1px 5px; border-radius: 3px; background: rgba(0,0,0,0.4); border: 1px solid rgba(0,255,204,0.2); color: #aaa; cursor: default; white-space: nowrap;';
                        badge.title = `${label}: ${pub.status}${pub.last_error ? ' — ' + pub.last_error : ''}${pub.remote_url ? '\n' + pub.remote_url : ''}`;
                        badge.innerText = `${icon} ${label}`;
                        if (pub.status === 'success' && pub.remote_url) {
                            badge.style.cursor = 'pointer';
                            badge.style.color = '#00ffcc88';
                            badge.addEventListener('click', (e) => { e.stopPropagation(); window.open(pub.remote_url, '_blank'); });
                        }
                        container.appendChild(badge);
                    });
                }).catch(() => {});
            });
        } catch (e) {
            ledgerContainer.innerHTML = `<div style="color:#ff6666; font-size:0.8rem;">Error loading ledger: ${e}</div>`;
        }
    }

    // ======== CREDENTIAL DRAWER ========
    function openDrawer(entry) {
        activeVcId = entry.vc_id;
        activeProjectContext = entry.project_context
            ? entry.project_context.split(/[\/\\]/).pop()
            : 'Unknown Workspace';

        // Highlight selected row
        document.querySelectorAll('.ledger-entry').forEach(r => r.classList.remove('selected'));
        const selectedRow = ledgerContainer.querySelector(`[data-vc-id="${entry.vc_id}"]`);
        if (selectedRow) selectedRow.classList.add('selected');

        drawerVcId.innerText = entry.vc_id;
        drawerAiInsight.innerText = entry.ai_insight || 'No AI insight recorded.';
        const drawerAiEngine = document.getElementById('drawer-ai-engine');
        if (drawerAiEngine) {
            drawerAiEngine.innerText = entry.ai_engine ? '[ ' + entry.ai_engine + ' ]' : '';
        }

        const drawerSkillTags = document.getElementById('drawer-skill-tags');
        if (drawerSkillTags) {
            drawerSkillTags.innerHTML = '';
            if (entry.skill_tags) {
                const tags = entry.skill_tags.split(',').map(t => t.trim()).filter(Boolean);
                if (tags.length > 0) {
                    tags.forEach(t => {
                        const span = document.createElement('span');
                        span.style.cssText = 'background: rgba(0,255,204,0.1); color: #00ffcc; border: 1px solid rgba(0,255,204,0.3); padding: 2px 6px; border-radius: 3px;';
                        span.innerText = t;
                        drawerSkillTags.appendChild(span);
                    });
                } else {
                    drawerSkillTags.innerHTML = '<span style="color:#888; font-style:italic;">No skill tags extracted.</span>';
                }
            } else {
                drawerSkillTags.innerHTML = '<span style="color:#888; font-style:italic;">No skill tags extracted.</span>';
            }
        }

        // Prefer reading from the signed VC JSON which carries FileDate (physical OS ModTime watermark).
        // Falls back to the legacy file_paths string for credentials minted before this feature.
        let manifestHTML = '';
        if (entry.full_vc_json) {
            try {
                const vc = JSON.parse(entry.full_vc_json);
                const files = vc?.credentialSubject?.proofOfWork?.files;
                const fullPaths = vc?.localMetadata?.full_paths || [];
                if (Array.isArray(files) && files.length > 0) {
                    manifestHTML = files.map((f, i) => {
                        const datePart = f.fileDate
                            ? `<span style="color:#888; margin-left:8px; font-size:0.7rem;">(Modified: ${f.fileDate})</span>`
                            : '';
                        const displayPath = fullPaths[i] ? fullPaths[i] : f.name;
                        return `<div>${displayPath}${datePart}</div>`;
                    }).join('');
                }
            } catch (_) { /* fall through to legacy path */ }
        }
        if (!manifestHTML) {
            // Legacy fallback: file_paths is a comma-separated string of full paths
            const paths = entry.file_paths
                ? entry.file_paths.split(',').map(f => f.trim()).filter(Boolean)
                : [];
            manifestHTML = paths.map(p => `<div>${p}</div>`).join('');
        }
        drawerFilePaths.innerHTML = manifestHTML;

        // Reset broadcast button & status to loading state
        if (btnBroadcastGist) {
            btnBroadcastGist.disabled = true;
            btnBroadcastGist.innerText = '[ ⏳ CHECKING... ]';
            btnBroadcastGist.style.opacity = '0.5';
        }
        if (broadcastStatus) { broadcastStatus.style.display = 'none'; }
        // Clear verify-sig result when switching credentials
        const verifySigEl = document.getElementById('verify-sig-status');
        if (verifySigEl) { verifySigEl.style.display = 'none'; verifySigEl.innerText = ''; }

        // Collapse the ledger list viewport so drawer gets full panel height
        const viewportLayer = document.querySelector('#view-ledger .viewport-layer');
        if (viewportLayer) viewportLayer.style.display = 'none';
        credentialDrawer.style.cssText = credentialDrawer.style.cssText + '; flex: 1; min-height: 0;';
        credentialDrawer.style.flex = '1';
        credentialDrawer.style.minHeight = '0';
        credentialDrawer.style.display = 'flex';

        // Async check: has this VC already been successfully broadcast to gist?
        GetBroadcastStatus(entry.vc_id).then(pubs => {
            if (!btnBroadcastGist) return;
            const gistPub = (pubs || []).find(p => p.channel === 'gist');
            if (gistPub && gistPub.status === 'success') {
                // Already published — lock the button
                btnBroadcastGist.disabled = true;
                btnBroadcastGist.innerText = '[ ✅ GIST PUBLISHED ]';
                btnBroadcastGist.style.opacity = '0.55';
                btnBroadcastGist.style.cursor = 'not-allowed';
                if (broadcastStatus) {
                    broadcastStatus.style.display = 'block';
                    broadcastStatus.style.background = 'rgba(0,255,204,0.06)';
                    broadcastStatus.style.color = 'rgba(0,255,204,0.8)';
                    broadcastStatus.style.border = '1px solid rgba(0,255,204,0.2)';
                    broadcastStatus.innerHTML = `✅ Published · <a href="${gistPub.remote_url}" style="color:#00ffcc;" target="_blank">${gistPub.remote_url}</a>
                        &nbsp;<span id="btn-rebroadcast-link" style="cursor:pointer; color:rgba(0,200,255,0.7); font-size:0.62rem; border-bottom:1px dotted rgba(0,200,255,0.4);" title="Update Gist content in-place (or create new if deleted)">🔄 Re-broadcast</span>
                        &nbsp;<span id="btn-delgist-link" style="cursor:pointer; color:rgba(255,80,80,0.75); font-size:0.62rem; border-bottom:1px dotted rgba(255,80,80,0.35);" title="Delete this Gist from GitHub. The local credential stays valid.">✕ Del-Gist</span>`;
                    document.getElementById('btn-rebroadcast-link')?.addEventListener('click', async () => {
                        if (!confirm('Re-broadcast this credential to GitHub Gist?\n\n• If the Gist still exists → content will be updated in-place (same URL)\n• If the Gist was deleted → a new Gist will be created')) return;
                        await ResetBroadcastVC(entry.vc_id, 'gist');
                        btnBroadcastGist.disabled = false;
                        btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                        btnBroadcastGist.style.opacity = '1';
                        btnBroadcastGist.style.cursor = 'pointer';
                        broadcastStatus.style.display = 'none';
                    });
                    document.getElementById('btn-delgist-link')?.addEventListener('click', async () => {
                        if (!confirm('Delete this Gist from GitHub?\n\nThe local credential will remain valid. You can re-broadcast a fresh Gist afterwards.')) return;
                        const delResult = JSON.parse(await DeleteBroadcastVC(entry.vc_id, 'gist'));
                        if (delResult.error) {
                            broadcastStatus.innerHTML = `✕ Delete failed: ${delResult.error}`;
                            broadcastStatus.style.color = 'var(--warning)';
                        } else {
                            btnBroadcastGist.disabled = false;
                            btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                            btnBroadcastGist.style.opacity = '1';
                            btnBroadcastGist.style.cursor = 'pointer';
                            broadcastStatus.style.display = 'none';
                        }
                    });
                }
            } else if (gistPub && (gistPub.status === 'pending' || gistPub.status === 'publishing')) {
                // In-flight — start polling so the button updates when backend finishes
                // (handles the case where the drawer is opened while a broadcast is running)
                btnBroadcastGist.disabled = true;
                btnBroadcastGist.innerText = '[ 📡 BROADCASTING... ]';
                btnBroadcastGist.style.opacity = '0.6';
                if (broadcastStatus) {
                    broadcastStatus.style.display = 'block';
                    broadcastStatus.style.background = 'rgba(0,180,255,0.06)';
                    broadcastStatus.style.color = 'rgba(0,200,255,0.85)';
                    broadcastStatus.style.border = '1px solid rgba(0,180,255,0.25)';
                    broadcastStatus.innerText = '📡 Broadcast in progress — waiting for GitHub response...';
                }
                // Poll for completion (same logic as the click handler)
                const polledVcId = entry.vc_id;
                let pollCount = 0;
                const pollInterval = setInterval(async () => {
                    pollCount++;
                    try {
                        const freshPubs = await GetBroadcastStatus(polledVcId);
                        const freshGistPub = (freshPubs || []).find(p => p.channel === 'gist');
                        if (!freshGistPub) return;
                        if (freshGistPub.status === 'success') {
                            clearInterval(pollInterval);
                            if (activeVcId === polledVcId && btnBroadcastGist) {
                                btnBroadcastGist.disabled = true;
                                btnBroadcastGist.innerText = '[ ✅ GIST PUBLISHED ]';
                                btnBroadcastGist.style.opacity = '0.55';
                                btnBroadcastGist.style.cursor = 'not-allowed';
                            }
                            if (broadcastStatus && activeVcId === polledVcId) {
                                broadcastStatus.style.background = 'rgba(0,255,204,0.06)';
                                broadcastStatus.style.color = 'rgba(0,255,204,0.8)';
                                broadcastStatus.style.border = '1px solid rgba(0,255,204,0.2)';
                                broadcastStatus.innerHTML = `✅ Published to GitHub Gist · <a href="${freshGistPub.remote_url}" style="color:#00ffcc;" target="_blank">${freshGistPub.remote_url}</a>`;
                            }
                        } else if (freshGistPub.status === 'failed' || pollCount >= 40) {
                            clearInterval(pollInterval);
                            if (activeVcId === polledVcId && btnBroadcastGist) {
                                btnBroadcastGist.disabled = false;
                                btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                                btnBroadcastGist.style.opacity = '1';
                                btnBroadcastGist.style.cursor = 'pointer';
                            }
                            if (broadcastStatus && activeVcId === polledVcId) {
                                const errMsg = freshGistPub.last_error || (pollCount >= 40 ? 'Timed out — check logs' : 'Unknown error');
                                broadcastStatus.style.background = 'rgba(255,85,0,0.08)';
                                broadcastStatus.style.color = 'var(--warning)';
                                broadcastStatus.style.border = '1px solid rgba(255,85,0,0.4)';
                                broadcastStatus.innerText = '✕ Broadcast failed: ' + errMsg;
                            }
                        }
                    } catch (_) { /* keep polling on network hiccup */ }
                }, 3000);
            } else {
                // Not yet broadcast (or previously failed) — enable
                btnBroadcastGist.disabled = false;
                btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                btnBroadcastGist.style.opacity = '1';
                btnBroadcastGist.style.cursor = 'pointer';
            }
        }).catch(() => {
            // On error, allow the user to try
            if (btnBroadcastGist) {
                btnBroadcastGist.disabled = false;
                btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                btnBroadcastGist.style.opacity = '1';
            }
        });
    }

    btnCloseDrawer.addEventListener('click', () => {
        const viewportLayer = document.querySelector('#view-ledger .viewport-layer');
        if (viewportLayer) viewportLayer.style.display = '';
        credentialDrawer.style.display = 'none';
        credentialDrawer.style.flex = '';
        credentialDrawer.style.minHeight = '';
        document.querySelectorAll('.ledger-entry').forEach(r => r.classList.remove('selected'));
        activeVcId = null;
    });

    // ======== BROADCAST GIST ========
    if (btnBroadcastGist) {
        btnBroadcastGist.addEventListener('click', async () => {
            if (!activeVcId) return;

            // Double-check server state before sending — prevents race conditions
            btnBroadcastGist.disabled = true;
            btnBroadcastGist.innerText = '[ ⏳ CHECKING... ]';
            if (broadcastStatus) broadcastStatus.style.display = 'none';

            try {
                const pubs = await GetBroadcastStatus(activeVcId);
                const gistPub = (pubs || []).find(p => p.channel === 'gist');

                if (gistPub && gistPub.status === 'success') {
                    // Already published — block and show link with re-broadcast option
                    btnBroadcastGist.innerText = '[ ✅ GIST PUBLISHED ]';
                    btnBroadcastGist.style.opacity = '0.55';
                    btnBroadcastGist.style.cursor = 'not-allowed';
                    if (broadcastStatus) {
                        broadcastStatus.style.display = 'block';
                        broadcastStatus.style.background = 'rgba(0,255,204,0.06)';
                        broadcastStatus.style.color = 'rgba(0,255,204,0.8)';
                        broadcastStatus.style.border = '1px solid rgba(0,255,204,0.2)';
                        broadcastStatus.innerHTML = `✅ Published · <a href="${gistPub.remote_url}" style="color:#00ffcc;" target="_blank">${gistPub.remote_url}</a>
                            &nbsp;<span id="btn-rebroadcast-link" style="cursor:pointer; color:rgba(0,200,255,0.7); font-size:0.62rem; border-bottom:1px dotted rgba(0,200,255,0.4);" title="Update Gist content in-place (or create new if deleted)">🔄 Re-broadcast</span>
                            &nbsp;<span id="btn-delgist-link" style="cursor:pointer; color:rgba(255,80,80,0.75); font-size:0.62rem; border-bottom:1px dotted rgba(255,80,80,0.35);" title="Delete this Gist from GitHub. The local credential stays valid.">✕ Del-Gist</span>`;
                        document.getElementById('btn-rebroadcast-link')?.addEventListener('click', async () => {
                            if (!confirm('Re-broadcast this credential to GitHub Gist?\n\n• If the Gist still exists → content will be updated in-place (same URL)\n• If the Gist was deleted → a new Gist will be created')) return;
                            await ResetBroadcastVC(activeVcId, 'gist');
                            btnBroadcastGist.disabled = false;
                            btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                            btnBroadcastGist.style.opacity = '1';
                            btnBroadcastGist.style.cursor = 'pointer';
                            broadcastStatus.style.display = 'none';
                        });
                        document.getElementById('btn-delgist-link')?.addEventListener('click', async () => {
                            if (!confirm('Delete this Gist from GitHub?\n\nThe local credential will remain valid. You can re-broadcast a fresh Gist afterwards.')) return;
                            const delResult = JSON.parse(await DeleteBroadcastVC(activeVcId, 'gist'));
                            if (delResult.error) {
                                broadcastStatus.innerHTML = `✕ Delete failed: ${delResult.error}`;
                                broadcastStatus.style.color = 'var(--warning)';
                            } else {
                                btnBroadcastGist.disabled = false;
                                btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                                btnBroadcastGist.style.opacity = '1';
                                btnBroadcastGist.style.cursor = 'pointer';
                                broadcastStatus.style.display = 'none';
                            }
                        });
                    }
                    return;
                }

                // Safe to broadcast
                btnBroadcastGist.innerText = '[ 📡 BROADCASTING... ]';
                btnBroadcastGist.style.opacity = '0.7';
                const result = JSON.parse(await BroadcastVC(activeVcId));
                if (result.error) {
                    // Show error and re-enable for retry
                    if (broadcastStatus) {
                        broadcastStatus.style.display = 'block';
                        broadcastStatus.style.background = 'rgba(255,85,0,0.08)';
                        broadcastStatus.style.color = 'var(--warning)';
                        broadcastStatus.style.border = '1px solid rgba(255,85,0,0.4)';
                        broadcastStatus.innerText = '✕ ' + result.error;
                    }
                    btnBroadcastGist.disabled = false;
                    btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                    btnBroadcastGist.style.opacity = '1';
                } else {
                    // Queued — show in-flight state and start polling for completion
                    const polledVcId = activeVcId; // capture before drawer might close
                    btnBroadcastGist.innerText = '[ 📡 BROADCASTING... ]';
                    btnBroadcastGist.style.opacity = '0.6';
                    if (broadcastStatus) {
                        broadcastStatus.style.display = 'block';
                        broadcastStatus.style.background = 'rgba(0,180,255,0.06)';
                        broadcastStatus.style.color = 'rgba(0,200,255,0.85)';
                        broadcastStatus.style.border = '1px solid rgba(0,180,255,0.25)';
                        broadcastStatus.innerText = '📡 Broadcast queued — waiting for GitHub response...';
                    }

                    // Poll every 3 s, up to 40 attempts (~2 min), to cover the backend's
                    // worst-case exponential backoff total (10+20+40+80+160 = 310s max,
                    // but most failures resolve within the first 1-2 retries, ~60s).
                    // A longer window prevents the UI from re-enabling the button while
                    // a backend goroutine is still retrying, which would cause duplicates.
                    let pollCount = 0;
                    const pollInterval = setInterval(async () => {
                        pollCount++;
                        try {
                            const pubs = await GetBroadcastStatus(polledVcId);
                            const gistPub = (pubs || []).find(p => p.channel === 'gist');
                            if (!gistPub) return; // not written yet, keep waiting

                            if (gistPub.status === 'success') {
                                clearInterval(pollInterval);
                                // Only update UI if the same VC is still open
                                if (activeVcId === polledVcId && btnBroadcastGist) {
                                    btnBroadcastGist.disabled = true;
                                    btnBroadcastGist.innerText = '[ ✅ GIST PUBLISHED ]';
                                    btnBroadcastGist.style.opacity = '0.55';
                                    btnBroadcastGist.style.cursor = 'not-allowed';
                                }
                                if (broadcastStatus && activeVcId === polledVcId) {
                                    broadcastStatus.style.background = 'rgba(0,255,204,0.06)';
                                    broadcastStatus.style.color = 'rgba(0,255,204,0.8)';
                                    broadcastStatus.style.border = '1px solid rgba(0,255,204,0.2)';
                                    broadcastStatus.innerHTML = `✅ Published to GitHub Gist · <a href="${gistPub.remote_url}" style="color:#00ffcc;" target="_blank">${gistPub.remote_url}</a>`;
                                }
                                // Refresh ledger badge too
                                const badgeContainerId = 'badges-' + polledVcId.replace(/[^a-z0-9]/gi, '_');
                                const badgeEl = document.getElementById(badgeContainerId);
                                if (badgeEl) {
                                    badgeEl.innerHTML = '';
                                    const badge = document.createElement('span');
                                    badge.style.cssText = 'font-size: 0.58rem; padding: 1px 5px; border-radius: 3px; background: rgba(0,0,0,0.4); border: 1px solid rgba(0,255,204,0.2); color: #00ffcc88; cursor: pointer; white-space: nowrap;';
                                    badge.title = `GIST: success\n${gistPub.remote_url}`;
                                    badge.innerText = `✅ GIST`;
                                    badge.addEventListener('click', (e) => { e.stopPropagation(); window.open(gistPub.remote_url, '_blank'); });
                                    badgeEl.appendChild(badge);
                                }
                            } else if (gistPub.status === 'failed' || pollCount >= 40) {
                                clearInterval(pollInterval);
                                if (activeVcId === polledVcId && btnBroadcastGist) {
                                    btnBroadcastGist.disabled = false;
                                    btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                                    btnBroadcastGist.style.opacity = '1';
                                    btnBroadcastGist.style.cursor = 'pointer';
                                }
                                if (broadcastStatus && activeVcId === polledVcId) {
                                    const errMsg = gistPub.last_error || (pollCount >= 40 ? 'Timed out — check console for details' : 'Unknown error');
                                    broadcastStatus.style.background = 'rgba(255,85,0,0.08)';
                                    broadcastStatus.style.color = 'var(--warning)';
                                    broadcastStatus.style.border = '1px solid rgba(255,85,0,0.4)';
                                    broadcastStatus.innerText = '✕ Broadcast failed: ' + errMsg;
                                }
                            }
                        } catch (_) { /* network hiccup — keep polling */ }
                    }, 3000);
                }
            } catch (e) {
                if (broadcastStatus) {
                    broadcastStatus.style.display = 'block';
                    broadcastStatus.style.color = 'var(--warning)';
                    broadcastStatus.innerText = '✕ Error: ' + e;
                }
                btnBroadcastGist.disabled = false;
                btnBroadcastGist.innerText = '[ 📡 BROADCAST GIST ]';
                btnBroadcastGist.style.opacity = '1';
            }
        });
    }


    // ======== RESTORE FROM SYNC ========
    const btnRestoreHistory = document.getElementById('btn-restore-history');
    const cloudRestoreStatus = document.getElementById('cloud-restore-status');
    if (btnRestoreHistory) {
        btnRestoreHistory.addEventListener('click', async () => {
            btnRestoreHistory.innerText = '[ ⟳ SCANNING CLOUD... ]';
            btnRestoreHistory.disabled = true;
            if (cloudRestoreStatus) cloudRestoreStatus.innerText = '';
            try {
                const resJSON = await RestoreDataFromSync();
                const res = JSON.parse(resJSON);
                if (res.error) {
                    if (cloudRestoreStatus) {
                        cloudRestoreStatus.innerText = '✕ ' + res.error;
                        cloudRestoreStatus.style.color = '#ff6666';
                    } else {
                        alert('Restoration error: ' + res.error);
                    }
                } else {
                    const msg = `✓ Restored ${res.credentials} credentials from ${res.source}. Please restart the app to reload.`;
                    if (cloudRestoreStatus) {
                        cloudRestoreStatus.innerText = msg;
                        cloudRestoreStatus.style.color = '#00ffcc';
                    } else {
                        alert(msg);
                    }
                }
            } catch (e) {
                if (cloudRestoreStatus) {
                    cloudRestoreStatus.innerText = '✕ Error: ' + e;
                    cloudRestoreStatus.style.color = '#ff6666';
                } else {
                    alert('Connection failure during restore: ' + e);
                }
            } finally {
                btnRestoreHistory.innerText = '[ ☁ RESTORE FROM CLOUD SYNC ]';
                btnRestoreHistory.disabled = false;
            }
        });
    }

    // ======== GENERATE HTML REPORT ========
    const btnGenerateHtml = document.getElementById('btn-generate-html');
    if (btnGenerateHtml) {
        btnGenerateHtml.addEventListener('click', async () => {
            if (!activeVcId) return;

            const customTitle = window.prompt("Enter Report Title:", activeProjectContext);
            if (customTitle === null) return; // User cancelled

            btnGenerateHtml.innerText = '[ RENDERING... ]';
            btnGenerateHtml.disabled = true;
            try {
                const resJSON = await GenerateHTMLReport(activeVcId, customTitle);
                const res = JSON.parse(resJSON);
                if (res.error) {
                    alert('HTML Generation failed: ' + res.error);
                } else if (res.status === 'CANCELLED') {
                    // User cancelled the directory selection dialog, do nothing
                } else {
                    alert('Professional Audit Report generated successfully!\n\nCheck the folder you selected.');
                }
            } catch (e) {
                alert('Connection failure: ' + e);
            } finally {
                btnGenerateHtml.innerText = '[ GENERATE HTML REPORT ]';
                btnGenerateHtml.disabled = false;
            }
        });
    }

    // ======== VERIFY SIGNATURE ========
    const btnVerifySig = document.getElementById('btn-verify-sig');
    const verifySigStatus = document.getElementById('verify-sig-status');
    if (btnVerifySig) {
        btnVerifySig.addEventListener('click', async () => {
            if (!activeVcId) return;
            btnVerifySig.innerText = 'Verifying...';
            btnVerifySig.disabled = true;
            verifySigStatus.style.display = 'none';
            try {
                const json = await ExportCredentialJSON(activeVcId);
                const result = JSON.parse(await VerifyCredential(json));
                verifySigStatus.style.display = 'block';
                if (result.valid) {
                    verifySigStatus.style.background = 'rgba(0,255,204,0.06)';
                    verifySigStatus.style.color = 'var(--primary)';
                    verifySigStatus.style.border = '1px solid rgba(0,255,204,0.25)';
                    verifySigStatus.innerText = '\u2713 SIGNATURE VALID \u2014 Ed25519 proof verified against issuer DID';
                } else {
                    verifySigStatus.style.background = 'rgba(255,85,0,0.08)';
                    verifySigStatus.style.color = 'var(--warning)';
                    verifySigStatus.style.border = '1px solid rgba(255,85,0,0.4)';
                    verifySigStatus.innerText = '\u2715 SIGNATURE INVALID \u2014 ' + (result.error || 'Verification failed');
                }
            } catch (e) {
                verifySigStatus.style.display = 'block';
                verifySigStatus.style.color = 'var(--warning)';
                verifySigStatus.innerText = '\u2715 Error: ' + e;
            } finally {
                btnVerifySig.innerText = '[ VERIFY SIGNATURE ]';
                btnVerifySig.disabled = false;
            }
        });
    }

    // ======== REVOKE CREDENTIAL ========
    if (btnRevokeCredential) {
        btnRevokeCredential.addEventListener('click', async () => {
            if (!activeVcId) return;

            const shortId = activeVcId.substring(0, 20) + '...';
            const confirmed = confirm(
                `REVOKE CREDENTIAL\n\n` +
                `ID: ${shortId}\n\n` +
                `This credential will be removed from the active Ledger.\n` +
                `The underlying record is preserved in the database\n` +
                `to maintain hash chain integrity --  it cannot be read\n` +
                `or displayed again without direct DB access.\n\n` +
                `Proceed?`
            );
            if (!confirmed) return;

            btnRevokeCredential.innerText = 'Revoking...';
            btnRevokeCredential.disabled = true;

            try {
                const result = JSON.parse(await RevokeCredential(activeVcId));
                if (result.error) {
                    revokeStatus.style.display = 'block';
                    revokeStatus.style.background = 'var(--warning-dim)';
                    revokeStatus.style.color = 'var(--warning)';
                    revokeStatus.style.border = '1px solid rgba(255,85,0,0.4)';
                    revokeStatus.innerText = '\u2715 Revoke failed: ' + result.error;
                    return;
                }
                // Success -- show brief confirmation then close drawer and refresh
                revokeStatus.style.display = 'block';
                revokeStatus.style.background = 'rgba(0,255,204,0.06)';
                revokeStatus.style.color = 'var(--primary)';
                revokeStatus.style.border = '1px solid rgba(0,255,204,0.25)';
                revokeStatus.innerText = '\u2713 Credential revoked. Refreshing ledger...';

                setTimeout(() => {
                    const viewportLayer = document.querySelector('#view-ledger .viewport-layer');
                    if (viewportLayer) viewportLayer.style.display = '';
                    credentialDrawer.style.display = 'none';
                    credentialDrawer.style.flex = '';
                    credentialDrawer.style.minHeight = '';
                    revokeStatus.style.display = 'none';
                    activeVcId = null;
                    renderLedger();
                }, 1400);

            } catch (e) {
                revokeStatus.style.display = 'block';
                revokeStatus.innerText = '\u2715 Error: ' + e;
            } finally {
                btnRevokeCredential.innerText = '[ REVOKE ]';
                btnRevokeCredential.disabled = false;
            }
        });
    }





    // ======== WIPE IDENTITY (FACTORY RESET) ========
    const btnWipeIdentity = document.getElementById('btn-wipe-identity');
    if (btnWipeIdentity) {
        btnWipeIdentity.addEventListener('click', async () => {
            if (confirm("⚠️ DANGER: This will permanently delete your identity, configuration, and local ledger from this device.\n\nAre you absolutely sure you want to factory reset?")) {
                btnWipeIdentity.innerText = "WIPING DATA...";
                btnWipeIdentity.disabled = true;
                try {
                    await WipeIdentity();
                    alert("Factory reset complete. The application will now restart.");
                    location.reload();
                } catch (e) {
                    alert("Error wiping identity: " + e);
                    btnWipeIdentity.innerText = "⚠️ FACTORY RESET / WIPE IDENTITY";
                    btnWipeIdentity.disabled = false;
                }
            }
        });
    }

    // ======== VERSION & UPDATE CHECK ========
    let currentAppVersion = "0.0.0";
    try {
        currentAppVersion = await GetAppVersion();
        const versionEl = document.getElementById('app-version-text');
        if (versionEl) versionEl.innerText = 'VeriHash v' + currentAppVersion;
    } catch (e) {
        console.warn("Version detection failed:", e);
    }

    const btnCheckUpdate = document.getElementById('btn-check-update');
    const updateStatus = document.getElementById('update-status');
    if (btnCheckUpdate) {
        btnCheckUpdate.addEventListener('click', async () => {
            btnCheckUpdate.innerText = "[ Checking... ]";
            btnCheckUpdate.disabled = true;
            updateStatus.innerText = "";
            updateStatus.style.color = "var(--primary)";
            
            try {
                const resStr = await CheckForUpdate(currentAppVersion);
                const res = JSON.parse(resStr);
                
                if (res.error) {
                    updateStatus.style.color = "var(--warning)";
                    updateStatus.innerText = "Error: " + res.error;
                    btnCheckUpdate.innerText = "Check for Updates";
                    btnCheckUpdate.disabled = false;
                } else if (res.update_available) {
                    updateStatus.style.color = "#00ffcc";
                    updateStatus.innerText = "New version found: " + res.version + "!";
                    btnCheckUpdate.innerText = "[ DOWNLOAD & UPDATE NOW ]";
                    btnCheckUpdate.style.color = "#ffaa00";
                    btnCheckUpdate.disabled = false;
                    
                    btnCheckUpdate.onclick = async () => {
                        btnCheckUpdate.innerText = "[ Downloading... ]";
                        btnCheckUpdate.disabled = true;
                        updateStatus.innerText = "Updating... DO NOT CLOSE.";
                        try {
                            const upStr = await ApplyUpdate();
                            const upRes = JSON.parse(upStr);
                            if (upRes.status === "success") {
                                updateStatus.innerText = "Update successful! Restarting in 3 seconds...";
                                setTimeout(() => RestartApp(), 3000);
                            } else {
                                updateStatus.style.color = "var(--warning)";
                                updateStatus.innerText = "Update failed: " + upRes.error;
                                btnCheckUpdate.innerText = "[ Retry Update ]";
                                btnCheckUpdate.disabled = false;
                            }
                        } catch (e) {
                            updateStatus.style.color = "var(--warning)";
                            updateStatus.innerText = "Update exception: " + e;
                            btnCheckUpdate.disabled = false;
                        }
                    };
                } else {
                    updateStatus.style.color = "#888";
                    updateStatus.innerText = "You are on the latest version.";
                    btnCheckUpdate.innerText = "Check for Updates";
                    btnCheckUpdate.disabled = false;
                }
            } catch (e) {
                updateStatus.style.color = "var(--warning)";
                updateStatus.innerText = "Check failed: " + e;
                btnCheckUpdate.innerText = "Check for Updates";
                btnCheckUpdate.disabled = false;
            }
        });
    }

});
