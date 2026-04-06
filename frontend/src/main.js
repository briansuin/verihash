import { SelectDirectory, SaveConfig, StartWatchdog, TriggerMint, GetDID, LoadConfig, GetWorkspaceFiles, GetLedger, ExportCredentialJSON, RevokeCredential, VerifyChain, VerifyCredential, ExportIdentityBundle, ImportIdentityBundle, SaveToFile, GetWalletStatus, UnlockWallet, InitWallet, MigrateWallet, GetMnemonic } from '../wailsjs/go/main/App';
import { EventsOn, WindowGetSize, WindowSetSize, OnFileDrop } from '../wailsjs/runtime/runtime';

document.addEventListener('DOMContentLoaded', async () => {

    // ======== WALLET LOCK SCREEN ========
    // Must resolve before any other UI interaction
    const walletOverlay    = document.getElementById('wallet-overlay');
    const walletSubtitle   = document.getElementById('wallet-subtitle');

    function showWalletScreen(screenId, subtitle) {
        walletOverlay.style.display = 'flex';
        walletSubtitle.innerText = subtitle;
        ['wallet-screen-unlock','wallet-screen-init','wallet-screen-migrate', 'wallet-screen-mnemonic'].forEach(id => {
            document.getElementById(id).style.display = (id === screenId) ? 'block' : 'none';
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
        } catch(e) {
            statusEl.className = 'wallet-status err';
            statusEl.innerText = '\u2715 Error: ' + e;
        } finally {
            btn.disabled = false;
        }
    }

    // Check wallet state on startup
    const walletState = await GetWalletStatus();
    if (walletState === 'encrypted') {
        showWalletScreen('wallet-screen-unlock', 'WALLET LOCKED');
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
            showWalletScreen('wallet-screen-init', 'INITIALIZE WALLET');
            const btn = document.getElementById('btn-wallet-init');
            const status = document.getElementById('wallet-init-status');
            const pwd = document.getElementById('wallet-init-pwd');
            const confirm = document.getElementById('wallet-init-pwd-confirm');
            btn.addEventListener('click', () => handleWalletAction(btn, status, () => {
                return InitWallet(pwd.value, confirm.value);
            }));
            pwd.focus();
        });
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
    
    const consoleOutput = document.getElementById('console-output');
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.getElementById('status-text');
    const btnMint = document.getElementById('btn-mint');
    const body = document.getElementById('app-body');
    const matrixCanvas = document.getElementById('matrix-canvas');
    const sidebar = document.getElementById('sidebar');
    const btnSidebarToggle = document.getElementById('btn-sidebar-toggle');

    // Custom dropdown references (must be declared here â€” used in boot sequence)
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
    const btnExportJson = document.getElementById('btn-export-json');
    const btnRevokeCredential = document.getElementById('btn-revoke-credential');
    const revokeStatus = document.getElementById('revoke-status');
    // Chain status bar elements
    const chainStatusBar = document.getElementById('chain-status-bar');
    const chainStatusIcon = document.getElementById('chain-status-icon');
    const chainStatusLabel = document.getElementById('chain-status-label');
    const chainStats = document.getElementById('chain-stats');
    let activeVcId = null;

    // M/D State
    let workspaces = [];
    let activeWorkspace = null;

    // Boot Sequence
    try {
        const did = await GetDID();
        nodeDid.innerText = did;
        
        const cfg = await LoadConfig();
        if (cfg.workspaces) workspaces = cfg.workspaces;
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

        renderWorkspaces();
        // Manually apply engine-specific UI state before triggering change,
        // so syncConfig doesn't overwrite correct values with UI defaults.
        if (cfg.ai_engine && cfg.ai_engine !== 'ollama') {
            cloudConfigGroup.style.display = 'block';
        }
        // Dispatch change to sync security badge, status dot, and placeholder hints
        aiEngineSelect.dispatchEvent(new Event('change'));
        if (workspaces.length > 0) {
            StartWatchdog();
        }
    } catch(e) { console.error("Boot error: ", e); }

    // Visual Mechanics
    btnSidebarToggle.addEventListener('click', async () => {
        sidebar.classList.toggle('collapsed');
        const isCollapsed = sidebar.classList.contains('collapsed');
        try {
            const size = await WindowGetSize();
            if (isCollapsed) {
                btnSidebarToggle.innerText = '[ < ]';
                WindowSetSize(800, size.h);
            } else {
                btnSidebarToggle.innerText = '[ > ]';
                WindowSetSize(1120, size.h);
            }
        } catch (err) {}
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
        await SaveConfig(workspaces, engine, model, key, baseUrl);
    }

    // AI Engine change handler â€” supports all 5 providers
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
                gemini:   { label: 'GEMINI LINKED',        placeholder: 'e.g. gemini-2.5-flash' },
                deepseek: { label: 'DEEPSEEK LINKED',      placeholder: 'e.g. deepseek-chat' },
                qwen:     { label: 'QWEN LINKED',           placeholder: 'e.g. qwen-turbo' },
                minimax:  { label: 'MINIMAX LINKED',       placeholder: 'e.g. MiniMax-Text-01' },
                openai:   { label: 'OPENAI LINKED',        placeholder: 'e.g. gpt-4o-mini' },
                custom:   { label: 'CUSTOM ENDPOINT',      placeholder: 'your-model-name' },
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
    if (apiKeyInput)   apiKeyInput.addEventListener('change', syncConfig);
    if (modelNameInput) modelNameInput.addEventListener('change', syncConfig);
    const baseUrlInput2 = document.getElementById('base-url');
    if (baseUrlInput2) baseUrlInput2.addEventListener('change', syncConfig);

    // M/D Workspace Mechanics
    function renderWorkspaces() {
        workspaceStack.innerHTML = '';
        workspaces.forEach(ws => {
            const card = document.createElement('div');
            card.className = `workspace-card ${ws === activeWorkspace ? 'active' : ''}`;
            const baseName = ws.split(/[\/\\]/).pop();
            card.innerHTML = `
                <div class="path-text">.../${baseName}</div>
                <div class="workspace-tooltip">${ws}</div>
                <button class="btn-remove">Ã—</button>
            `;
            card.addEventListener('click', (e) => {
                if(e.target.classList.contains('btn-remove')) {
                    workspaces = workspaces.filter(w => w !== ws);
                    if(activeWorkspace === ws) activeWorkspace = null;
                    syncConfig();
                    renderWorkspaces();
                    updateView();
                    return;
                }
                activeWorkspace = activeWorkspace === ws ? null : ws;
                renderWorkspaces();
                updateView();
            });
            workspaceStack.appendChild(card);
        });
    }

    async function updateView() {
        if (!activeWorkspace) {
            telemetryPanel.style.display = 'block';
            workspaceView.style.display = 'none';
        } else {
            telemetryPanel.style.display = 'none';
            workspaceView.style.display = 'block';
            activeWorkspaceName.innerText = activeWorkspace.split(/[\/\\]/).pop();
            await renderFileTree(activeWorkspace);
        }
    }

    async function renderFileTree(ws) {
        fileTreeContainer.innerHTML = '<div style="color:#888;">Fetching modifications...</div>';
        try {
            const files = await GetWorkspaceFiles(ws);
            fileTreeContainer.innerHTML = '';
            if(!files || files.length === 0) {
                fileTreeContainer.innerHTML = '<div style="color:#888; font-size:0.8rem;">No recent modifications detected.</div>';
                return;
            }
            const normalizedWs = ws.replace(/\\/g, '/');
            files.forEach(file => {
                const item = document.createElement('label');
                item.className = 'file-tree-item';
                
                // Determine clean relative path trimming the workspace root
                let relPath = file;
                if (file.toLowerCase().startsWith(normalizedWs.toLowerCase())) {
                    relPath = file.substring(normalizedWs.length);
                }
                relPath = relPath.replace(/^[\/\\]/, '');

                // Default is unchecked for targeted selection UX
                item.innerHTML = `
                    <input type="checkbox" class="file-checkbox" value="${file}">
                    <span class="file-path">${relPath}</span>
                `;
                fileTreeContainer.appendChild(item);
            });
        } catch(e) {
            fileTreeContainer.innerHTML = `<div class="err">Error loading tree: ${e}</div>`;
        }
    }

    // Addition Handlers
    OnFileDrop(async (x, y, paths) => {
        if (paths && paths.length > 0) {
            addWorkspace(paths[0]);
        }
    }, true);

    btnSelectDir.addEventListener('click', async () => {
        const dir = await SelectDirectory();
        if (dir) addWorkspace(dir);
    });

    async function addWorkspace(dir) {
        if (!workspaces.includes(dir)) {
            workspaces.push(dir);
            await syncConfig();
            appendLog(`[SYSTEM] Workspace Hooked: ${dir}`, 'sys');
            StartWatchdog();
            renderWorkspaces();
        }
    }

    // Contextual Minting
    btnMint.addEventListener('click', async () => {
        if (btnMint.classList.contains('disabled')) return;
        
        if (!activeWorkspace) {
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
        
        try {
            // We switch to global view to show the result if we want, or stay in context. 
            // Better to show the hash result clearly.
            const mintingWorkspace = activeWorkspace;
            activeWorkspace = null;
            renderWorkspaces();
            updateView();
            appendLog(`\n[ORACLE] Forging Credential for workspace [${mintingWorkspace}] with ${selectedFiles.length} files...`, 'sys');

            const resultJSON = await TriggerMint(selectedFiles, mintingWorkspace);
            // Parse result for clean display instead of dumping raw JSON
            try {
                const vc = JSON.parse(resultJSON);
                if (vc.error) {
                    appendLog(`[ORACLE ERROR] ${vc.error}`, 'err');
                } else {
                    appendLog('\nâš¡ SESSION CREDENTIAL MINTED âš¡', 'sys');
                    appendLog(`[VC_ID]  ${vc.id}`, 'sys');
                    appendLog(`[ISSUER] ${vc.issuer?.substring(0, 60)}...`, 'sys');
                    appendLog(`[DATE]   ${vc.issuanceDate}`, 'sys');
                    appendLog(`[FILES]  ${vc.credentialSubject?.proofOfWork?.filePaths?.length || 0} files anchored`, 'sys');
                    appendLog(`\nâ†’ View full credential in [ THE_LEDGER ] tab`, 'sys');
                }
            } catch {
                // Fallback: show raw if parse fails
                appendLog('\nâš¡ SESSION CREDENTIAL MINTED âš¡', 'sys');
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
            activeWorkspace = null;
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
                engineStatusText.innerText = `LOCAL node online Â· ${ms}ms`;
            } catch {
                engineDot.className = 'engine-dot offline';
                engineStatusText.innerText = 'LOCAL node offline â€” start Ollama';
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

    // ======== P3: SETTINGS GEAR â€” IDENTITY MODAL ========
    const btnSettings = document.getElementById('btn-settings');
    const identityModal = document.getElementById('identity-modal');
    const btnModalClose = document.getElementById('btn-modal-close');
    const btnExportIdentity = document.getElementById('btn-export-identity');
    const btnImportIdentity = document.getElementById('btn-import-identity');
    const exportStatus = document.getElementById('export-status');
    const importStatus = document.getElementById('import-status');

    function openIdentityModal() {
        if (exportStatus) { exportStatus.className = 'modal-status'; exportStatus.innerText = ''; }
        if (importStatus) { importStatus.className = 'modal-status'; importStatus.innerText = ''; }
        identityModal.classList.add('open');
    }
    function closeIdentityModal() {
        identityModal.classList.remove('open');
    }

    if (btnSettings) btnSettings.addEventListener('click', openIdentityModal);
    if (btnModalClose) btnModalClose.addEventListener('click', closeIdentityModal);
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
        chainStatusIcon.innerText = 'â§—';
        chainStatusLabel.innerText = 'Verifying chain integrity...';
        chainStats.innerText = '';
        try {
            const raw = await VerifyChain();
            const r = JSON.parse(raw);
            if (r.intact) {
                chainStatusBar.classList.add('intact');
                chainStatusIcon.className = 'chain-status-icon intact';
                chainStatusIcon.innerText = 'â›“';
                chainStatusLabel.innerText = 'CHAIN INTACT';
                const parts = [];
                if (r.total_blocks > 0) {
                    parts.push(`${r.active_blocks} ACTIVE`);
                    if (r.revoked_blocks > 0) parts.push(`${r.revoked_blocks} REVOKED`);
                    parts.push(`${r.total_blocks} TOTAL BLOCKS`);
                }
                chainStats.innerText = parts.length ? 'Â· ' + parts.join(' Â· ') + ' Â· ' + r.message : r.message;
            } else {
                chainStatusBar.classList.add('broken');
                chainStatusIcon.className = 'chain-status-icon broken';
                chainStatusIcon.innerText = 'âš ';
                chainStatusLabel.innerText = 'CHAIN INTEGRITY FAILURE';
                const breakInfo = r.break_at_vc_id
                    ? `break at: ${r.break_at_vc_id.substring(9, 25)}...`
                    : '';
                chainStats.innerText = r.message + (breakInfo ? ' Â· ' + breakInfo : '');
            }
        } catch(e) {
            chainStatusIcon.className = 'chain-status-icon broken';
            chainStatusIcon.innerText = 'âš ';
            chainStatusLabel.innerText = 'VERIFY ERROR';
            chainStats.innerText = String(e);
        }
    }


    // ======== LEDGER RENDERING ========
    async function renderLedger() {
        ledgerContainer.innerHTML = '<div style="color:#888; font-size:0.8rem; padding:20px 0;">Querying credential archive...</div>';
        credentialDrawer.style.display = 'none';
        activeVcId = null;
        // Kick off chain verification in parallel
        renderChainStatus();
        try {
            const entries = await GetLedger();
            ledgerContainer.innerHTML = '';
            if (!entries || entries.length === 0) {
                ledgerContainer.innerHTML = '<div style="color:#888; font-size:0.8rem; padding:20px 0;">[ LEDGER EMPTY ] â€” No credentials have been minted yet.</div>';
                return;
            }
            entries.forEach(entry => {
                const row = document.createElement('div');
                row.className = 'ledger-entry';
                row.dataset.vcId = entry.vc_id;

                const ts = new Date(entry.timestamp * 1000);
                const dateStr = ts.toLocaleDateString('zh-CN', { year:'numeric', month:'2-digit', day:'2-digit' });
                const timeStr = ts.toLocaleTimeString('zh-CN', { hour:'2-digit', minute:'2-digit' });

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
                        ${entry.vc_hash ? `<div class="ledger-vc-hash">â›“ ${entry.vc_hash.substring(0, 32)}...</div>` : ''}
                    </div>
                    <div class="ledger-badge">${fileCount} files</div>
                `;

                row.addEventListener('click', () => openDrawer(entry));
                ledgerContainer.appendChild(row);
            });
        } catch(e) {
            ledgerContainer.innerHTML = `<div style="color:#ff6666; font-size:0.8rem;">Error loading ledger: ${e}</div>`;
        }
    }

    // ======== CREDENTIAL DRAWER ========
    function openDrawer(entry) {
        activeVcId = entry.vc_id;
        // Highlight selected row
        document.querySelectorAll('.ledger-entry').forEach(r => r.classList.remove('selected'));
        const selectedRow = ledgerContainer.querySelector(`[data-vc-id="${entry.vc_id}"]`);
        if (selectedRow) selectedRow.classList.add('selected');

        drawerVcId.innerText = entry.vc_id;
        drawerAiInsight.innerText = entry.ai_insight || 'No AI insight recorded.';

        const paths = entry.file_paths
            ? entry.file_paths.split(',').map(f => f.trim()).filter(Boolean)
            : [];
        drawerFilePaths.innerHTML = paths.map(p => `<div>${p.split(/[\/\\]/).pop()}</div>`).join('');

        credentialDrawer.style.display = 'flex';
    }

    btnCloseDrawer.addEventListener('click', () => {
        credentialDrawer.style.display = 'none';
        document.querySelectorAll('.ledger-entry').forEach(r => r.classList.remove('selected'));
        activeVcId = null;
    });

    // ======== JSON EXPORT ========
    btnExportJson.addEventListener('click', async () => {
        if (!activeVcId) return;
        try {
            const json = await ExportCredentialJSON(activeVcId);
            const parsed = JSON.parse(json);
            if (parsed.error) { alert('Export failed: ' + parsed.error); return; }
            const defaultName = `verihash_credential_${activeVcId.substring(0, 16)}.json`;
            const result = JSON.parse(await SaveToFile(defaultName, json));
            if (result.error) alert('Save failed: ' + result.error);
        } catch(e) {
            alert('Export failed: ' + e);
        }
    });

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
                    verifySigStatus.innerText = '\u2713 SIGNATURE VALID â€” Ed25519 proof verified against issuer DID';
                } else {
                    verifySigStatus.style.background = 'rgba(255,85,0,0.08)';
                    verifySigStatus.style.color = 'var(--warning)';
                    verifySigStatus.style.border = '1px solid rgba(255,85,0,0.4)';
                    verifySigStatus.innerText = '\u2715 SIGNATURE INVALID â€” ' + (result.error || 'Verification failed');
                }
            } catch(e) {
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
                `to maintain hash chain integrity â€” it cannot be read\n` +
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
                // Success â€” show brief confirmation then close drawer and refresh
                revokeStatus.style.display = 'block';
                revokeStatus.style.background = 'rgba(0,255,204,0.06)';
                revokeStatus.style.color = 'var(--primary)';
                revokeStatus.style.border = '1px solid rgba(0,255,204,0.25)';
                revokeStatus.innerText = '\u2713 Credential revoked. Refreshing ledger...';

                setTimeout(() => {
                    credentialDrawer.style.display = 'none';
                    revokeStatus.style.display = 'none';
                    activeVcId = null;
                    renderLedger();
                }, 1400);

            } catch(e) {
                revokeStatus.style.display = 'block';
                revokeStatus.innerText = '\u2715 Error: ' + e;
            } finally {
                btnRevokeCredential.innerText = '[ REVOKE ]';
                btnRevokeCredential.disabled = false;
            }
        });
    }

    // ======== IDENTITY BUNDLE EXPORT ========
    if (btnExportIdentity) {
        btnExportIdentity.addEventListener('click', async () => {
            const exportPwd = document.getElementById('export-pwd').value;
            const exportPwdConfirm = document.getElementById('export-pwd-confirm').value;
            exportStatus.className = 'modal-status';
            exportStatus.innerText = '';

            if (!exportPwd) {
                exportStatus.className = 'modal-status err';
                exportStatus.innerText = '\u2715 A backup password is required.';
                document.getElementById('export-pwd').focus();
                return;
            }
            if (exportPwd.length < 8) {
                exportStatus.className = 'modal-status err';
                exportStatus.innerText = '\u2715 Password must be at least 8 characters.';
                return;
            }
            if (exportPwd !== exportPwdConfirm) {
                exportStatus.className = 'modal-status err';
                exportStatus.innerText = '\u2715 Passwords do not match.';
                document.getElementById('export-pwd-confirm').focus();
                return;
            }

            btnExportIdentity.innerText = 'Encrypting... (may take a moment)';
            btnExportIdentity.disabled = true;
            try {
                const bundleJSON = await ExportIdentityBundle(exportPwd);
                const parsed = JSON.parse(bundleJSON);
                if (parsed.error) {
                    exportStatus.className = 'modal-status err';
                    exportStatus.innerText = '\u2715 Error: ' + parsed.error;
                    return;
                }
                const did = parsed.did || 'identity';
                const didShort = did.substring(did.length - 12);
                const defaultName = `verihash_identity_${didShort}.encrypted.json`;
                const saveResult = JSON.parse(await SaveToFile(defaultName, bundleJSON));
                if (saveResult.error) {
                    exportStatus.className = 'modal-status err';
                    exportStatus.innerText = '\u2715 Save failed: ' + saveResult.error;
                } else if (saveResult.cancelled) {
                    exportStatus.innerText = '';
                } else {
                    exportStatus.className = 'modal-status ok';
                    exportStatus.innerText = '\u2713 Encrypted bundle saved. Remember your backup password \u2014 it cannot be recovered.';
                    document.getElementById('export-pwd').value = '';
                    document.getElementById('export-pwd-confirm').value = '';
                }
            } catch(e) {
                exportStatus.className = 'modal-status err';
                exportStatus.innerText = '\u2715 Export failed: ' + e;
            } finally {
                btnExportIdentity.innerHTML = '\u2b07\u00a0EXPORT (ENCRYPTED)';
                btnExportIdentity.disabled = false;
            }
        });
    }

    // ======== IDENTITY BUNDLE IMPORT ========
    if (btnImportIdentity) {
        btnImportIdentity.addEventListener('click', () => {
            const importPwd = document.getElementById('import-pwd').value;
            importStatus.className = 'modal-status';
            importStatus.innerText = '';

            if (!importPwd) {
                importStatus.className = 'modal-status err';
                importStatus.innerText = '\u2715 Enter the bundle password before selecting a file.';
                document.getElementById('import-pwd').focus();
                return;
            }

            const fileInput = document.createElement('input');
            fileInput.type = 'file';
            fileInput.accept = '.json,application/json';
            fileInput.style.display = 'none';
            document.body.appendChild(fileInput);
            fileInput.addEventListener('change', async () => {
                const file = fileInput.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = async (ev) => {
                    const content = ev.target.result;
                    btnImportIdentity.innerHTML = 'Decrypting &amp; verifying...';
                    btnImportIdentity.disabled = true;
                    try {
                        const resultJSON = await ImportIdentityBundle(content, importPwd);
                        const result = JSON.parse(resultJSON);
                        if (result.error) {
                            importStatus.className = 'modal-status err';
                            importStatus.innerText = '\u2715 Failed: ' + result.error;
                        } else {
                            importStatus.className = 'modal-status ok';
                            importStatus.innerHTML = `\u2713 Identity imported!<br>DID: <span style="color:#00cc88;font-size:0.65rem;word-break:break-all;">${result.did || ''}</span><br><br>Restart the app for the new identity to take effect.`;
                            document.getElementById('import-pwd').value = '';
                        }
                    } catch(e) {
                        importStatus.className = 'modal-status err';
                        importStatus.innerText = '\u2715 Import error: ' + e;
                    } finally {
                        btnImportIdentity.innerHTML = '\u2b06\u00a0SELECT BUNDLE &amp; IMPORT';
                        btnImportIdentity.disabled = false;
                    }
                };
                reader.readAsText(file);
                document.body.removeChild(fileInput);
            });
            fileInput.click();
        });
    }

});
