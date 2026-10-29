/**
 * PhishShift — AI-Powered Message Threat Scanner
 * Frontend Application Controller
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Element References
    const statusPill = document.getElementById('system-status-pill');
    const statusLabel = document.getElementById('status-label');
    const scannerForm = document.getElementById('scanner-form');
    const messageInput = document.getElementById('message-input');
    const charCounter = document.getElementById('char-counter');
    const wordCounter = document.getElementById('word-counter');
    const clearBtn = document.getElementById('clear-message-btn');
    const analyzeBtn = document.getElementById('analyze-btn');
    const errorAlert = document.getElementById('scanner-error');
    const errorText = document.getElementById('scanner-error-text');
    const errorDismiss = document.getElementById('error-dismiss');
    const scanningLoader = document.getElementById('scanning-loader');
    const scanningStepText = document.getElementById('scanning-step-text');

    // Results Dashboard References
    const resultsDashboard = document.getElementById('results-dashboard');
    const resultsTimestamp = document.getElementById('results-meta-timestamp');
    const copyReportBtn = document.getElementById('copy-report-btn');
    const copyReportText = document.getElementById('copy-report-text');

    // Verdict Card Elements
    const verdictBadge = document.getElementById('verdict-category-badge');
    const verdictCategory = document.getElementById('verdict-category');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictRiskLevel = document.getElementById('verdict-risk-level');
    const gaugeCircle = document.getElementById('gauge-circle');
    const gaugeScoreValue = document.getElementById('gauge-score-value');
    const verdictExplanation = document.getElementById('verdict-explanation');

    // Confidence Card Elements
    const confValPhishing = document.getElementById('conf-val-phishing');
    const confBarPhishing = document.getElementById('conf-bar-phishing');
    const confValSpam = document.getElementById('conf-val-spam');
    const confBarSpam = document.getElementById('conf-bar-spam');
    const confValLegit = document.getElementById('conf-val-legit');
    const confBarLegit = document.getElementById('conf-bar-legit');

    // Lists Elements
    const indicatorCountBadge = document.getElementById('indicator-count-badge');
    const indicatorsList = document.getElementById('indicators-list');
    const urlCountBadge = document.getElementById('url-count-badge');
    const urlsList = document.getElementById('urls-list');
    const recommendationsList = document.getElementById('recommendations-list');

    // Sample Message Data
    const SAMPLE_MESSAGES = {
        phishing: "URGENT: Your Wells Fargo account has been locked due to suspicious activity. Verify immediately at http://192.168.1.1/login-wf to prevent permanent suspension.",
        package: "USPS: Your package delivery was stopped due to an incorrect street address. Please update your shipping details at http://usps-track-update.xyz/parcel to reschedule.",
        spam: "CONGRATULATIONS! You have been selected as the exclusive winner of a $1,000 Walmart Gift Card! Call 1-800-FREE-NOW or claim your reward now.",
        legitimate: "Hi Sarah, are we still meeting for lunch tomorrow at 12:30 PM at the cafe downtown? Let me know if that time still works for you!"
    };

    let lastScanReport = null;

    // -----------------------------------------------------------------------
    // System Health Check
    // -----------------------------------------------------------------------
    async function checkSystemHealth() {
        try {
            const response = await fetch('/api/health');
            const data = await response.json();
            if (data.model_loaded) {
                statusPill.className = 'system-status-pill';
                statusLabel.textContent = 'Model Active (v1.0)';
                statusPill.title = `Model loaded. Classes: ${data.classes ? data.classes.join(', ') : 'Ready'}`;
            } else {
                statusPill.className = 'system-status-pill degraded';
                statusLabel.textContent = 'Model Offline';
                statusPill.title = data.model_error || 'Model file not found';
            }
        } catch (err) {
            statusPill.className = 'system-status-pill degraded';
            statusLabel.textContent = 'Server Disconnected';
            statusPill.title = 'Could not reach PhishShift backend service';
        }
    }

    // -----------------------------------------------------------------------
    // Character and Word Counter
    // -----------------------------------------------------------------------
    function updateMetrics() {
        const text = messageInput.value;
        const charCount = text.length;
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;

        charCounter.textContent = `${charCount.toLocaleString()} / 10,000 characters`;
        wordCounter.textContent = `${words.toLocaleString()} word${words === 1 ? '' : 's'}`;

        if (charCount > 10000) {
            charCounter.style.color = 'var(--status-danger)';
        } else {
            charCounter.style.color = '';
        }
    }

    messageInput.addEventListener('input', updateMetrics);

    // -----------------------------------------------------------------------
    // Sample Button Handlers
    // -----------------------------------------------------------------------
    document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleType = btn.getAttribute('data-sample');
            if (SAMPLE_MESSAGES[sampleType]) {
                messageInput.value = SAMPLE_MESSAGES[sampleType];
                updateMetrics();
                hideError();
                messageInput.focus();
            }
        });
    });

    // -----------------------------------------------------------------------
    // Clear Button
    // -----------------------------------------------------------------------
    clearBtn.addEventListener('click', () => {
        messageInput.value = '';
        updateMetrics();
        hideError();
        messageInput.focus();
    });

    // Error Alert Controls
    function showError(msg) {
        errorText.textContent = msg;
        errorAlert.classList.remove('hidden');
    }

    function hideError() {
        errorAlert.classList.add('hidden');
    }

    if (errorDismiss) {
        errorDismiss.addEventListener('click', hideError);
    }

    // -----------------------------------------------------------------------
    // Radial SVG Gauge Calculation
    // -----------------------------------------------------------------------
    function updateGauge(score, category) {
        const radius = 50;
        const circumference = 2 * Math.PI * radius; // ~314.16
        const clampedScore = Math.max(0, Math.min(100, score));
        const offset = circumference - (clampedScore / 100) * circumference;

        gaugeCircle.style.strokeDashoffset = offset;

        // Color coding
        gaugeCircle.className.baseVal = 'gauge-progress';
        if (clampedScore >= 70 || category === 'phishing') {
            gaugeCircle.classList.add('gauge-phishing');
        } else if (clampedScore >= 40 || category === 'spam') {
            gaugeCircle.classList.add('gauge-spam');
        } else {
            gaugeCircle.classList.add('gauge-legitimate');
        }

        // Animate counter number
        animateValue(gaugeScoreValue, 0, clampedScore, 800);
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.textContent = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            } else {
                obj.textContent = end;
            }
        };
        window.requestAnimationFrame(step);
    }

    // -----------------------------------------------------------------------
    // Render Results Function
    // -----------------------------------------------------------------------
    function renderScanResults(data) {
        lastScanReport = data;

        // Timestamp & Meta
        const now = new Date();
        resultsTimestamp.textContent = `Scanned ${now.toLocaleTimeString()} • ${data.metadata.analyzed_characters} chars • ${data.metadata.analyzed_words} words`;

        // 1. Verdict Card
        const pred = (data.prediction || 'legitimate').toLowerCase();
        verdictCategory.textContent = data.label || 'Unknown';

        // Badge styling & icon
        verdictBadge.className = 'category-badge';
        if (pred === 'phishing') {
            verdictBadge.classList.add('badge-phishing');
            verdictIcon.textContent = '🚨';
        } else if (pred === 'spam') {
            verdictBadge.classList.add('badge-spam');
            verdictIcon.textContent = '📢';
        } else {
            verdictBadge.classList.add('badge-legitimate');
            verdictIcon.textContent = '🛡️';
        }

        // Risk Level Tag
        const rLevel = data.risk_level || 'Low';
        verdictRiskLevel.className = `risk-level-tag level-${rLevel.toLowerCase()}`;
        verdictRiskLevel.innerHTML = `Risk Level: <strong>${escapeHtml(rLevel)}</strong>`;

        // Heuristic Gauge
        updateGauge(data.risk_score || 0, pred);

        // Synthesis explanation
        verdictExplanation.textContent = data.explanation || 'Analysis completed.';

        // 2. Confidence Card
        if (data.probabilities) {
            const pPhish = Math.round((data.probabilities.phishing || 0) * 100);
            const pSpam = Math.round((data.probabilities.spam || 0) * 100);
            const pLegit = Math.round((data.probabilities.legitimate || 0) * 100);

            confValPhishing.textContent = `${pPhish}%`;
            confBarPhishing.style.width = `${pPhish}%`;

            confValSpam.textContent = `${pSpam}%`;
            confBarSpam.style.width = `${pSpam}%`;

            confValLegit.textContent = `${pLegit}%`;
            confBarLegit.style.width = `${pLegit}%`;
        } else if (data.confidence !== null) {
            const cPct = Math.round(data.confidence * 100);
            confValPhishing.textContent = pred === 'phishing' ? `${cPct}%` : 'N/A';
            confBarPhishing.style.width = pred === 'phishing' ? `${cPct}%` : '0%';
            confValSpam.textContent = pred === 'spam' ? `${cPct}%` : 'N/A';
            confBarSpam.style.width = pred === 'spam' ? `${cPct}%` : '0%';
            confValLegit.textContent = pred === 'legitimate' ? `${cPct}%` : 'N/A';
            confBarLegit.style.width = pred === 'legitimate' ? `${cPct}%` : '0%';
        } else {
            confValPhishing.textContent = 'N/A';
            confValSpam.textContent = 'N/A';
            confValLegit.textContent = 'N/A';
        }

        // 3. Indicators List
        indicatorsList.innerHTML = '';
        const indicators = data.indicators || [];
        indicatorCountBadge.textContent = `${indicators.length} Found`;

        if (indicators.length === 0) {
            const emptyEl = document.createElement('div');
            emptyEl.className = 'empty-state-notice';
            emptyEl.textContent = 'No high-risk textual indicators were triggered in this message.';
            indicatorsList.appendChild(emptyEl);
        } else {
            indicators.forEach(ind => {
                const item = document.createElement('div');
                item.className = `indicator-item severity-${ind.severity || 'medium'}`;

                const header = document.createElement('div');
                header.className = 'indicator-header';

                const name = document.createElement('span');
                name.className = 'indicator-name';
                name.textContent = ind.label || ind.type;

                const sev = document.createElement('span');
                sev.className = `severity-tag sev-${ind.severity || 'medium'}`;
                sev.textContent = (ind.severity || 'medium').toUpperCase();

                header.appendChild(name);
                header.appendChild(sev);
                item.appendChild(header);

                if (ind.description) {
                    const desc = document.createElement('p');
                    desc.className = 'indicator-desc';
                    desc.textContent = ind.description;
                    item.appendChild(desc);
                }

                if (ind.snippets && ind.snippets.length > 0) {
                    const snippetsContainer = document.createElement('div');
                    snippetsContainer.className = 'indicator-snippets';
                    ind.snippets.forEach(snip => {
                        const tag = document.createElement('span');
                        tag.className = 'snippet-tag';
                        tag.textContent = `"${snip}"`;
                        snippetsContainer.appendChild(tag);
                    });
                    item.appendChild(snippetsContainer);
                }

                indicatorsList.appendChild(item);
            });
        }

        // 4. URL Forensics List
        urlsList.innerHTML = '';
        const urls = data.urls || [];
        urlCountBadge.textContent = `${urls.length} Link${urls.length === 1 ? '' : 's'}`;

        if (urls.length === 0) {
            const emptyEl = document.createElement('div');
            emptyEl.className = 'empty-state-notice';
            emptyEl.textContent = 'No web links or URLs were detected in this message.';
            urlsList.appendChild(emptyEl);
        } else {
            urls.forEach(u => {
                const item = document.createElement('div');
                item.className = 'url-item';

                const header = document.createElement('div');
                header.className = 'url-header';

                const host = document.createElement('span');
                host.className = 'url-display-host';
                host.textContent = u.display_host || u.original_url;

                const rTag = document.createElement('span');
                const rLevelStr = (u.risk_level || 'Low').toLowerCase();
                rTag.className = `url-risk-tag url-risk-${rLevelStr}`;
                rTag.textContent = `${u.risk_level || 'Low'} Risk`;

                header.appendChild(host);
                header.appendChild(rTag);
                item.appendChild(header);

                const orig = document.createElement('div');
                orig.className = 'url-original-text';
                orig.textContent = u.original_url;
                item.appendChild(orig);

                if (u.flags && u.flags.length > 0) {
                    const flagsContainer = document.createElement('div');
                    flagsContainer.className = 'url-flags-list';
                    u.flags.forEach(f => {
                        const flagEl = document.createElement('div');
                        flagEl.className = 'url-flag';
                        flagEl.textContent = `• ${f.label}: ${f.detail}`;
                        flagsContainer.appendChild(flagEl);
                    });
                    item.appendChild(flagsContainer);
                }

                urlsList.appendChild(item);
            });
        }

        // 5. Safety Recommendations
        recommendationsList.innerHTML = '';
        const recs = data.recommendations || [];
        recs.forEach(recText => {
            const li = document.createElement('li');
            li.innerHTML = `
                <svg class="rec-check-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                <span>${escapeHtml(recText)}</span>
            `;
            recommendationsList.appendChild(li);
        });

        // Show Dashboard and Scroll Into View
        resultsDashboard.classList.remove('hidden');
        resultsDashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Helper for HTML escaping
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // -----------------------------------------------------------------------
    // Form Submission & API Request
    // -----------------------------------------------------------------------
    scannerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();

        const messageText = messageInput.value.trim();

        if (!messageText) {
            showError('Please enter or paste a message before analyzing.');
            messageInput.focus();
            return;
        }

        if (messageText.length > 10000) {
            showError(`Message length (${messageText.length} characters) exceeds the maximum allowed limit of 10,000 characters.`);
            return;
        }

        // Start scanning loader state
        analyzeBtn.disabled = true;
        scanningLoader.classList.remove('hidden');
        resultsDashboard.classList.add('hidden');

        // Progressive steps for visual feedback
        const steps = [
            "Extracting message tokens and n-grams...",
            "Evaluating TF-IDF vectors with Logistic Regression...",
            "Inspecting URL structures and domain reputation flags...",
            "Synthesizing heuristic risk score and advisory report..."
        ];

        let stepIndex = 0;
        scanningStepText.textContent = steps[0];
        const stepInterval = setInterval(() => {
            stepIndex = (stepIndex + 1) % steps.length;
            scanningStepText.textContent = steps[stepIndex];
        }, 350);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: messageText })
            });

            clearInterval(stepInterval);
            const data = await response.json();

            if (!response.ok || !data.success) {
                const errMsg = data.error || `Server responded with status ${response.status}.`;
                showError(errMsg);
                return;
            }

            // Render genuine backend results
            renderScanResults(data);

        } catch (err) {
            clearInterval(stepInterval);
            console.error('[PhishShift Network Error]', err);
            showError('Network error: Unable to contact the PhishShift scanning API. Please check your connection and ensure the server is running.');
        } finally {
            analyzeBtn.disabled = false;
            scanningLoader.classList.add('hidden');
        }
    });

    // -----------------------------------------------------------------------
    // Copy Summary to Clipboard
    // -----------------------------------------------------------------------
    copyReportBtn.addEventListener('click', async () => {
        if (!lastScanReport) return;

        const summary = [
            `--- PhishShift Security Report ---`,
            `Verdict: ${lastScanReport.label} (Risk Level: ${lastScanReport.risk_level})`,
            `Heuristic Risk Score: ${lastScanReport.risk_score} / 100`,
            `Model Confidence: ${lastScanReport.confidence ? Math.round(lastScanReport.confidence * 100) + '%' : 'N/A'}`,
            `Synthesis: ${lastScanReport.explanation}`,
            `Extracted URLs: ${(lastScanReport.urls || []).length}`,
            `Indicators Found: ${(lastScanReport.indicators || []).map(i => i.label).join(', ') || 'None'}`,
            `----------------------------------`
        ].join('\n');

        try {
            await navigator.clipboard.writeText(summary);
            copyReportText.textContent = 'Copied!';
            setTimeout(() => {
                copyReportText.textContent = 'Copy Summary';
            }, 2000);
        } catch (err) {
            console.error('Clipboard copy failed:', err);
        }
    });

    // Run Initial Health Check
    checkSystemHealth();
});
