const ScanState = {
    IDLE: 'idle',
    VALIDATING: 'validating',
    SCANNING: 'scanning',
    COMPLETED: 'completed',
    PARTIAL: 'partial',
    FAILED: 'failed'
};

let currentScanState = ScanState.IDLE;
let data = null;

function resetResultsState() {
    data = null;
    const scoreVal = document.getElementById('scoreValue');
    if (scoreVal) scoreVal.textContent = '--';

    const scoreStat = document.getElementById('scoreStatus');
    if (scoreStat) {
        scoreStat.textContent = 'Not Scanned';
        scoreStat.classList.remove('risk-low', 'risk-medium', 'risk-high');
    }

    const downloadBtn = document.getElementById('downloadReportBtn');
    if (downloadBtn) {
        downloadBtn.disabled = true;
    }

    resetAllFieldsToPlaceholder('Not scanned yet');
}

function setScanState(state, payload = {}) {
    currentScanState = state;
    console.log(`[ScanState] Transitioned to: ${state}`, payload);

    const badgeEl = document.getElementById('scanStatusBadge');
    const scoreCardEl = document.getElementById('scoreCardResult');
    const downloadBtn = document.getElementById('downloadReportBtn');
    const errorBanner = document.getElementById('scanErrorBanner');
    const heroProgress = document.getElementById('heroScanProgress');
    const inlineProgress = document.getElementById('inlineScanProgress');
    const scanBtn = document.querySelector('.scan-btn');
    const expandBtns = document.querySelectorAll('.expand-btn');

    if (badgeEl) {
        badgeEl.className = 'scan-status-badge';
    }

    if (errorBanner && state !== ScanState.FAILED) {
        errorBanner.style.display = 'none';
    }

    if (heroProgress) {
        heroProgress.style.display = state === ScanState.SCANNING ? 'flex' : 'none';
    }

    if (inlineProgress) {
        inlineProgress.style.display = state === ScanState.SCANNING ? 'flex' : 'none';
    }

    switch (state) {
        case ScanState.IDLE:
            if (badgeEl) {
                badgeEl.textContent = 'Not Started';
                badgeEl.classList.add('badge-idle');
            }
            if (scoreCardEl) {
                scoreCardEl.style.display = 'none';
            }
            resetResultsState();
            if (scanBtn) {
                scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan Now';
                scanBtn.disabled = false;
            }
            break;

        case ScanState.VALIDATING:
            if (badgeEl) {
                badgeEl.textContent = 'Validating URL...';
                badgeEl.classList.add('badge-idle');
            }
            if (scanBtn) {
                scanBtn.disabled = true;
            }
            break;

        case ScanState.SCANNING:
            if (badgeEl) {
                badgeEl.textContent = 'Scanning...';
                badgeEl.classList.add('badge-scanning');
            }
            if (scoreCardEl) {
                scoreCardEl.style.display = 'none';
            }
            if (downloadBtn) {
                downloadBtn.disabled = true;
            }
            expandBtns.forEach(btn => {
                btn.disabled = true;
            });
            resetAllFieldsToPlaceholder('Scanning...');
            if (scanBtn) {
                scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
                scanBtn.disabled = true;
            }
            break;

        case ScanState.COMPLETED:
            if (badgeEl) {
                badgeEl.textContent = 'Scan Complete';
                badgeEl.classList.add('badge-completed');
            }
            if (scoreCardEl) {
                scoreCardEl.style.display = 'block';
            }
            if (downloadBtn) {
                downloadBtn.disabled = false;
            }
            expandBtns.forEach(btn => {
                btn.disabled = false;
            });
            if (scanBtn) {
                scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan Now';
                scanBtn.disabled = false;
            }
            break;

        case ScanState.PARTIAL:
            if (badgeEl) {
                badgeEl.textContent = 'Partial Results';
                badgeEl.classList.add('badge-partial');
            }
            if (scoreCardEl) {
                scoreCardEl.style.display = 'block';
            }
            if (downloadBtn) {
                downloadBtn.disabled = false;
            }
            expandBtns.forEach(btn => {
                btn.disabled = false;
            });
            if (scanBtn) {
                scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan Now';
                scanBtn.disabled = false;
            }
            break;

        case ScanState.FAILED:
            if (badgeEl) {
                badgeEl.textContent = 'Scan Failed';
                badgeEl.classList.add('badge-failed');
            }
            if (scoreCardEl) {
                scoreCardEl.style.display = 'none';
            }
            resetResultsState();
            if (errorBanner) {
                errorBanner.style.display = 'flex';
                const errText = document.getElementById('scanErrorText');
                if (errText) {
                    errText.textContent = payload.error || 'Scan failed to complete. Please check the website URL and try again.';
                }
            }
            expandBtns.forEach(btn => {
                btn.disabled = true;
            });
            if (scanBtn) {
                scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan Now';
                scanBtn.disabled = false;
            }
            break;
    }
}

function resetAllFieldsToPlaceholder(text = 'Not scanned yet') {
    const textIds = [
        'humanSummaryText', 'metaIp', 'metaLocation', 'metaIsp', 'metaCreated',
        'metaRegistrar', 'metaConnectionType', 'sslStatus', 'sslProtocol',
        'sslExpires', 'sslCert', 'sslProtocolVersion', 'sslCipher', 'sslIssuer',
        'sslSubjectCN', 'sslSanDomains', 'sslSelfSigned', 'sslSerial',
        'seoTitle', 'seoMetaDescription', 'seoMissingAltImages', 'headingCount',
        'seoCanonical', 'seoRobots', 'seoViewport', 'seoOgTitle', 'seoOgDescription',
        'seoWordCount', 'runningServices', 'openPorts', 'vulnerablePorts',
        'criticalVuln', 'highVuln', 'mediumVuln', 'lowVuln', 'performanceScore',
        'fcp', 'lcp', 'speedIndex', 'pageLoadTime', 'ttfb', 'mobileFriendly',
        'dnsIp', 'dnsA', 'dnsMX', 'dnsNS', 'dnsTXT', 'perfTbt', 'perfCls',
        'dnsSpfRecord', 'dnsDmarcRecord', 'techServer', 'techPoweredBy',
        'techGenerator', 'techCookies', 'resultUrl', 'resultDate'
    ];

    textIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = text;
        }
    });

    const techContainer = document.getElementById('technologyContainer');
    if (techContainer) {
        techContainer.innerHTML = `<div class="technology-loading">${text}</div>`;
    }

    const recList = document.getElementById('recommendationsList');
    if (recList) {
        recList.innerHTML = `<li>${text}</li>`;
    }

    const corsList = document.getElementById('corsFindingsList');
    if (corsList) {
        corsList.innerHTML = `<div style="opacity: 0.6; padding: 4px 0;">${text}</div>`;
    }
    const corsBadge = document.getElementById('corsRiskBadge');
    if (corsBadge) {
        corsBadge.innerHTML = `<span style="opacity: 0.6;">${text}</span>`;
    }

    const expContainer = document.getElementById('exposedPathsContainer');
    if (expContainer) {
        expContainer.innerHTML = `<div style="opacity: 0.6; padding: 4px 0;">${text}</div>`;
    }
    const expBadge = document.getElementById('exposedPathsRiskBadge');
    if (expBadge) {
        expBadge.innerHTML = `<span style="opacity: 0.6;">${text}</span>`;
    }

    const portsRisk = document.getElementById('portsRiskDetails');
    if (portsRisk) {
        portsRisk.innerHTML = `<div style="opacity: 0.6; padding: 4px 0;">${text}</div>`;
    }

    const headersMissing = document.getElementById('headersMissingDetails');
    if (headersMissing) {
        headersMissing.innerHTML = `<div style="opacity: 0.6; padding: 4px 0;">${text}</div>`;
    }
    const headersCount = document.getElementById('headersMissingCount');
    if (headersCount) {
        headersCount.textContent = text;
    }
}

function retryScan() {
    resetResultsState();
    setScanState(ScanState.IDLE);
    const errorBanner = document.getElementById('scanErrorBanner');
    if (errorBanner) errorBanner.style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('heroSection').style.display = 'block';
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.focus();
    }
}

async function scanWebsite() {
    try {
        const urlInput = document.getElementById('urlInput');
        const errorEl = document.getElementById('urlInputError');
        const rawUrl = urlInput ? urlInput.value.trim() : '';

        if (errorEl) {
            errorEl.style.display = 'none';
            errorEl.textContent = '';
        }
        if (urlInput) {
            urlInput.style.borderColor = '';
        }

        setScanState(ScanState.VALIDATING);

        if (!rawUrl || !isValidUrl(rawUrl)) {
            const msg = !rawUrl ? 'Please enter a website URL' : 'Please enter a valid website URL (e.g., https://example.com)';
            if (errorEl) {
                errorEl.textContent = msg;
                errorEl.style.display = 'block';
            }
            if (urlInput) {
                urlInput.style.borderColor = 'var(--danger)';
            }
            setScanState(ScanState.IDLE);
            return;
        }

        let url = rawUrl;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        document.querySelectorAll('.card-expanded-details').forEach(panel => {
            panel.classList.remove('open');
            panel.style.maxHeight = '0px';
        });
        document.querySelectorAll('.expand-btn').forEach(btn => {
            btn.classList.remove('active');
            const span = btn.querySelector('span');
            if (span) span.textContent = 'View Full Details';
        });

        document.getElementById('heroSection').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'block';

        const chatWidget = document.getElementById('aiChatbotWidget');
        if (chatWidget) {
            chatWidget.style.display = 'block';
        }

        setScanState(ScanState.SCANNING);

        const apiHost = typeof auth !== 'undefined' ? auth.backendBase : (typeof window.getBackendBaseUrl === 'function' ? window.getBackendBaseUrl() : 'https://shieldscope-backend-e3hu.onrender.com');
        const apiUrl = `${apiHost}/scan`;

        const token = typeof auth !== 'undefined' ? auth.getToken() : null;
        const headers = {
            'Content-Type': 'application/json'
        };
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url })
        });

        // Handle authentication and authorization errors before parsing body
        if (response.status === 401) {
            auth.clearSession();
            setScanState(ScanState.FAILED, { error: 'Your session has expired. Please log in again.' });
            setTimeout(() => { window.location.href = 'login.html'; }, 2000);
            return;
        }

        if (response.status === 403) {
            let detail = 'No scans remaining. Please upgrade your account.';
            try { const errData = await response.json(); detail = errData.detail || detail; } catch(e) {}
            setScanState(ScanState.FAILED, { error: detail });
            return;
        }

        if (!response.ok) {
            throw new Error(`Backend Error: ${response.status}`);
        }

        data = await response.json();
        console.log("API Response:", data);

        if (!data || data.success === false) {
            const errorMsg = data?.error || data?.summary?.human_summary || "Scan failed to complete. Please check the website URL.";
            setScanState(ScanState.FAILED, { error: errorMsg });
            return;
        }

        let isPartial = data.status === 'partial';
        if (data.scans) {
            Object.values(data.scans).forEach(scanner => {
                if (scanner && typeof scanner === 'object' && scanner.success === false) {
                    isPartial = true;
                }
            });
        }

        const nextState = isPartial ? ScanState.PARTIAL : ScanState.COMPLETED;

        displayScanData(url, data);

        setScanState(nextState);

        setTimeout(() => {
            const resSec = document.getElementById('resultsSection');
            if (resSec) resSec.scrollIntoView({ behavior: 'smooth' });
        }, 300);

    } catch (error) {
        console.error("Scan error:", error);
        setScanState(ScanState.FAILED, { error: error.message || 'An unexpected error occurred while processing results.' });
    }
}

// Universal DOM renderer for scan data (shared between index and dashboard)
function displayScanData(url, data) {
    if (!data) return;

    let domain = url;
    try {
        domain = new URL(url).hostname;
    } catch (_) {}

    const setElemText = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setElemText('resultWebsite', domain);
    setElemText('resultUrl', url);
    setElemText('resultDate', data.createdAt ? new Date(data.createdAt).toLocaleString() : new Date().toLocaleString());
    setElemText('scannerVersion', 'Engine v1.0');

    setElemText('humanSummaryText', data.summary?.human_summary || "No summary generated.");

    const info = data.website_info || {};
    setElemText('metaIp', info.ip_address || "N/A");
    setElemText('metaLocation', info.country || "N/A");
    setElemText('metaIsp', info.isp || "N/A");
    setElemText('metaCreated', info.created || "N/A");
    setElemText('metaRegistrar', info.registrar || "N/A");
    setElemText('metaConnectionType', data.scans?.ssl?.ssl_enabled ? 'Secure (HTTPS)' : 'Insecure (HTTP)');

    const score = data.summary?.security_score ?? data.score ?? 0;
    setElemText('scoreValue', score);

    const scoreStatus = document.getElementById('scoreStatus');
    if (scoreStatus) {
        const riskLevel = data.summary?.risk_level || data.risk_level || 'UNKNOWN';
        scoreStatus.textContent = riskLevel;
        scoreStatus.classList.remove('risk-low', 'risk-medium', 'risk-high');
        const riskVal = (riskLevel || '').toUpperCase();
        if (riskVal === 'HIGH' || riskVal.includes('HIGH')) {
            scoreStatus.classList.add('risk-high');
        } else if (riskVal === 'MEDIUM' || riskVal.includes('MEDIUM')) {
            scoreStatus.classList.add('risk-medium');
        } else {
            scoreStatus.classList.add('risk-low');
        }
    }

    const progressCircle = document.getElementById('progressCircle');
    if (progressCircle) {
        const circumference = 282.7;
        const offset = circumference - (score / 100) * circumference;
        progressCircle.style.strokeDashoffset = offset;
    }

    const sslScan = data.scans?.ssl || {};
    if (sslScan.success === false) {
        setElemText('sslStatus', 'Scan failed for this category');
        setElemText('sslProtocol', 'Scan failed for this category');
        setElemText('sslExpires', 'Scan failed for this category');
        setElemText('sslCert', 'Scan failed for this category');
    } else {
        setElemText('sslStatus', sslScan.ssl_enabled ? 'Enabled' : 'Disabled');
        setElemText('sslProtocol', sslScan.protocol_version || 'None');
        setElemText('sslExpires', sslScan.expiry_date || 'N/A');
        setElemText('sslCert', sslScan.is_self_signed ? 'Self-Signed (Warning)' : (sslScan.success ? 'Valid' : 'Invalid'));
    }

    const portsScan = data.scans?.ports || {};
    if (portsScan.success === false) {
        setElemText('runningServices', 'Scan failed for this category');
        setElemText('openPorts', 'Scan failed for this category');
        setElemText('vulnerablePorts', 'Scan failed for this category');
    } else {
        const openPorts = portsScan.open_ports || [];
        const vulnerablePorts = portsScan.vulnerable_ports || [];
        const vulnCounts = portsScan.vulnerability_counts || {};

        setElemText('runningServices', openPorts.length > 0 ? openPorts.map(port => typeof port === 'object' ? port.service : port).join(', ') : 'None');
        setElemText('openPorts', openPorts.length);
        setElemText('vulnerablePorts', vulnerablePorts.length);

        setElemText('criticalVuln', vulnCounts.critical ?? 0);
        setElemText('highVuln', vulnCounts.high ?? 0);
        setElemText('mediumVuln', vulnCounts.medium ?? 0);
        setElemText('lowVuln', vulnCounts.low ?? 0);

        setElemText('vulnCritical', vulnCounts.critical ?? 0);
        setElemText('vulnHigh', vulnCounts.high ?? 0);
        setElemText('vulnMedium', vulnCounts.medium ?? 0);
        setElemText('vulnLow', vulnCounts.low ?? 0);
    }

    const perf = data.scans?.performance || {};
    if (perf && perf.success !== false) {
        setElemText('performanceScore', perf.performance_score !== undefined && perf.performance_score !== null ? Math.round(perf.performance_score) : 'N/A');
        setElemText('fcp', perf.first_contentful_paint || 'N/A');
        setElemText('lcp', perf.largest_contentful_paint || 'N/A');
        setElemText('speedIndex', perf.speed_index || 'N/A');
        setElemText('pageLoadTime', perf.page_load_time || 'N/A');
        setElemText('ttfb', perf.ttfb || 'N/A');
        setElemText('mobileFriendly', perf.mobile_friendly || 'N/A');
    } else {
        setElemText('performanceScore', 'Scan failed for this category');
        setElemText('fcp', 'Scan failed for this category');
        setElemText('lcp', 'Scan failed for this category');
        setElemText('speedIndex', 'Scan failed for this category');
        setElemText('pageLoadTime', 'Scan failed for this category');
        setElemText('ttfb', 'Scan failed for this category');
        setElemText('mobileFriendly', 'Scan failed for this category');
    }

    const dnsScan = data.scans?.dns || {};
    if (dnsScan.success === false) {
        setElemText('dnsIp', 'Scan failed for this category');
        setElemText('dnsA', 'Scan failed for this category');
        setElemText('dnsMX', 'Scan failed for this category');
        setElemText('dnsNS', 'Scan failed for this category');
        setElemText('dnsTXT', 'Scan failed for this category');
    } else {
        setElemText('dnsIp', dnsScan.ip_address || 'N/A');
        setElemText('dnsA', (dnsScan.A?.length) ? dnsScan.A.join(", ") : "None");
        setElemText('dnsMX', (dnsScan.MX?.length) ? dnsScan.MX.join(", ") : "None");
        setElemText('dnsNS', (dnsScan.NS?.length) ? dnsScan.NS.join(", ") : "None");
        setElemText('dnsTXT', (dnsScan.TXT?.length) ? dnsScan.TXT.slice(0, 3).join(", ") : "None");
    }

    const technologyContainer = document.getElementById("technologyContainer");
    if (technologyContainer) {
        const technology = data.scans?.technology || {};
        if (technology.success && technology.technologies && Object.keys(technology.technologies).length > 0) {
            technologyContainer.innerHTML = "";
            Object.entries(technology.technologies).forEach(([key, value]) => {
                const item = document.createElement("div");
                item.className = "tech-item";
                const title = document.createElement("div");
                title.className = "tech-title";
                title.textContent = key.replace(/-/g, " ").replace(/\b\w/g, l => l.toUpperCase());
                const techValue = document.createElement("div");
                techValue.className = "tech-value";
                techValue.textContent = Array.isArray(value) ? value.join(", ") : value;
                item.appendChild(title);
                item.appendChild(techValue);
                technologyContainer.appendChild(item);
            });
        } else if (technology.success === false) {
            technologyContainer.innerHTML = `<div class="technology-loading">Scan failed for this category</div>`;
        } else {
            technologyContainer.innerHTML = `<div class="technology-loading">No technology detected.</div>`;
        }
    }

    const seoScan = data.scans?.seo || {};
    if (seoScan.success === false) {
        setElemText('seoTitle', 'Scan failed for this category');
        setElemText('seoMetaDescription', 'Scan failed for this category');
        setElemText('seoMissingAltImages', 'Scan failed for this category');
        setElemText('headingCount', 'Scan failed for this category');
    } else {
        setElemText('seoTitle', seoScan.title || 'Not Found');
        setElemText('seoMetaDescription', seoScan.meta_description ? 'Present' : 'Missing');
        setElemText('seoMissingAltImages', seoScan.missing_alt_images ?? 0);
        setElemText('headingCount', seoScan.h1_count ?? 0);
    }

    const recommendations = data.summary?.recommendations || [];
    const recommendationList = document.getElementById("recommendationsList");
    if (recommendationList) {
        recommendationList.innerHTML = "";
        if (recommendations.length > 0) {
            recommendations.forEach(rec => {
                const li = document.createElement("li");
                li.textContent = rec;
                recommendationList.appendChild(li);
            });
        } else {
            recommendationList.innerHTML = "<li>No specific recommendations.</li>";
        }
    }

    if (typeof populateSslDetails === 'function') populateSslDetails(data.scans?.ssl);
    if (typeof populateSeoDetails === 'function') populateSeoDetails(data.scans?.seo);
    if (typeof populatePerformanceDetails === 'function') populatePerformanceDetails(data.scans?.performance);
    if (typeof populateDnsDetails === 'function') populateDnsDetails(data.scans?.dns);
    if (typeof populateTechnologyDetails === 'function') populateTechnologyDetails(data.scans?.technology);
    if (typeof populatePortsDetails === 'function') populatePortsDetails(data.scans?.ports);
    if (typeof populateHeadersDetails === 'function') populateHeadersDetails(data.scans?.headers);
    if (typeof populateCorsDetails === 'function') populateCorsDetails(data.scans?.cors);
    if (typeof populateExposedPathsDetails === 'function') populateExposedPathsDetails(data.scans?.exposed_paths);
}

    } catch (error) {
        console.error("Scan error:", error);
        setScanState(ScanState.FAILED, { error: error.message || 'An unexpected error occurred while processing results.' });
    }
}

// Update progress bars
function updateProgressBar(id, percentage) {

    const value =
        document.getElementById(id);

    if (value) {
        value.textContent = percentage + "%";
    }

    let fillId = "";

    if (id === "metaTags") {
        fillId = "metaTagsFill";
    }

    else if (id === "headingCount") {
        fillId = "headingFill";
    }

    else if (id === "missingAlt") {
        fillId = "accessibilityFill";
    }

    const fill =
        document.getElementById(fillId);

    if (fill) {

        fill.style.width =
            percentage + "%";
    }
}

// Back to Scanner
function backToScanner() {
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('heroSection').style.display = 'block';
    const urlInput = document.getElementById('urlInput');
    if (urlInput) urlInput.value = '';
    const errorEl = document.getElementById('urlInputError');
    if (errorEl) {
        errorEl.style.display = 'none';
        errorEl.textContent = '';
    }
    setScanState(ScanState.IDLE);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Download Report (TXT)
function downloadReport() {
    if (currentScanState !== ScanState.COMPLETED && currentScanState !== ScanState.PARTIAL) {
        console.warn('Report download attempted outside COMPLETED or PARTIAL state.');
        return;
    }

    const website = document.getElementById('resultWebsite')?.textContent || 'scanner-report';
    const url = document.getElementById('resultUrl')?.textContent || '-';
    const score = document.getElementById('scoreValue')?.textContent || 'N/A';
    const status = document.getElementById('scoreStatus')?.textContent || 'UNKNOWN';
    const date = document.getElementById('resultDate')?.textContent || new Date().toLocaleString();
    const version = document.getElementById('scannerVersion')?.textContent || 'v1.0';
    const humanSummary = document.getElementById('humanSummaryText')?.textContent || 'No summary available.';

    const metaIp = document.getElementById('metaIp')?.textContent || '-';
    const metaLoc = document.getElementById('metaLocation')?.textContent || '-';
    const metaIsp = document.getElementById('metaIsp')?.textContent || '-';
    const metaCreated = document.getElementById('metaCreated')?.textContent || '-';
    const metaReg = document.getElementById('metaRegistrar')?.textContent || '-';
    const metaConn = document.getElementById('metaConnectionType')?.textContent || '-';

    const reportContent = `
WEBSITE SECURITY SCAN REPORT (${currentScanState.toUpperCase()})
========================================

Website: ${website}
URL: ${url}
Scan Date: ${date}
Scanner Engine: ${version}

SECURITY SCORE: ${score}/100 (${status} Risk)

HUMAN-FRIENDLY SUMMARY
========================================
${humanSummary}

WEBSITE INFO & DETAILS
========================================
- IP Address: ${metaIp}
- Hosting Location: ${metaLoc}
- Internet Provider (ISP): ${metaIsp}
- Domain Created: ${metaCreated}
- Domain Registrar: ${metaReg}
- Connection Security: ${metaConn}

========================================
DETAILED SECURITY METRICS
========================================

SSL/TLS CERTIFICATE:
- Status: ${document.getElementById('sslStatus')?.textContent || '-'}
- Protocol: ${document.getElementById('sslProtocol')?.textContent || '-'}
- Expires: ${document.getElementById('sslExpires')?.textContent || '-'}

PORT SCAN:
- Open Ports: ${document.getElementById('openPorts')?.textContent || '0'}
- Vulnerable: ${document.getElementById('vulnerablePorts')?.textContent || '0'}
- Critical Vulnerabilities: ${document.getElementById('criticalVuln')?.textContent || '0'}
- High Vulnerabilities: ${document.getElementById('highVuln')?.textContent || '0'}
- Medium Vulnerabilities: ${document.getElementById('mediumVuln')?.textContent || '0'}
- Low Vulnerabilities: ${document.getElementById('lowVuln')?.textContent || '0'}
- Services: ${document.getElementById('runningServices')?.textContent || 'None'}

DNS INFORMATION:
- IP Address: ${document.getElementById('dnsIp')?.textContent || '-'}
- A Records: ${document.getElementById('dnsA')?.textContent || 'None'}
- MX Records: ${document.getElementById('dnsMX')?.textContent || 'None'}
- NS Records: ${document.getElementById('dnsNS')?.textContent || 'None'}
- TXT Records: ${document.getElementById('dnsTXT')?.textContent || 'None'}

PERFORMANCE:
- Performance Score: ${document.getElementById('performanceScore')?.textContent || '-'}
- First Contentful Paint: ${document.getElementById('fcp')?.textContent || '-'}
- Largest Contentful Paint: ${document.getElementById('lcp')?.textContent || '-'}
- Speed Index: ${document.getElementById('speedIndex')?.textContent || '-'}

SEO ANALYSIS:
- Title: ${document.getElementById('seoTitle')?.textContent || 'Missing'}
- Meta Description: ${document.getElementById('seoMetaDescription')?.textContent || 'Missing'}
- H1 Count: ${document.getElementById('headingCount')?.textContent || '0'}
- Missing Alt Images: ${document.getElementById('seoMissingAltImages')?.textContent || '0'}

CORS CONFIGURATION:
- Risk Level: ${data?.scans?.cors?.risk_level || 'LOW'}
- Tests Performed: ${data?.scans?.cors?.tests_performed ? data.scans.cors.tests_performed.join(', ') : 'N/A'}
- Findings: ${data?.scans?.cors?.findings ? data.scans.cors.findings.map(f => `[${f.severity}/${f.confidence || '-'}] ${f.title || f.issue}${f.exploitability ? ' (Exploitability: ' + f.exploitability + ')' : ''}${f.impact ? ' — Impact: ' + f.impact : ''}`).join('; ') : 'None'}

EXPOSED SENSITIVE FILES:
- Risk Level: ${data?.scans?.exposed_paths?.risk_level || 'LOW'}
- Exposed Files: ${data?.scans?.exposed_paths?.exposed_count !== undefined ? `${data.scans.exposed_paths.exposed_count} of ${data.scans.exposed_paths.total_checked}` : 'N/A'}
- Findings: ${data?.scans?.exposed_paths?.exposed_paths && data.scans.exposed_paths.exposed_paths.length > 0 ? data.scans.exposed_paths.exposed_paths.map(f => `[${f.severity}] ${f.path} - ${f.description}`).join('; ') : 'None'}

RECOMMENDATIONS:
${Array.from(document.querySelectorAll('#recommendationsList li')).map(li => `- ${li.textContent}`).join('\n') || 'None'}

Generated by Website Security Scanner (${version})
${new Date().toLocaleString()}
    `;

    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(reportContent));
    element.setAttribute('download', `security-report-${website.replace(/[^a-zA-Z0-9.-]/g, '_')}-${Date.now()}.txt`);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// Validate URL
function isValidUrl(string) {
    if (!string) return false;
    let urlString = string.trim();
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
        urlString = 'https://' + urlString;
    }
    try {
        const parsed = new URL(urlString);
        return Boolean(parsed.hostname && parsed.hostname.includes('.'));
    } catch (_) {
        return false;
    }
}

// Add animation on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.animation = 'fadeInUp 0.6s ease forwards';
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe all cards and sections
document.querySelectorAll('.detector-card, .step-card, .score-card, .risk-card, .value-card, .feature-card, .pricing-card, .result-card').forEach(el => {
    observer.observe(el);
});

// Add animation keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-30px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }

    @keyframes floatIn {
        from {
            opacity: 0;
            transform: translateY(20px) scale(0.95);
        }
        to {
            opacity: 1;
            transform: translateY(0) scale(1);
        }
    }

    @keyframes glow {
        0%, 100% {
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        50% {
            box-shadow: 0 0 40px rgba(0, 212, 255, 0.5);
        }
    }

    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }

    .fa-spinner {
        animation: spin 1s linear infinite;
    }

    .hero h1 {
        animation: slideDown 0.8s ease;
    }
`;
document.head.appendChild(style);

// Navbar scroll effect
let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', function() {
    let scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    if (scrollTop > 100) {
        navbar.style.boxShadow = '0 5px 20px rgba(0, 0, 0, 0.3)';
    } else {
        navbar.style.boxShadow = 'none';
    }
    
    lastScrollTop = scrollTop <= 0 ? 0 : scrollTop;
});

// Pricing plan selection
document.addEventListener('DOMContentLoaded', function() {
    const pricingBtns = document.querySelectorAll('.pricing-btn');
    pricingBtns.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const planName = this.parentElement.querySelector('h3').textContent;
            alert(`You selected the ${planName} plan. Proceeding to checkout...`);
        });
    });
});

// Add hover effects to table rows
const tableRows = document.querySelectorAll('.scan-table tbody tr');
tableRows.forEach(row => {
    row.addEventListener('click', function() {
        const website = this.querySelector('td:first-child').textContent;
        console.log('Selected website:', website);
    });
});

// Mobile menu toggle (if needed in future)
function toggleMobileMenu() {
    const navMenu = document.querySelector('.nav-menu');
    navMenu.style.display = navMenu.style.display === 'flex' ? 'none' : 'flex';
}

// Debounce function for window resize
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Handle window resize for responsive adjustments
const handleResize = debounce(function() {
    console.log('Window resized');
}, 250);

window.addEventListener('resize', handleResize);

// Auto-format URL input
document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('blur', function() {
            let value = this.value.trim();
            if (value && !value.startsWith('http')) {
                value = 'https://' + value;
                this.value = value;
            }
        });
    }
});

// Add keyboard shortcut for scan (Enter key)
document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                scanWebsite();
            }
        });
    }
});

// Analytics tracking (placeholder)
function trackEvent(eventName, eventData) {
    console.log('Event tracked:', {
        event: eventName,
        data: eventData,
        timestamp: new Date().toISOString()
    });
    // In production, this would send data to an analytics service
}

// Track page views
trackEvent('page_view', {
    page: 'home',
    url: window.location.href
});

// Track button clicks
document.querySelectorAll('button, a').forEach(element => {
    element.addEventListener('click', function() {
        trackEvent('button_click', {
            text: this.textContent.trim(),
            type: this.tagName.toLowerCase()
        });
    });
});


// ===========================
// FAQ Toggle Functionality
// ===========================
function toggleFAQ(element) {
    // Close all other FAQ items
    document.querySelectorAll('.faq-question').forEach(item => {
        if (item !== element) {
            item.classList.remove('active');
            item.nextElementSibling.classList.remove('active');
        }
    });

    // Toggle current FAQ item
    element.classList.toggle('active');
    element.nextElementSibling.classList.toggle('active');
}

// =========================
// SEO MODAL FUNCTIONS
// =========================

// Close Modal
function closeDetailModal() {
    const modal = document.getElementById('detailModal');
    modal.style.display = 'none';
}

// Show Meta Description Details
function showMetaDescriptionDetails() {
    if (!data || !data.scans || !data.scans.seo) {
        alert('No SEO data available');
        return;
    }

    const seoData = data.scans.seo;
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    // Set title
    modalTitle.innerHTML = '<i class="fas fa-file-alt"></i> Meta Description Details';

    // Build content
    let content = '';

    if (seoData.meta_description) {
        content = `
            <div class="details-list">
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-check-circle"></i> Meta Description Found
                    </div>
                    <div class="detail-item-content">
                        ${seoData.meta_description}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-ruler"></i> Length
                    </div>
                    <div class="detail-item-content">
                        ${seoData.meta_description.length} characters
                        <br/>
                        <small style="color: var(--text-secondary);">
                            ${seoData.meta_description.length >= 120 && seoData.meta_description.length <= 160 
                                ? '✅ Optimal length (120-160 chars)' 
                                : '⚠️ Consider adjusting to 120-160 characters'}
                        </small>
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-lightbulb"></i> SEO Tip
                    </div>
                    <div class="detail-item-content">
                        A good meta description should be between 120-160 characters and include your main keywords. This text appears in search engine results and helps users decide whether to click your link.
                    </div>
                </div>
            </div>
        `;
    } else {
        content = `
            <div class="empty-state">
                <i class="fas fa-times-circle"></i>
                <h3 style="color: var(--danger);">No Meta Description Found</h3>
                <p>This page is missing a meta description. This is important for SEO and search engine visibility.</p>
                <p style="margin-top: 1.5rem; font-size: 0.9rem;">
                    <strong>Recommendation:</strong> Add a meta description tag to your HTML:
                </p>
                <div style="background: var(--code-bg); padding: 1rem; border: 1px solid var(--code-border); border-radius: 0.5rem; margin-top: 1rem; text-align: left;">
                    <code style="color: var(--primary);">&lt;meta name="description" content="Your description here" /&gt;</code>
                </div>
            </div>
        `;
    }

    modalBody.innerHTML = content;
    modal.style.display = 'flex';
}

// Show H1 Tags Details
function showH1TagsDetails() {
    if (!data || !data.scans || !data.scans.seo) {
        alert('No SEO data available');
        return;
    }

    const seoData = data.scans.seo;
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    // Set title
    modalTitle.innerHTML = `<i class="fas fa-heading"></i> H1 Tags Details`;

    // Build content
    let content = '';

    if (seoData.h1_tags && seoData.h1_tags.length > 0) {
        const h1List = seoData.h1_tags.map((h1, index) => `
            <div class="detail-item">
                <div class="detail-item-label">
                    <i class="fas fa-heading"></i> H1 Tag #${index + 1}
                </div>
                <div class="detail-item-content">
                    "${h1}"
                </div>
            </div>
        `).join('');

        content = `
            <div class="details-list">
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-check-circle"></i> Total H1 Tags Found
                    </div>
                    <div class="detail-item-content">
                        ${seoData.h1_tags.length}
                        <br/>
                        <small style="color: var(--text-secondary);">
                            ${seoData.h1_tags.length === 1 
                                ? '✅ Perfect - one H1 tag per page' 
                                : '⚠️ Best practice: use only one H1 tag per page'}
                        </small>
                    </div>
                </div>
                ${h1List}
                <div class="detail-item">
                    <div class="detail-item-label">
                        <i class="fas fa-lightbulb"></i> SEO Tip
                    </div>
                    <div class="detail-item-content">
                        Each page should have exactly one H1 tag that describes the main topic. It helps both users and search engines understand what your page is about. Make sure your H1 includes relevant keywords.
                    </div>
                </div>
            </div>
        `;
    } else {
        content = `
            <div class="empty-state">
                <i class="fas fa-times-circle"></i>
                <h3 style="color: var(--danger);">No H1 Tags Found</h3>
                <p>This page is missing H1 tags. Every page should have at least one H1 tag for proper SEO.</p>
                <p style="margin-top: 1.5rem; font-size: 0.9rem;">
                    <strong>Recommendation:</strong> Add an H1 tag to your HTML:
                </p>
                <div style="background: var(--code-bg); padding: 1rem; border: 1px solid var(--code-border); border-radius: 0.5rem; margin-top: 1rem; text-align: left;">
                    <code style="color: var(--primary);">&lt;h1&gt;Your Page Title Here&lt;/h1&gt;</code>
                </div>
            </div>
        `;
    }

    modalBody.innerHTML = content;
    modal.style.display = 'flex';
}

// Close modal when clicking outside of it
document.addEventListener('click', function(event) {
    const modal = document.getElementById('detailModal');
    if (modal && event.target === modal) {
        closeDetailModal();
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeDetailModal();
    }
});

/* ==========================================================================
   Accordion Collapsible Detail Panel Functions
   ========================================================================== */

function toggleCardDetails(panelId, btn) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    
    const header = btn.closest ? (btn.closest('.module-tile-header') || btn) : btn;
    const toggleBtn = header.querySelector ? (header.querySelector('.module-toggle-btn') || header) : header;
    
    const isOpen = panel.classList.contains('open');
    
    if (isOpen) {
        panel.classList.remove('open');
        panel.style.maxHeight = "0px";
        if (toggleBtn) {
            toggleBtn.classList.remove('active');
            const icon = toggleBtn.querySelector('i');
            if (icon) icon.className = 'fas fa-plus';
        }
    } else {
        panel.classList.add('open');
        panel.style.maxHeight = (panel.scrollHeight + 40) + "px";
        if (toggleBtn) {
            toggleBtn.classList.add('active');
            const icon = toggleBtn.querySelector('i');
            if (icon) icon.className = 'fas fa-minus';
        }
    }
}

function populateSslDetails(sslData) {
    if (!sslData) return;
    document.getElementById('sslProtocolVersion').textContent = sslData.protocol_version || '-';
    document.getElementById('sslCipher').textContent = sslData.cipher_suite || '-';
    document.getElementById('sslIssuer').textContent = sslData.issuer || '-';
    document.getElementById('sslSubjectCN').textContent = sslData.subject_common_name || '-';
    document.getElementById('sslSanDomains').textContent = (sslData.san_domains || []).join(', ') || '-';
    document.getElementById('sslSelfSigned').textContent = sslData.is_self_signed ? 'Yes (Warning)' : 'No (Secure)';
    document.getElementById('sslSerial').textContent = sslData.serial_number || '-';
}

function populateSeoDetails(seoData) {
    if (!seoData) return;
    document.getElementById('seoCanonical').textContent = seoData.canonical_url || 'None';
    document.getElementById('seoRobots').textContent = seoData.robots_meta || 'None';
    document.getElementById('seoViewport').innerHTML = seoData.has_viewport 
        ? '<span style="color: var(--success);"><i class="fas fa-check-circle"></i> Enabled</span>' 
        : '<span style="color: var(--danger);"><i class="fas fa-times-circle"></i> Missing</span>';
    document.getElementById('seoOgTitle').textContent = seoData.og_title || 'None';
    document.getElementById('seoOgDescription').textContent = seoData.og_description || 'None';
    document.getElementById('seoWordCount').textContent = seoData.word_count || '0';
    document.getElementById('seoInternalLinks').textContent = seoData.internal_links || '0';
    document.getElementById('seoExternalLinks').textContent = seoData.external_links || '0';
}

function populatePerformanceDetails(perfData) {
    if (!perfData || perfData.success === false) {
        document.getElementById('perfTbt').textContent = '--';
        document.getElementById('perfCls').textContent = '--';
        const oppsContainer = document.getElementById('perfOpportunities');
        if (oppsContainer) {
            oppsContainer.innerHTML = '<div style="opacity: 0.6; padding: 4px 0;">Performance scan details unavailable.</div>';
        }
        return;
    }
    document.getElementById('perfTbt').textContent = perfData.total_blocking_time || '0 ms';
    document.getElementById('perfCls').textContent = perfData.cumulative_layout_shift || '0';
    
    const oppsContainer = document.getElementById('perfOpportunities');
    if (!oppsContainer) return;
    oppsContainer.innerHTML = '';
    
    const opps = perfData.opportunities || [];
    if (opps.length > 0) {
        opps.forEach(o => {
            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.justifyContent = 'space-between';
            row.style.padding = '4px 0';
            row.style.borderBottom = '1px solid var(--border-color)';
            row.innerHTML = `
                <span style="opacity: 0.8;"><i class="fas fa-exclamation-circle" style="color: var(--warning); margin-right: 4px;"></i> ${o.title}</span>
                <span style="color: var(--warning); font-weight: 500;">${o.potential_savings}</span>
            `;
            oppsContainer.appendChild(row);
        });
    } else {
        oppsContainer.innerHTML = '<div style="opacity: 0.6; padding: 4px 0;">No significant opportunities identified (score is high).</div>';
    }
}

function populateDnsDetails(dnsData) {
    if (!dnsData) return;
    document.getElementById('dnsSpfPresent').innerHTML = dnsData.has_spf 
        ? '<span style="color: var(--success);"><i class="fas fa-check-circle"></i> Present</span>' 
        : '<span style="color: var(--danger);"><i class="fas fa-times-circle"></i> Missing</span>';
    document.getElementById('dnsSpfRecord').textContent = dnsData.spf_record || 'None';
    
    document.getElementById('dnsDmarcPresent').innerHTML = dnsData.has_dmarc 
        ? '<span style="color: var(--success);"><i class="fas fa-check-circle"></i> Present</span>' 
        : '<span style="color: var(--danger);"><i class="fas fa-times-circle"></i> Missing</span>';
    document.getElementById('dnsDmarcRecord').textContent = dnsData.dmarc_record || 'None';
}

function populateTechnologyDetails(techData) {
    if (!techData) return;
    const additional = techData.additional_detection || {};
    document.getElementById('techServer').textContent = additional.server || 'Unknown';
    document.getElementById('techPoweredBy').textContent = additional.powered_by || 'Unknown';
    document.getElementById('techGenerator').textContent = additional.generator || 'None';
    document.getElementById('techCookies').textContent = (additional.cookies_detected || []).join(', ') || 'None';
}

function populatePortsDetails(portsData) {
    if (!portsData) return;
    const riskDetails = document.getElementById('portsRiskDetails');
    if (!riskDetails) return;
    riskDetails.innerHTML = '';
    
    const openPorts = portsData.open_ports || [];
    const riskNotes = portsData.risk_notes || {};
    let hasWarnings = false;
    
    openPorts.forEach(p => {
        const portNum = typeof p === 'object' ? p.port : p;
        const serviceName = typeof p === 'object' ? p.service : 'Service';
        const severity = typeof p === 'object' ? (p.severity || 'LOW').toUpperCase() : 'LOW';
        const note = (typeof p === 'object' && p.note) ? p.note : (riskNotes[portNum] || riskNotes[String(portNum)]);
        
        if (note || severity !== 'INFO') {
            hasWarnings = true;
            let badgeColor = 'var(--primary)';
            if (severity === 'CRITICAL' || severity === 'HIGH') badgeColor = 'var(--danger)';
            else if (severity === 'MEDIUM') badgeColor = 'var(--warning)';
            else if (severity === 'LOW') badgeColor = 'var(--text-secondary)';

            const item = document.createElement('div');
            item.style.padding = '8px 10px';
            item.style.marginBottom = '6px';
            item.style.borderRadius = '6px';
            item.style.background = 'rgba(0,0,0,0.25)';
            item.style.borderLeft = `3px solid ${badgeColor}`;
            item.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <strong style="color: var(--text-primary); font-size: 0.85rem;">Port ${portNum} (${serviceName})</strong>
                    <span style="font-size: 0.7rem; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: var(--surface-elevated); color: ${badgeColor}; border: 1px solid ${badgeColor};">${severity}</span>
                </div>
                <div style="color: var(--text-secondary); font-size: 0.8rem; line-height: 1.4;">${note || 'Port is publicly accessible.'}</div>
            `;
            riskDetails.appendChild(item);
        }
    });
    
    if (!hasWarnings && openPorts.length > 0) {
        riskDetails.innerHTML = '<div style="opacity: 0.8; padding: 6px 0; color: var(--success);"><i class="fas fa-check-circle"></i> Open ports detected, but no high-risk vulnerabilities identified.</div>';
    } else if (openPorts.length === 0) {
        riskDetails.innerHTML = '<div style="opacity: 0.8; padding: 6px 0; color: var(--success);"><i class="fas fa-check-circle"></i> No open ports detected.</div>';
    }
}

function populateHeadersDetails(headersData) {
    if (!headersData) return;
    
    const missingHeaders = headersData.missing_headers || [];
    const descriptions = headersData.header_descriptions || {};
    
    document.getElementById('headersMissingCount').textContent = missingHeaders.length;
    
    const detailsContainer = document.getElementById('headersMissingDetails');
    if (!detailsContainer) return;
    detailsContainer.innerHTML = '';
    
    if (missingHeaders.length > 0) {
        missingHeaders.forEach(header => {
            const desc = descriptions[header] || 'Missing required security header.';
            const item = document.createElement('div');
            item.style.padding = '6px 0';
            item.style.borderBottom = '1px solid var(--border-color)';
            item.innerHTML = `
                <strong style="color: var(--warning);">${header}:</strong> ${desc}
            `;
            detailsContainer.appendChild(item);
        });
    } else {
        detailsContainer.innerHTML = '<div style="opacity: 0.6; padding: 4px 0; color: var(--success);"><i class="fas fa-check-circle"></i> All key security headers are correctly implemented!</div>';
    }
}

function populateCorsDetails(corsData) {
    const riskBadgeContainer = document.getElementById('corsRiskBadge');
    const dashRiskBadgeContainer = document.getElementById('dashboardCorsRiskBadge');
    const findingsContainer = document.getElementById('corsFindingsList');
    const dashFindingsContainer = document.getElementById('dashCorsFindingsList');

    if (!corsData || corsData.success === false) {
        const errorMsg = corsData?.error || 'CORS check unavailable';
        const fallbackHtml = `<div style="color: var(--text-secondary); opacity: 0.8; padding: 6px 0;"><i class="fas fa-exclamation-triangle" style="color: var(--warning); margin-right: 6px;"></i> CORS check unavailable: ${errorMsg}</div>`;
        if (findingsContainer) findingsContainer.innerHTML = fallbackHtml;
        if (dashFindingsContainer) dashFindingsContainer.innerHTML = fallbackHtml;
        if (riskBadgeContainer) riskBadgeContainer.innerHTML = `<span class="badge-pill badge-medium"><span class="status-dot"></span>N/A</span>`;
        if (dashRiskBadgeContainer) dashRiskBadgeContainer.innerHTML = `<span class="badge-pill badge-medium"><span class="status-dot"></span>N/A</span>`;
        return;
    }

    const riskLevel = (corsData.risk_level || 'LOW').toUpperCase();
    let badgeKey = 'low';
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
        badgeKey = 'high';
    } else if (riskLevel === 'MEDIUM') {
        badgeKey = 'medium';
    }

    const badgeHtml = `<span class="badge-pill badge-${badgeKey}"><span class="status-dot"></span>${riskLevel}</span>`;

    if (riskBadgeContainer) riskBadgeContainer.innerHTML = badgeHtml;
    if (dashRiskBadgeContainer) dashRiskBadgeContainer.innerHTML = badgeHtml;

    const findings = corsData.findings || [];
    let contentHtml = '';

    // Human-friendly summary block
    const summaryText = corsData.summary || '';
    if (summaryText) {
        contentHtml += `<div style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 12px; padding: 8px 10px; border-radius: 6px; background: var(--surface-elevated); border: 1px solid var(--border-color);"><i class="fas fa-info-circle" style="color: var(--primary); margin-right: 6px;"></i>${summaryText}</div>`;
    }

    if (findings.length > 0) {
        contentHtml += findings.map(item => {
            const sev = (item.severity || 'INFO').toUpperCase();
            let itemColor = 'var(--primary)';
            if (sev === 'CRITICAL' || sev === 'HIGH') itemColor = 'var(--danger)';
            else if (sev === 'MEDIUM') itemColor = 'var(--warning)';
            else if (sev === 'INFO' || sev === 'LOW') itemColor = 'var(--success)';

            const confidence = item.confidence ? `<span style="font-size: 0.7rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background: var(--surface-elevated); color: var(--text-secondary);"><i class="fas fa-shield-alt" style="font-size: 0.65rem; margin-right: 3px;"></i>${item.confidence}</span>` : '';

            // Map new exploitability enum values to colors
            let exploitabilityColor = 'var(--text-secondary)';
            let exploitabilityLabel = item.exploitability || '';
            if (exploitabilityLabel === 'CONFIRMED_POLICY_WEAKNESS') { exploitabilityColor = 'var(--danger)'; exploitabilityLabel = 'Confirmed'; }
            else if (exploitabilityLabel === 'LIKELY') { exploitabilityColor = '#ff6b35'; exploitabilityLabel = 'Likely'; }
            else if (exploitabilityLabel === 'POTENTIAL') { exploitabilityColor = 'var(--warning)'; exploitabilityLabel = 'Potential'; }
            else if (exploitabilityLabel === 'NOT_CONFIRMED') { exploitabilityColor = 'var(--success)'; exploitabilityLabel = 'Not Confirmed'; }
            // Backward compat for old values
            else if (exploitabilityLabel === 'Confirmed') exploitabilityColor = 'var(--danger)';
            else if (exploitabilityLabel === 'Potential') exploitabilityColor = 'var(--warning)';
            else if (exploitabilityLabel === 'None') exploitabilityColor = 'var(--success)';

            const exploitabilityBadge = exploitabilityLabel ? `<span style="font-size: 0.7rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background: var(--surface-elevated); color: ${exploitabilityColor}; border: 1px solid ${exploitabilityColor};"><i class="fas fa-bug" style="font-size: 0.65rem; margin-right: 3px;"></i>${exploitabilityLabel}</span>` : '';

            // Use title if available, fall back to issue
            const displayTitle = item.title || item.issue || 'Finding';

            const endpointHtml = item.endpoint ? `<div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 6px; word-break: break-all;"><strong style="color: var(--text-primary);"><i class="fas fa-link" style="font-size: 0.7rem; margin-right: 4px;"></i>Endpoint:</strong> <code style="background: var(--surface-elevated); padding: 2px 5px; border-radius: 4px; color: var(--text-primary);">${item.endpoint}</code></div>` : '';

            let evidenceHtml = '';
            if (item.evidence && Object.keys(item.evidence).length > 0) {
                const evPairs = Object.entries(item.evidence).map(([k, v]) => `<span style="display: inline-block; background: var(--surface-elevated); padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; margin-right: 6px; margin-top: 4px; border: 1px solid var(--border-subtle);"><strong style="color: var(--text-secondary);">${k}:</strong> <span style="color: var(--text-primary);">${v}</span></span>`).join('');
                evidenceHtml = `<div style="font-size: 0.78rem; margin-top: 6px;"><strong style="color: var(--text-primary);"><i class="fas fa-search" style="font-size: 0.7rem; margin-right: 4px;"></i>Evidence:</strong> <div style="display: flex; flex-wrap: wrap; gap: 2px;">${evPairs}</div></div>`;
            }

            // Impact section (new field)
            const impactHtml = item.impact ? `<div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 6px;"><strong style="color: var(--text-primary);"><i class="fas fa-exclamation-circle" style="font-size: 0.7rem; margin-right: 4px; color: var(--warning);"></i>Why it matters:</strong> ${item.impact}</div>` : '';

            // Per-finding remediation (new field)
            const fixHtml = item.remediation ? `<div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 6px;"><strong style="color: var(--text-primary);"><i class="fas fa-wrench" style="font-size: 0.7rem; margin-right: 4px; color: var(--primary);"></i>How to fix:</strong> ${item.remediation}</div>` : '';

            // Test type badge (new field)
            const testTypeBadge = item.test_type ? `<span style="font-size: 0.65rem; font-weight: 500; padding: 1px 5px; border-radius: 3px; background: var(--surface-elevated); color: var(--text-secondary); margin-left: 4px;">${item.test_type}</span>` : '';

            return `
                <div class="cors-finding-item" style="padding: 12px; border-radius: 8px; background: rgba(0, 0, 0, 0.25); margin-bottom: 10px; border-left: 3px solid ${itemColor}; border-top: 1px solid rgba(255,255,255,0.03); border-right: 1px solid rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.03);">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; flex-wrap: wrap; margin-bottom: 6px;">
                        <strong style="color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 200px;">${displayTitle}${testTypeBadge}</strong>
                        <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                            ${confidence}
                            ${exploitabilityBadge}
                            <span style="font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: var(--surface-elevated); color: ${itemColor}; border: 1px solid ${itemColor};">${sev}</span>
                        </div>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.82rem; margin: 0 0 4px 0; line-height: 1.4;">${item.issue || item.detail || ''}</p>
                    ${endpointHtml}
                    ${evidenceHtml}
                    ${impactHtml}
                    ${fixHtml}
                </div>
            `;
        }).join('');
    } else {
        contentHtml += `<div style="color: var(--success); padding: 4px 0;"><i class="fas fa-check-circle"></i> No CORS misconfiguration detected.</div>`;
    }

    if (corsData.remediation && corsData.remediation.length > 0) {
        const remediationItems = corsData.remediation.map(tip => `<li style="margin-bottom: 4px;">${tip}</li>`).join('');
        contentHtml += `
            <div style="margin-top: 14px; padding: 10px 12px; border-radius: 8px; background: var(--surface-elevated); border: 1px solid var(--border-color);">
                <strong style="color: var(--text-primary); font-size: 0.85rem; display: block; margin-bottom: 6px;"><i class="fas fa-lightbulb" style="color: var(--warning); margin-right: 6px;"></i> Remediation Guidance:</strong>
                <ul style="color: var(--text-secondary); font-size: 0.8rem; margin: 0; padding-left: 18px; line-height: 1.4;">
                    ${remediationItems}
                </ul>
            </div>
        `;
    }

    // Show tests performed and endpoints tested if available
    const testsPerformed = corsData.tests_performed || [];
    const endpointsTested = corsData.endpoints_tested || [];
    if (testsPerformed.length > 0 || endpointsTested.length > 0) {
        let metaHtml = '<div style="margin-top: 12px; padding: 8px 10px; border-radius: 6px; background: var(--surface-elevated); border: 1px solid var(--border-subtle); font-size: 0.75rem; color: var(--text-secondary);">';
        if (testsPerformed.length > 0) {
            metaHtml += `<div style="margin-bottom: 4px;"><strong style="color: var(--text-primary);"><i class="fas fa-vial" style="font-size: 0.65rem; margin-right: 4px;"></i>Tests performed:</strong> ${testsPerformed.join(', ')}</div>`;
        }
        if (endpointsTested.length > 0) {
            metaHtml += `<div><strong style="color: var(--text-primary);"><i class="fas fa-sitemap" style="font-size: 0.65rem; margin-right: 4px;"></i>Endpoints tested:</strong> ${endpointsTested.length} endpoint(s)</div>`;
        }
        metaHtml += '</div>';
        contentHtml += metaHtml;
    }

    // Show CORS header descriptions reference if available
    const headerDescs = corsData.cors_header_descriptions || {};
    const headerDescEntries = Object.entries(headerDescs);
    if (headerDescEntries.length > 0) {
        const descItems = headerDescEntries.map(([header, desc]) => `<div style="margin-bottom: 4px;"><code style="color: var(--primary); font-family: monospace; font-size: 0.78rem;">${header}:</code> <span style="color: var(--text-secondary); font-size: 0.78rem;">${desc}</span></div>`).join('');
        contentHtml += `
            <div class="cors-headers-reference-section" style="margin-top: 12px; padding: 10px 12px; border-radius: 8px; background: var(--surface-elevated); border: 1px solid var(--border-color);">
                <strong style="color: var(--text-primary); font-size: 0.85rem; display: block; margin-bottom: 6px;"><i class="fas fa-book" style="color: var(--primary); margin-right: 6px;"></i> CORS Header Reference:</strong>
                <div>${descItems}</div>
            </div>
        `;
    }

    if (findingsContainer) findingsContainer.innerHTML = contentHtml;
    if (dashFindingsContainer) dashFindingsContainer.innerHTML = contentHtml;
}

const renderCorsResult = populateCorsDetails;

function populateExposedPathsDetails(exposedPathsData) {
    const riskBadgeContainer = document.getElementById('exposedPathsRiskBadge');
    const dashRiskBadgeContainer = document.getElementById('dashboardExposedPathsRiskBadge');
    const findingsContainer = document.getElementById('exposedPathsFindingsList');
    const dashFindingsContainer = document.getElementById('dashExposedPathsFindingsList');

    if (!exposedPathsData || exposedPathsData.success === false) {
        const errorMsg = exposedPathsData?.error || 'Exposed paths check unavailable';
        const fallbackHtml = `<div style="color: var(--text-secondary); opacity: 0.8; padding: 6px 0;"><i class="fas fa-exclamation-triangle" style="color: var(--warning); margin-right: 6px;"></i> Exposed paths check unavailable: ${errorMsg}</div>`;
        if (findingsContainer) findingsContainer.innerHTML = fallbackHtml;
        if (dashFindingsContainer) dashFindingsContainer.innerHTML = fallbackHtml;
        if (riskBadgeContainer) riskBadgeContainer.innerHTML = `<span class="badge-pill badge-medium"><span class="status-dot"></span>N/A</span>`;
        if (dashRiskBadgeContainer) dashRiskBadgeContainer.innerHTML = `<span class="badge-pill badge-medium"><span class="status-dot"></span>N/A</span>`;
        return;
    }

    const riskLevel = (exposedPathsData.risk_level || 'LOW').toUpperCase();
    let badgeKey = 'low';
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
        badgeKey = 'high';
    } else if (riskLevel === 'MEDIUM') {
        badgeKey = 'medium';
    }

    const badgeHtml = `<span class="badge-pill badge-${badgeKey}"><span class="status-dot"></span>${riskLevel}</span>`;

    if (riskBadgeContainer) riskBadgeContainer.innerHTML = badgeHtml;
    if (dashRiskBadgeContainer) dashRiskBadgeContainer.innerHTML = badgeHtml;

    // Populate card-face stats (visible without expanding)
    const totalChecked = exposedPathsData.total_checked || 0;
    const exposedCount = exposedPathsData.exposed_count || 0;
    const protectedCount = (exposedPathsData.protected_paths || []).length;

    // index.html elements
    const elChecked = document.getElementById('exposedPathsChecked');
    const elExposed = document.getElementById('exposedPathsExposedCount');
    const elProtected = document.getElementById('exposedPathsProtectedCount');
    if (elChecked) elChecked.textContent = totalChecked;
    if (elExposed) elExposed.textContent = exposedCount;
    if (elProtected) elProtected.textContent = protectedCount;

    // dashboard.html elements
    const dashElChecked = document.getElementById('dashExposedPathsChecked');
    const dashElExposed = document.getElementById('dashExposedPathsExposedCount');
    const dashElProtected = document.getElementById('dashExposedPathsProtectedCount');
    if (dashElChecked) dashElChecked.textContent = totalChecked;
    if (dashElExposed) dashElExposed.textContent = exposedCount;
    if (dashElProtected) dashElProtected.textContent = protectedCount;

    let contentHtml = '';

    // Baseline note info banner if SPA / always 200 router detected
    if (exposedPathsData.baseline_note) {
        contentHtml += `<div class="baseline-note-banner" style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 12px; padding: 8px 10px; border-radius: 6px; background: rgba(0,212,255,0.06); border: 1px solid rgba(0,212,255,0.2);"><i class="fas fa-info-circle" style="color: var(--primary); margin-right: 6px;"></i>${exposedPathsData.baseline_note}</div>`;
    }

    // Summary line: e.g. "2 of 22 sensitive paths exposed"
    contentHtml += `<div style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600; margin-bottom: 10px;"><i class="fas fa-search" style="color: var(--primary); margin-right: 6px;"></i>${exposedCount} of ${totalChecked} sensitive paths exposed</div>`;

    // List each entry in exposed_paths showing path, severity badge, and description
    const exposedPaths = exposedPathsData.exposed_paths || [];
    if (exposedPaths.length > 0) {
        contentHtml += exposedPaths.map(item => {
            const sev = (item.severity || 'LOW').toUpperCase();
            let itemColor = 'var(--primary)';
            if (sev === 'CRITICAL' || sev === 'HIGH') itemColor = 'var(--danger)';
            else if (sev === 'MEDIUM') itemColor = 'var(--warning)';
            else if (sev === 'LOW' || sev === 'INFO') itemColor = 'var(--success)';

            const conf = (item.confidence || '').toUpperCase();
            let confColor = 'var(--text-secondary)';
            if (conf === 'HIGH') confColor = 'var(--danger)';
            else if (conf === 'MEDIUM') confColor = 'var(--warning)';
            const confBadge = conf ? `<span style="font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: var(--surface-elevated); color: ${confColor}; border: 1px solid ${confColor}; margin-left: 6px;">${conf} CONFIDENCE</span>` : '';

            const pathUrl = item.url ? `<a href="${item.url}" target="_blank" rel="noopener noreferrer" style="color: var(--primary); font-family: monospace; font-size: 0.85rem; text-decoration: underline;">${item.path}</a>` : `<code style="font-family: monospace; font-size: 0.85rem;">${item.path}</code>`;
            const categoryLabel = item.category ? `<span style="font-size: 0.72rem; opacity: 0.7; margin-left: 6px;">[${item.category}]</span>` : '';
            const lengthInfo = item.content_length !== null && item.content_length !== undefined ? `<span style="font-size: 0.72rem; opacity: 0.7; margin-left: 8px;">(${item.content_length} bytes${item.content_truncated ? ', response truncated for safety' : ''})</span>` : '';
            const dirListingWarning = item.directory_listing_detected ? `<p style="color: var(--warning); font-size: 0.82rem; margin: 4px 0 0 0; line-height: 1.4;"><i class="fas fa-exclamation-triangle" style="margin-right: 4px;"></i> Directory listing is publicly viewable at this path</p>` : '';

            return `
                <div class="exposed-path-item" style="padding: 10px 12px; border-radius: 8px; background: rgba(0, 0, 0, 0.25); margin-bottom: 8px; border-left: 3px solid ${itemColor}; border-top: 1px solid rgba(255,255,255,0.03); border-right: 1px solid rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.03);">
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px;">
                        <span style="font-weight: 600;">${pathUrl}${categoryLabel} ${lengthInfo}</span>
                        <div>
                            <span style="font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: var(--surface-elevated); color: ${itemColor}; border: 1px solid ${itemColor};">${sev}</span>${confBadge}
                        </div>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.82rem; margin: 0; line-height: 1.4;">${item.description || ''}</p>${dirListingWarning}
                </div>
            `;
        }).join('');
    } else {
        contentHtml += `<div style="color: var(--success); padding: 4px 0;"><i class="fas fa-check-circle"></i> No common sensitive paths were found exposed on this server.</div>`;
    }

    // Protected paths as a collapsed/secondary "✓ Protected" list
    const protectedPaths = exposedPathsData.protected_paths || [];
    if (protectedPaths.length > 0) {
        const protectedItemsHtml = protectedPaths.map(p => `<span style="display: inline-block; background: rgba(0,255,136,0.08); color: var(--success); border: 1px solid rgba(0,255,136,0.2); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; margin-right: 6px; margin-top: 4px; font-family: monospace;">✓ ${p.path} (${p.status_code})</span>`).join('');
        contentHtml += `
            <div class="protected-paths-section" style="margin-top: 14px; padding: 10px 12px; border-radius: 8px; background: var(--surface-elevated); border: 1px solid var(--border-color);">
                <strong style="color: var(--text-primary); font-size: 0.85rem; display: block; margin-bottom: 6px;"><i class="fas fa-shield-alt" style="color: var(--success); margin-right: 6px;"></i> Protected Paths (${protectedPaths.length}):</strong>
                <div style="display: flex; flex-wrap: wrap; gap: 2px;">${protectedItemsHtml}</div>
            </div>
        `;
    }

    if (findingsContainer) findingsContainer.innerHTML = contentHtml;
    if (dashFindingsContainer) dashFindingsContainer.innerHTML = contentHtml;
}

const renderExposedPathsResult = populateExposedPathsDetails;


// ==========================================
// AI SECURITY CHATBOX INTERACTION SCRIPT
// ==========================================

function getActiveScanData() {
    // Check if the global 'data' variable exists (index.html context)
    if (typeof data !== 'undefined' && data) {
        return data;
    }
    
    // Check if the global 'currentReport' variable exists (dashboard.html simulated scan context)
    if (typeof currentReport !== 'undefined' && currentReport) {
        return {
            website: document.getElementById('resultWebsite')?.textContent?.replace('Scan Results for ', '') || 'Scanned Website',
            summary: {
                security_score: currentReport.score,
                risk_level: currentReport.status,
                recommendations: []
            },
            scans: {
                ssl: {
                    ssl_enabled: currentReport.ssl?.status?.toLowerCase() === 'valid',
                    protocol_version: currentReport.ssl?.protocol
                },
                headers: {
                    missing_headers: currentReport.vulnerabilities?.high > 0 ? ['Content-Security-Policy', 'Strict-Transport-Security'] : []
                },
                ports: {
                    open_ports: currentReport.vulnerabilities?.critical > 0 ? [{port: 3306, service: 'mysql'}] : []
                },
                performance: {
                    performance_score: currentReport.score >= 80 ? 90 : 50
                }
            }
        };
    }
    return null;
}

function copyCodeText(id) {
    const codeElem = document.getElementById(id);
    if (!codeElem) return;
    
    const text = codeElem.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = codeElem.closest('.code-block-container').querySelector('.code-block-copy-btn');
        if (btn) {
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.classList.remove('copied');
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

function compileTable(rows) {
    if (rows.length === 0) return '';
    let html = '<div class="table-container"><table>';
    
    // Header
    html += '<thead><tr>';
    rows[0].forEach(cell => {
        html += `<th>${cell}</th>`;
    });
    html += '</tr></thead><tbody>';
    
    // Body
    for (let i = 1; i < rows.length; i++) {
        html += '<tr>';
        rows[i].forEach(cell => {
            html += `<td>${cell}</td>`;
        });
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
}

function formatMarkdown(text) {
    if (!text) return "";
    
    // Extract code blocks first to protect code content from formatting
    const codeBlocks = [];
    let escaped = text.replace(/```(\w*)\n([\s\S]+?)```/g, function(match, lang, code) {
        const id = 'code-' + Math.random().toString(36).substr(2, 9);
        const index = codeBlocks.length;
        const cleanCode = code.trim().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const languageLabel = lang ? lang.toUpperCase() : 'CODE';
        codeBlocks.push(`
            <div class="code-block-container">
                <div class="code-block-header">
                    <span class="code-block-lang">${languageLabel}</span>
                    <button class="code-block-copy-btn" onclick="copyCodeText('${id}')">
                        <i class="far fa-copy"></i> Copy
                    </button>
                </div>
                <pre><code class="language-${lang || 'none'}" id="${id}">${cleanCode}</code></pre>
            </div>
        `);
        return `__CODE_BLOCK_${index}__`;
    });
    
    escaped = escaped.replace(/```([\s\S]+?)```/g, function(match, code) {
        const id = 'code-' + Math.random().toString(36).substr(2, 9);
        const index = codeBlocks.length;
        const cleanCode = code.trim().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        codeBlocks.push(`
            <div class="code-block-container">
                <div class="code-block-header">
                    <span class="code-block-lang">CODE</span>
                    <button class="code-block-copy-btn" onclick="copyCodeText('${id}')">
                        <i class="far fa-copy"></i> Copy
                    </button>
                </div>
                <pre><code class="language-none" id="${id}">${cleanCode}</code></pre>
            </div>
        `);
        return `__CODE_BLOCK_${index}__`;
    });

    // Escape raw HTML outside code blocks
    escaped = escaped
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

    // Inline code
    escaped = escaped.replace(/`([^`\n]+?)`/g, '<code>$1</code>');
    
    // Bold
    escaped = escaped.replace(/\*\*([^*]+?)\*\*/g, '<strong>$1</strong>');
    
    // Headings
    escaped = escaped.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    escaped = escaped.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
    escaped = escaped.replace(/^## (.*$)/gim, '<h2>$1</h2>');

    // Split lines for list and table processing
    let lines = escaped.split('\n');
    let inList = false;
    let inOrderList = false;
    let inTable = false;
    let tableRows = [];
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        // Handle Tables
        if (line.startsWith('|') && line.endsWith('|')) {
            if (inList) { lines[i-1] += '</ul>'; inList = false; }
            if (inOrderList) { lines[i-1] += '</ol>'; inOrderList = false; }
            
            if (line.includes('---') || line.includes('-:-')) {
                lines[i] = '';
                continue;
            }
            
            let cells = line.split('|').map(c => c.trim()).filter((c, idx, arr) => idx > 0 && idx < arr.length - 1);
            tableRows.push(cells);
            lines[i] = '';
            inTable = true;
            continue;
        } else if (inTable) {
            lines[i-1] = compileTable(tableRows);
            tableRows = [];
            inTable = false;
        }
        
        // Handle Lists
        if (line.startsWith('- ') || line.startsWith('* ')) {
            let content = line.substring(2);
            if (!inList) {
                lines[i] = '<ul><li>' + content + '</li>';
                inList = true;
            } else {
                lines[i] = '<li>' + content + '</li>';
            }
        } else if (/^\d+\.\s/.test(line)) {
            let content = line.replace(/^\d+\.\s/, '');
            if (!inOrderList) {
                lines[i] = '<ol><li>' + content + '</li>';
                inOrderList = true;
            } else {
                lines[i] = '<li>' + content + '</li>';
            }
        } else {
            if (inList) {
                lines[i-1] = lines[i-1] + '</ul>';
                inList = false;
            }
            if (inOrderList) {
                lines[i-1] = lines[i-1] + '</ol>';
                inOrderList = false;
            }
        }
    }
    
    if (inTable) {
        lines[lines.length - 1] = compileTable(tableRows);
    }
    if (inList) lines[lines.length - 1] = lines[lines.length - 1] + '</ul>';
    if (inOrderList) lines[lines.length - 1] = lines[lines.length - 1] + '</ol>';
    
    escaped = lines.filter(l => l !== '').join('\n');
    
    // Paragraph breaks
    escaped = escaped.replace(/\n\n/g, '</p><p>');
    escaped = escaped.replace(/\n/g, '<br>');
    
    escaped = '<p>' + escaped + '</p>';
    escaped = escaped.replace(/<p><(ul|ol|h2|h3|h4|div|table)/g, '<$1');
    escaped = escaped.replace(/<\/(ul|ol|h2|h3|h4|div|table)><\/p>/g, '</$1>');
    escaped = escaped.replace(/<br><(ul|ol|li|h2|h3|h4|div|table)/g, '<$1');
    escaped = escaped.replace(/<\/(ul|ol|li|h2|h3|h4|div|table)><br>/g, '</$1>');
    escaped = escaped.replace(/<p>\s*<\/p>/g, '');
    
    // Re-inject code blocks
    for (let index = 0; index < codeBlocks.length; index++) {
        escaped = escaped.replace(`__CODE_BLOCK_${index}__`, codeBlocks[index]);
    }
    
    return escaped;
}

async function sendChatMessage(isSuggestion = false) {
    const chatInput = document.getElementById('chatInput');
    if (!chatInput) return;
    
    const message = chatInput.value.trim();
    if (!message) return;
    
    chatInput.value = '';
    
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;
    
    // Hide suggestion chips
    const suggestionsDiv = document.getElementById('chatSuggestions');
    if (suggestionsDiv) {
        suggestionsDiv.style.display = 'none';
    }
    
    // 1. Append User Message
    const userMessageDiv = document.createElement('div');
    userMessageDiv.className = 'chat-message user-message animate-message';
    userMessageDiv.innerHTML = `
        <div class="message-avatar"><i class="fas fa-user"></i></div>
        <div class="message-text">${message}</div>
    `;
    chatMessages.appendChild(userMessageDiv);
    chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
    
    // 2. Add Typing Indicator
    const typingMessageDiv = document.createElement('div');
    typingMessageDiv.className = 'chat-message bot-message typing-indicator-container animate-message';
    typingMessageDiv.innerHTML = `
        <div class="message-avatar"><i class="fas fa-robot"></i></div>
        <div class="message-text">
            <div class="typing-indicator">
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
            </div>
        </div>
    `;
    chatMessages.appendChild(typingMessageDiv);
    chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
    
    // 3. Make API Call to FastAPI
    try {
        const scanData = getActiveScanData();
        const savedKey = localStorage.getItem('gemini_api_key') || '';
        const host = typeof auth !== 'undefined' ? auth.backendBase : (typeof window.getBackendBaseUrl === 'function' ? window.getBackendBaseUrl() : 'https://shieldscope-backend-e3hu.onrender.com');
            
        const token = typeof auth !== 'undefined' ? auth.getToken() : (localStorage.getItem('access_token') || localStorage.getItem('token'));
        const headers = {
            'Content-Type': 'application/json'
        };
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${host}/chat`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                message: message,
                scan_results: scanData,
                api_key: savedKey,
                module: selectedModule,
                is_suggestion: isSuggestion
            })
        });
        
        // Remove typing indicator
        const indicator = document.querySelector('.typing-indicator-container');
        if (indicator) indicator.remove();
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        
        const responseData = await response.json();
        
        // Create response source badge
        let badgeHtml = '';
        if (responseData.source === 'rule') {
            badgeHtml = `<span class="response-source-badge rule-badge"><i class="fas fa-wrench"></i> Rule Engine</span>`;
        } else if (responseData.source === 'ai') {
            badgeHtml = `<span class="response-source-badge ai-badge"><i class="fas fa-robot"></i> Hybrid AI${responseData.cached ? ' (Cached)' : ''}</span>`;
        } else if (responseData.source === 'fallback') {
            badgeHtml = `<span class="response-source-badge fallback-badge"><i class="fas fa-life-ring"></i> Offline Helper</span>`;
        }
 
        // 4. Append Bot Response
        const botMessageDiv = document.createElement('div');
        botMessageDiv.className = 'chat-message bot-message animate-message';
        botMessageDiv.innerHTML = `
            <div class="message-avatar"><i class="fas fa-robot"></i></div>
            <div class="message-text">
                ${formatMarkdown(responseData.response)}
                ${badgeHtml}
            </div>
        `;
        chatMessages.appendChild(botMessageDiv);
        chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
        
    } catch (error) {
        console.error('Error fetching chat response:', error);
        
        // Remove typing indicator
        const indicator = document.querySelector('.typing-indicator-container');
        if (indicator) indicator.remove();
        
        const errorMessageDiv = document.createElement('div');
        errorMessageDiv.className = 'chat-message bot-message animate-message';
        errorMessageDiv.innerHTML = `
            <div class="message-avatar"><i class="fas fa-robot"></i></div>
            <div class="message-text" style="color: var(--danger);">
                <i class="fas fa-exclamation-triangle"></i> Sorry, I couldn't reach the backend advisor service. Please make sure the backend server is running and try again.
            </div>
        `;
        chatMessages.appendChild(errorMessageDiv);
        chatMessages.scrollTo({ top: chatMessages.scrollHeight, behavior: 'smooth' });
    }
}
 
function askSuggestedQuestion(qText) {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.value = qText;
        sendChatMessage(true);
    }
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter') {
        sendChatMessage();
    }
}

const MODULE_SUGGESTIONS = {
    general: [
        'Explain My Scan',
        'Improve Website Security',
        'Website Security Tips',
        'Beginner Guide',
        'Fix My Website'
    ],
    ssl: [
        'Explain SSL',
        'Check SSL Status',
        'How to get free SSL',
        'Fix SSL expiration',
        'Is self-signed SSL safe?'
    ],
    headers: [
        'Explain Security Headers',
        'How to fix CSP',
        'What is HSTS?',
        'Configure X-Frame-Options',
        'Add missing headers'
    ],
    ports: [
        'What is a port scan?',
        'Fix open ports',
        'Is port 80/443 safe?',
        'Secure database ports',
        'Vulnerable service mitigation'
    ],
    dns: [
        'What is DNS?',
        'Verify MX & A records',
        'Check SPF & DMARC',
        'How to set up DMARC'
    ],
    seo: [
        'Explain SEO scan',
        'Fix missing meta tags',
        'Why H1 count matters',
        'Optimize image alt text'
    ],
    performance: [
        'Improve website speed',
        'What is FCP & LCP?',
        'Optimize Speed Index',
        'Reduce page load time'
    ],
    technology: [
        'What technology was detected?',
        'Are my backend versions safe?',
        'Explain server cookies safety',
        'Hide server signature'
    ],
    cors: [
        'Explain CORS misconfiguration',
        'What is arbitrary origin reflection?',
        'Why is null origin unsafe?',
        'How to fix Access-Control-Allow-Origin'
    ],
    exposed_paths: [
        'Explain exposed sensitive paths',
        'How to block access to .env file',
        'Why git config exposure is critical',
        'How to secure backup files on web server'
    ]
};

function updateChatSuggestions(module) {
    const suggestionsDiv = document.getElementById('chatSuggestions');
    if (!suggestionsDiv) return;
    
    const suggestions = MODULE_SUGGESTIONS[module] || MODULE_SUGGESTIONS['general'];
    
    suggestionsDiv.innerHTML = suggestions
        .map(q => `<button onclick="askSuggestedQuestion('${q.replace(/'/g, "\\\'")}')">${q}</button>`)
        .join('');
        
    suggestionsDiv.style.display = 'flex';
}

/* Auto-detect the currently visible scan module from the page */
function autoDetectActiveModule() {
    // Priority 1: any expanded detail panel
    const panelMap = {
        sslDetails:     'ssl',
        headersDetails: 'headers',
        corsDetails:    'cors',
        dashCorsDetails:'cors',
        exposedPathsDetails:     'exposed_paths',
        dashExposedPathsDetails: 'exposed_paths',
        portsDetails:   'ports',
        dnsDetails:     'dns',
        seoDetails:     'seo',
        perfDetails:    'performance',
        techDetails:    'technology'
    };
    for (const [id, mod] of Object.entries(panelMap)) {
        const el = document.getElementById(id);
        if (el && el.classList.contains('open')) return mod;
    }

    // Priority 2: which result-card is most centered in viewport
    const cardMap = [
        { selector: '.ssl-card',         module: 'ssl'         },
        { selector: '.headers-card',     module: 'headers'     },
        { selector: '.cors-card',        module: 'cors'        },
        { selector: '.exposed-paths-card', module: 'exposed_paths' },
        { selector: '.port-card',        module: 'ports'       },
        { selector: '.dns-card',         module: 'dns'         },
        { selector: '.seo-card',         module: 'seo'         },
        { selector: '.performance-card', module: 'performance' },
        { selector: '.result-card:not(.ssl-card):not(.headers-card):not(.cors-card):not(.exposed-paths-card):not(.port-card):not(.dns-card):not(.seo-card):not(.performance-card)', module: 'technology' }
    ];
    const vMid = window.innerHeight / 2;
    let bestMod = 'general', bestDist = Infinity;
    for (const { selector, module } of cardMap) {
        document.querySelectorAll(selector).forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.bottom < 0 || rect.top > window.innerHeight) return;
            const mid  = (rect.top + rect.bottom) / 2;
            const dist = Math.abs(mid - vMid);
            if (dist < bestDist) { bestDist = dist; bestMod = module; }
        });
    }
    return bestMod;
}

function handleModuleChange() {
    const module = autoDetectActiveModule();
    updateChatSuggestions(module);
}

function toggleChatbot() {
    const chatbotWidget = document.getElementById('aiChatbotWidget');
    if (!chatbotWidget) return;
    chatbotWidget.classList.toggle('open');
    // When opening, seed suggestions based on visible module
    if (chatbotWidget.classList.contains('open')) {
        handleModuleChange();
    }
}

/* Chatbot Settings Panel Functionality */
function toggleChatSettings() {
    const panel = document.getElementById('chatbotSettingsPanel');
    if (panel) {
        if (panel.style.display === 'none') {
            panel.style.display = 'block';
            const input = document.getElementById('geminiApiKeyInput');
            if (input) {
                input.value = localStorage.getItem('gemini_api_key') || '';
            }
        } else {
            panel.style.display = 'none';
        }
    }
}

function saveGeminiApiKey() {
    const input = document.getElementById('geminiApiKeyInput');
    const status = document.getElementById('settingsKeyStatus');
    if (!input || !status) return;

    const key = input.value.trim();
    if (!key) {
        status.textContent = '⚠️ Please enter a valid API Key.';
        status.style.color = 'var(--danger)';
        return;
    }

    localStorage.setItem('gemini_api_key', key);
    status.textContent = '✅ API Key saved successfully!';
    status.style.color = 'var(--success)';
    
    updateChatbotStatus();
    
    setTimeout(() => {
        toggleChatSettings();
        status.textContent = '';
    }, 1500);
}

function clearGeminiApiKey() {
    const input = document.getElementById('geminiApiKeyInput');
    const status = document.getElementById('settingsKeyStatus');
    if (input) input.value = '';
    
    localStorage.removeItem('gemini_api_key');
    if (status) {
        status.textContent = '🗑️ API Key cleared.';
        status.style.color = 'var(--warning)';
    }
    
    updateChatbotStatus();
    
    setTimeout(() => {
        toggleChatSettings();
        if (status) status.textContent = '';
    }, 1500);
}

function updateChatbotStatus() {
    const statusText = document.getElementById('chatbotStatus');
    if (!statusText) return;
    
    const key = localStorage.getItem('gemini_api_key');
    if (key) {
        statusText.innerHTML = '<span class="status-dot online" style="background-color: var(--success);"></span> Hybrid Mode';
        statusText.style.color = 'var(--success)';
    } else {
        statusText.innerHTML = '<span class="status-dot" style="background-color: #9ca3af;"></span> Rule Mode';
        statusText.style.color = 'var(--text-secondary)';
    }
}

// Wire scroll listener so pills update as the user scrolls through cards
window.addEventListener('scroll', () => {
    const widget = document.getElementById('aiChatbotWidget');
    if (widget && widget.classList.contains('open')) handleModuleChange();
}, { passive: true });

// Wire expand-btn clicks so pills update immediately when a card is opened
document.addEventListener('click', e => {
    if (e.target.closest('.expand-btn') || e.target.closest('.card-expand-toggle')) {
        setTimeout(handleModuleChange, 50);
    }
});

// Initialize scan state on page load
document.addEventListener('DOMContentLoaded', () => {
    setScanState(ScanState.IDLE);
});
setScanState(ScanState.IDLE);

