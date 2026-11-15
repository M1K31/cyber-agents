// AegisSIEM Security Dashboard - Client Application
// All dynamic content is sanitized via escapeHtml() before DOM insertion.

const API_BASE = (typeof window !== 'undefined' && window.location && window.location.origin) ? window.location.origin : 'http://localhost:8088';
const POLL_INTERVAL = 10000;

let pollTimer = null;

// ── Utilities ──

function timeAgo(dateStr) {
    if (!dateStr) return '--';
    const now = Date.now();
    const then = new Date(dateStr).getTime();
    if (isNaN(then)) return dateStr;
    const seconds = Math.floor((now - then) / 1000);
    if (seconds < 60) return seconds + 's ago';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm ago';
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ago';
    const days = Math.floor(hours / 24);
    return days + 'd ago';
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ── Safe DOM Helpers ──
// These helpers build DOM elements programmatically to avoid raw innerHTML.

function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
        Object.keys(attrs).forEach(function(key) {
            if (key === 'className') node.className = attrs[key];
            else if (key === 'textContent') node.textContent = attrs[key];
            else if (key === 'title') node.title = attrs[key];
            else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), attrs[key]);
            else node.setAttribute(key, attrs[key]);
        });
    }
    if (children) {
        if (!Array.isArray(children)) children = [children];
        children.forEach(function(child) {
            if (child === null || child === undefined) return;
            if (typeof child === 'string') node.appendChild(document.createTextNode(child));
            else node.appendChild(child);
        });
    }
    return node;
}

function clearChildren(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
}

function severityBadge(severity) {
    var s = (severity || '').toUpperCase();
    var clsMap = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' };
    var cls = clsMap[s] || '';
    return el('span', { className: 'badge ' + cls, textContent: s || 'UNKNOWN' });
}

function statusClass(status) {
    var s = (status || '').toLowerCase();
    return { open: 'status-open', blocked: 'status-blocked', resolved: 'status-resolved' }[s] || '';
}

var ESCALATION_NAMES = {
    '0': 'Monitoring',
    '1': 'Warning',
    '2': 'Aggressive',
    '2.5': 'Critical',
    '3': 'Maximum'
};

function escalationBadge(level) {
    var lvl = parseFloat(level);
    var name = ESCALATION_NAMES[String(lvl)] || ('Level ' + lvl);
    var cls = 'level-0';
    if (lvl >= 3) cls = 'level-3';
    else if (lvl >= 2.5) cls = 'level-25';
    else if (lvl >= 2) cls = 'level-2';
    else if (lvl >= 1) cls = 'level-1';
    return el('span', { className: 'badge ' + cls, textContent: name + ' (' + lvl + ')' });
}

function emptyRow(colspan, message) {
    return el('tr', null, [el('td', { colspan: String(colspan), className: 'empty-state', textContent: message })]);
}

// ── Toast Notifications ──

function showToast(message, type) {
    type = type || 'success';
    var container = document.getElementById('toast-container');
    var toast = el('div', { className: 'toast ' + type, textContent: message });
    container.appendChild(toast);
    setTimeout(function() {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(function() { toast.remove(); }, 300);
    }, 4000);
}

// ── API Helpers ──

async function apiGet(path) {
    var resp = await fetch(API_BASE + path);
    if (!resp.ok) throw new Error('GET ' + path + ': ' + resp.status);
    return resp.json();
}

function currentTotpPayload(extra) {
    var payload = Object.assign({}, extra || {});
    var input = document.getElementById('totp-code');
    if (input && input.value && input.value.trim()) {
        payload.totp_code = input.value.trim();
    }
    return payload;
}

// A TOTP code is single-use. Clear it once the request that carried it has
// succeeded — but only if the field still holds THAT code: the operator may
// already have typed the next one while the request was in flight.
function clearTotpInput(submittedCode) {
    var input = document.getElementById('totp-code');
    if (input && submittedCode && input.value.trim() === submittedCode) {
        input.value = '';
    }
}

// POST with the TOTP currently in the field (if any) merged into `extra`, and
// clear that code on success.
async function postWithTotp(path, extra) {
    var payload = currentTotpPayload(extra);
    var result = await apiPost(path, payload);
    clearTotpInput(payload.totp_code);
    return result;
}

async function apiPost(path, body) {
    var payload = body !== undefined ? body : currentTotpPayload();
    var resp = await fetch(API_BASE + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (!resp.ok) {
        var detail = '';
        try {
            var errBody = await resp.json();
            detail = errBody.detail || errBody.status || '';
        } catch (_) {}
        throw new Error('POST ' + path + ': ' + resp.status + (detail ? ' (' + detail + ')' : ''));
    }
    return resp.json();
}

// ── Connection Status ──

function setConnected(connected) {
    var dot = document.getElementById('status-indicator');
    var text = document.getElementById('status-text');
    if (connected) {
        dot.className = 'status-dot connected';
        text.textContent = 'Connected';
    } else {
        dot.className = 'status-dot disconnected';
        text.textContent = 'Disconnected';
    }
}

// ── Renderers ──

function renderStatus(data) {
    document.getElementById('stat-open-threats').textContent = data.open_threats != null ? data.open_threats : '--';
    document.getElementById('stat-blocked-ips').textContent = data.blocked_ips != null ? data.blocked_ips : '--';
    document.getElementById('stat-active-profiles').textContent = data.active_profiles != null ? data.active_profiles : '--';
    document.getElementById('stat-honeypot-events').textContent = data.honeypot_events_24h != null ? data.honeypot_events_24h : '--';
    document.getElementById('stat-pending-approvals').textContent = data.pending_approvals != null ? data.pending_approvals : '--';
}

function renderThreats(threats) {
    var tbody = document.querySelector('#threats-table tbody');
    clearChildren(tbody);
    if (!threats || threats.length === 0) {
        tbody.appendChild(emptyRow(8, 'No threats detected'));
        return;
    }
    threats.forEach(function(t) {
        var actionCells = [];
        if (t.status === 'open') {
            actionCells.push(el('button', { className: 'btn btn-block', textContent: 'Block', onClick: function() { actionBlock(t.id); } }));
            actionCells.push(el('button', { className: 'btn btn-resolve', textContent: 'Resolve', onClick: function() { actionResolve(t.id); } }));
        }
        var row = el('tr', null, [
            el('td', { textContent: String(t.source_ip || '') }),
            el('td', { textContent: String(t.threat_type || '') }),
            el('td', null, [severityBadge(t.severity)]),
            el('td', { textContent: String(t.count != null ? t.count : '') }),
            el('td', { textContent: timeAgo(t.first_seen), title: String(t.first_seen || '') }),
            el('td', { textContent: timeAgo(t.last_seen), title: String(t.last_seen || '') }),
            el('td', { className: statusClass(t.status), textContent: (t.status || '').toUpperCase() }),
            el('td', null, actionCells)
        ]);
        tbody.appendChild(row);
    });
}

function renderBlocked(blocked) {
    var tbody = document.querySelector('#blocked-table tbody');
    clearChildren(tbody);
    if (!blocked || blocked.length === 0) {
        tbody.appendChild(emptyRow(5, 'No blocked IPs'));
        return;
    }
    blocked.forEach(function(b) {
        var row = el('tr', null, [
            el('td', { textContent: String(b.ip || '') }),
            el('td', { textContent: String(b.router || '') }),
            el('td', { textContent: timeAgo(b.blocked_at), title: String(b.blocked_at || '') }),
            el('td', { textContent: String(b.blocked_by || '') }),
            el('td', null, [el('button', { className: 'btn btn-unblock', textContent: 'Unblock', onClick: function() { actionUnblock(b.id); } })])
        ]);
        tbody.appendChild(row);
    });
}

function renderProfiles(profiles) {
    var tbody = document.querySelector('#profiles-table tbody');
    clearChildren(tbody);
    if (!profiles || profiles.length === 0) {
        tbody.appendChild(emptyRow(7, 'No attacker profiles'));
        return;
    }
    profiles.forEach(function(p) {
        var row = el('tr', null, [
            el('td', { textContent: String(p.ip || '') }),
            el('td', null, [escalationBadge(p.escalation_level)]),
            el('td', { textContent: String(p.total_attempts != null ? p.total_attempts : '') }),
            el('td', { textContent: String(p.country || '') }),
            el('td', { textContent: String(p.asn_org || '') }),
            el('td', { textContent: String(p.reverse_dns || '') }),
            el('td', { textContent: timeAgo(p.last_seen), title: String(p.last_seen || '') })
        ]);
        tbody.appendChild(row);
    });
}

function renderHoneypot(events) {
    var tbody = document.querySelector('#honeypot-table tbody');
    clearChildren(tbody);
    if (!events || events.length === 0) {
        tbody.appendChild(emptyRow(5, 'No honeypot events'));
        return;
    }
    events.forEach(function(e) {
        var row = el('tr', null, [
            el('td', { textContent: timeAgo(e.timestamp), title: String(e.timestamp || '') }),
            el('td', { textContent: String(e.attacker_ip || '') }),
            el('td', { textContent: String(e.port != null ? e.port : '') }),
            el('td', { textContent: String(e.service || '') }),
            el('td', { textContent: String(e.event_type || '') })
        ]);
        tbody.appendChild(row);
    });
}

function renderApprovals(approvals) {
    var container = document.getElementById('approvals-container');
    clearChildren(container);
    if (!approvals || approvals.length === 0) {
        container.appendChild(el('div', { className: 'empty-state', textContent: 'No pending approvals' }));
        return;
    }
    approvals.forEach(function(a) {
        var summary = a.profile_summary || {};
        var summaryItems = [];
        if (summary.ip) {
            summaryItems.push(el('dt', { textContent: 'IP:' }));
            summaryItems.push(el('dd', { textContent: String(summary.ip) }));
        }
        if (summary.escalation_level !== undefined) {
            summaryItems.push(el('dt', { textContent: 'Level:' }));
            summaryItems.push(el('dd', { textContent: String(summary.escalation_level) }));
        }
        if (summary.total_attempts) {
            summaryItems.push(el('dt', { textContent: 'Attempts:' }));
            summaryItems.push(el('dd', { textContent: String(summary.total_attempts) }));
        }
        if (summary.country) {
            summaryItems.push(el('dt', { textContent: 'Country:' }));
            summaryItems.push(el('dd', { textContent: String(summary.country) }));
        }
        if (a.reason) {
            summaryItems.push(el('dt', { textContent: 'Reason:' }));
            summaryItems.push(el('dd', { textContent: String(a.reason) }));
        }

        var item = el('div', { className: 'approval-item' }, [
            el('div', { className: 'approval-header' }, [
                el('span', { className: 'approval-checkpoint', textContent: String(a.checkpoint || '') }),
                el('div', { className: 'approval-actions' }, [
                    el('button', { className: 'btn btn-approve', textContent: 'Proceed', onClick: function() { actionApprove(a.id); } }),
                    el('button', { className: 'btn btn-deny', textContent: 'Stop', onClick: function() { actionDeny(a.id); } })
                ])
            ]),
            el('dl', { className: 'approval-summary' }, summaryItems)
        ]);
        container.appendChild(item);
    });
}

// ── Actions ──

async function actionBlock(id) {
    try {
        var result = await postWithTotp('/api/threats/' + id + '/block');
        // A block that hits the approval gate returns 202 pending_approval
        // (not an error, so apiPost does not throw). Report it as pending —
        // the threat is NOT yet contained — rather than "blocked successfully".
        if (result && result.status === 'pending_approval') {
            showToast(
                result.detail || 'Block requires operator approval; see Pending Approvals.',
                'pending'
            );
        } else {
            showToast('Threat blocked successfully');
        }
        refreshAll();
    } catch (err) {
        showToast('Block failed: ' + err.message, 'error');
    }
}

async function actionResolve(id) {
    try {
        await postWithTotp('/api/threats/' + id + '/resolve');
        showToast('Threat resolved');
        refreshAll();
    } catch (err) {
        showToast('Resolve failed: ' + err.message, 'error');
    }
}

async function actionUnblock(id) {
    try {
        await postWithTotp('/api/blocked/' + id + '/unblock');
        showToast('IP unblocked');
        refreshAll();
    } catch (err) {
        showToast('Unblock failed: ' + err.message, 'error');
    }
}

async function actionApprove(id) {
    try {
        await postWithTotp('/api/approvals/' + id + '/approve');
        showToast('Approval granted');
        refreshAll();
    } catch (err) {
        showToast('Approve failed: ' + err.message, 'error');
    }
}

async function actionDeny(id) {
    try {
        await postWithTotp('/api/approvals/' + id + '/deny');
        showToast('Action denied');
        refreshAll();
    } catch (err) {
        showToast('Deny failed: ' + err.message, 'error');
    }
}

// ── Policy Bar & Step-Up Controls ──

function initPolicyControls() {
    var bar = document.getElementById('policy-bar');
    var modal = document.getElementById('override-modal');
    var btnSetup = document.getElementById('btn-setup-totp');

    if (modal) {
        modal.availableApps = ['aegissiem_daemon'];
    }
    if (bar && modal) {
        bar.addEventListener('ecosystem-manage-restrictions', function() { modal.open(); });
        bar.addEventListener('ecosystem-restore-restrictions', async function() {
            try {
                await postWithTotp('/api/policy/restrictions/on', {});
                showToast('Conservative Restrictions: On restored');
                refreshAll();
            } catch (err) {
                showToast('Restore failed: ' + err.message, 'error');
            }
        });
        bar.addEventListener('ecosystem-freeze-request', async function() {
            try {
                // Sent even with an empty TOTP field: on the daemon host itself no
                // step-up is needed. From another machine the daemon answers 401.
                await postWithTotp('/api/policy/freeze', {
                    initiated_by: 'cyber-agents-dashboard',
                    channel: 'dashboard',
                    reason: 'Emergency Freeze triggered from AegisSIEM Daemon Dashboard'
                });
                showToast('Ecosystem Freeze engaged');
                refreshAll();
            } catch (err) {
                showToast('Freeze NOT engaged (a 6-digit TOTP code is required when not on the daemon host): ' + err.message, 'error');
            }
        });
        bar.addEventListener('ecosystem-resume-request', async function() {
            try {
                await postWithTotp('/api/policy/resume', {
                    reason: 'Operator resumed from AegisSIEM Daemon Dashboard'
                });
                showToast('Normal policy operation resumed');
                refreshAll();
            } catch (err) {
                showToast('Resume failed (enter 6-digit TOTP): ' + err.message, 'error');
            }
        });
        modal.addEventListener('ecosystem-override-submit', async function(ev) {
            var d = ev.detail || {};
            try {
                // Field names follow validateOverrideForm's payload
                // (duration_id, step_up.{method,credential}).
                var stepUp = d.step_up || {};
                var body = {
                    scope: d.scope,
                    duration: d.duration_id,
                    until_revoked: d.duration_id === 'until_revoked',
                    reason: d.reason
                };
                if (stepUp.method === 'totp') {
                    body.totp_code = stepUp.credential;
                } else if (stepUp.credential) {
                    body.step_up_token = stepUp.credential;
                }
                await apiPost('/api/policy/restrictions/off', body);
                showToast('Signed scoped Restrictions: Off grant active');
                refreshAll();
            } catch (err) {
                showToast('Override failed: ' + err.message, 'error');
            }
        });
    }
    if (btnSetup) {
        btnSetup.addEventListener('click', async function() {
            try {
                var res = await postWithTotp('/api/auth/step-up/totp/enroll', { operator_id: 'admin' });
                showEnrollSecret(res.secret);
                res = null;
            } catch (err) {
                showToast('2FA setup: ' + err.message, 'error');
            }
        });
    }
}

// The policy bar, Freeze button and override modal come from the shared
// ecosystem bundle (/ui/ecosystem-ui-controls.js). If it did not load, the
// custom elements never upgrade and render nothing — say so instead of leaving
// an operator to assume there is simply nothing to show.
function initUiAssetsNotice() {
    var notice = document.getElementById('ui-assets-missing');
    if (notice && !window.EcosystemUIControls) {
        notice.hidden = false;
    }
}

// The enrolment secret is returned exactly once. Keep it on screen until the
// operator says they have stored it; it lives only in this DOM node — never in
// a toast, a log, storage or a lingering variable.
function showEnrollSecret(secret) {
    var panel = document.getElementById('totp-enroll-panel');
    var code = document.getElementById('totp-enroll-secret');
    if (!panel || !code) {
        showToast('2FA enrolled, but the secret panel is missing from this page; re-run setup after reloading.', 'error');
        return;
    }
    code.textContent = secret;
    panel.hidden = false;
    code.focus();
}

function dismissEnrollSecret() {
    var panel = document.getElementById('totp-enroll-panel');
    var code = document.getElementById('totp-enroll-secret');
    if (code) code.textContent = '';
    if (panel) panel.hidden = true;
}

function initEnrollPanel() {
    var done = document.getElementById('btn-totp-enroll-done');
    if (done) done.addEventListener('click', dismissEnrollSecret);
    // Do not leave the secret in a page that is being hidden or cached.
    window.addEventListener('pagehide', dismissEnrollSecret);
}

// ── Polling ──

async function refreshAll() {
    try {
        var results = await Promise.all([
            apiGet('/api/status'),
            apiGet('/api/threats'),
            apiGet('/api/blocked'),
            apiGet('/api/profiles'),
            apiGet('/api/honeypot/events'),
            apiGet('/api/approvals'),
            apiGet('/api/policy/state')
        ]);

        setConnected(true);
        renderStatus(results[0]);
        renderThreats(results[1]);
        renderBlocked(results[2]);
        renderProfiles(results[3]);
        renderHoneypot(results[4]);
        renderApprovals(results[5]);

        var bar = document.getElementById('policy-bar');
        if (bar && results[6]) {
            bar.policyState = results[6];
        }

        document.getElementById('last-update').textContent = 'Last update: ' + new Date().toLocaleTimeString();
    } catch (err) {
        setConnected(false);
        console.error('Poll error:', err);
    }
}

function startPolling() {
    initUiAssetsNotice();
    initPolicyControls();
    initEnrollPanel();
    refreshAll();
    pollTimer = setInterval(refreshAll, POLL_INTERVAL);
}

// ── Init ──

document.addEventListener('DOMContentLoaded', startPolling);
