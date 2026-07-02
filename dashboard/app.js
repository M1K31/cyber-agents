// AegisSIEM Security Dashboard - Client Application
// All dynamic content is sanitized via escapeHtml() before DOM insertion.

const API_BASE = 'http://localhost:8088';
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

async function apiPost(path) {
    var resp = await fetch(API_BASE + path, { method: 'POST' });
    if (!resp.ok) throw new Error('POST ' + path + ': ' + resp.status);
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
        await apiPost('/api/threats/' + id + '/block');
        showToast('Threat blocked successfully');
        refreshAll();
    } catch (err) {
        showToast('Block failed: ' + err.message, 'error');
    }
}

async function actionResolve(id) {
    try {
        await apiPost('/api/threats/' + id + '/resolve');
        showToast('Threat resolved');
        refreshAll();
    } catch (err) {
        showToast('Resolve failed: ' + err.message, 'error');
    }
}

async function actionUnblock(id) {
    try {
        await apiPost('/api/blocked/' + id + '/unblock');
        showToast('IP unblocked');
        refreshAll();
    } catch (err) {
        showToast('Unblock failed: ' + err.message, 'error');
    }
}

async function actionApprove(id) {
    try {
        await apiPost('/api/approvals/' + id + '/approve');
        showToast('Approval granted');
        refreshAll();
    } catch (err) {
        showToast('Approve failed: ' + err.message, 'error');
    }
}

async function actionDeny(id) {
    try {
        await apiPost('/api/approvals/' + id + '/deny');
        showToast('Action denied');
        refreshAll();
    } catch (err) {
        showToast('Deny failed: ' + err.message, 'error');
    }
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
            apiGet('/api/approvals')
        ]);

        setConnected(true);
        renderStatus(results[0]);
        renderThreats(results[1]);
        renderBlocked(results[2]);
        renderProfiles(results[3]);
        renderHoneypot(results[4]);
        renderApprovals(results[5]);

        document.getElementById('last-update').textContent = 'Last update: ' + new Date().toLocaleTimeString();
    } catch (err) {
        setConnected(false);
        console.error('Poll error:', err);
    }
}

function startPolling() {
    refreshAll();
    pollTimer = setInterval(refreshAll, POLL_INTERVAL);
}

// ── Init ──

document.addEventListener('DOMContentLoaded', startPolling);
