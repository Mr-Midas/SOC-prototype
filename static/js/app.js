const state = {
    alerts: [],
    selectedAlertId: null,
    runtime: window.SOC_BOOTSTRAP || {},
};

const elements = {
    feed: document.getElementById("alert-feed"),
    feedEmpty: document.getElementById("feed-empty"),
    detailEmpty: document.getElementById("detail-empty"),
    detailContent: document.getElementById("detail-content"),
    detailTitle: document.getElementById("detail-title"),
    detailSummary: document.getElementById("detail-summary"),
    detailSeverity: document.getElementById("detail-severity"),
    detailGovernor: document.getElementById("detail-governor"),
    detailCreatedAt: document.getElementById("detail-created-at"),
    riskScore: document.getElementById("detail-risk-score"),
    confidenceScore: document.getElementById("detail-confidence-score"),
    riskBarFill: document.getElementById("risk-bar-fill"),
    confidenceBarFill: document.getElementById("confidence-bar-fill"),
    reasoningLog: document.getElementById("reasoning-log"),
    telemetryList: document.getElementById("telemetry-list"),
    indicatorList: document.getElementById("indicator-list"),
    proposedAction: document.getElementById("proposed-action"),
    operatorNote: document.getElementById("operator-note"),
    approveButton: document.getElementById("approve-button"),
    rejectButton: document.getElementById("reject-button"),
    generateButton: document.getElementById("generate-button"),
    refreshButton: document.getElementById("refresh-button"),
    openCount: document.getElementById("open-count"),
    criticalCount: document.getElementById("critical-count"),
    approvedCount: document.getElementById("approved-count"),
    modeBadge: document.getElementById("mode-badge"),
    modelBadge: document.getElementById("model-badge"),
    intervalBadge: document.getElementById("interval-badge"),
    toast: document.getElementById("toast"),
    resolvedSection: document.getElementById("resolved-section"),
    resolvedToggle: document.getElementById("resolved-toggle"),
    resolvedCount: document.getElementById("resolved-count"),
    resolvedChevron: document.getElementById("resolved-chevron"),
    resolvedList: document.getElementById("resolved-list"),
};

function isLive(alert) {
    return !alert.governor.status || alert.governor.status === "Pending" || alert.governor.status === "Pending Approval";
}

function isResolved(alert) {
    return alert.governor.status === "Approved" || alert.governor.status === "Rejected";
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function severityClass(severity) {
    const map = {
        Low: "severity-low",
        Medium: "severity-medium",
        High: "severity-high",
        Critical: "severity-critical",
    };
    return map[severity] || "severity-medium";
}

function statusClass(status) {
    const map = {
        "Pending Approval": "status-pending",
        Pending: "status-pending",
        Approved: "status-approved",
        Rejected: "status-rejected",
    };
    return map[status] || "status-pending";
}

function formatDate(value) {
    return new Date(value).toLocaleString([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
    });
}

function setRuntimeBadges() {
    const provider = state.runtime.provider || "unknown";
    elements.modeBadge.textContent = state.runtime.liveAiMode ? "Selective AI" : "Rules-Only";
    elements.modelBadge.textContent = `${String(provider).toUpperCase()} / ${state.runtime.model || "Unconfigured"}`;
    elements.intervalBadge.textContent = state.runtime.autoGenerate
        ? `${state.runtime.generationIntervalSeconds || 0}s`
        : `Manual / AI >= ${state.runtime.minRiskForAi ?? "n/a"}`;
    if (!state.runtime.sampleGenerationEnabled) {
        elements.generateButton.disabled = true;
        elements.generateButton.style.opacity = "0.6";
        elements.generateButton.style.cursor = "not-allowed";
        elements.generateButton.title = "Sample event generation disabled by configuration.";
    }
}

function showToast(message, tone = "info") {
    elements.toast.textContent = message;
    elements.toast.classList.remove("hidden");
    elements.toast.style.borderColor = tone === "error" ? "rgba(255, 94, 122, 0.28)" : "rgba(67, 217, 244, 0.22)";
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => {
        elements.toast.classList.add("hidden");
    }, 3200);
}

async function api(path, options = {}) {
    const response = await fetch(path, {
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
        },
        ...options,
    });

    if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Authentication required.");
    }

    if (!response.ok) {
        let message = "Request failed.";
        try {
            const errorPayload = await response.json();
            message = errorPayload.detail || message;
        } catch (error) {
            console.error("Failed to parse error payload", error);
        }
        throw new Error(message);
    }

    return response.json();
}

function renderStats() {
    const live = state.alerts.filter(isLive);
    const pending = live.length;
    const critical = live.filter((alert) => ["High", "Critical"].includes(alert.manager.severity)).length;
    const approved = state.alerts.filter((alert) => alert.governor.status === "Approved").length;

    elements.openCount.textContent = String(pending);
    elements.criticalCount.textContent = String(critical);
    elements.approvedCount.textContent = String(approved);
}

function renderFeed() {
    const liveAlerts = state.alerts.filter(isLive);

    if (!liveAlerts.length) {
        elements.feed.innerHTML = "";
        elements.feedEmpty.classList.remove("hidden");
        renderEmptyDetail();
    } else {
        elements.feedEmpty.classList.add("hidden");
        elements.feed.innerHTML = liveAlerts
            .map((alert) => {
                const isActive = alert.id === state.selectedAlertId;
                return `
                    <button class="feed-item ${isActive ? "active" : ""}" data-alert-id="${escapeHtml(alert.id)}">
                        <div class="flex flex-wrap items-start justify-between gap-3">
                            <div class="max-w-[75%]">
                                <div class="severity-pill ${severityClass(alert.manager.severity)}">${escapeHtml(alert.manager.severity)}</div>
                                <div class="mt-4 font-display text-xl font-bold uppercase tracking-[0.08em] text-white">${escapeHtml(alert.rule_name)}</div>
                                <p class="mt-3 text-sm leading-7 text-slate-300">${escapeHtml(alert.summary)}</p>
                            </div>
                            <div class="flex flex-col items-end gap-2">
                                <div class="status-chip ${statusClass(alert.governor.status)}">${escapeHtml(alert.governor.status)}</div>
                                <div class="font-accent text-[11px] uppercase tracking-[0.2em] text-slate-500">${escapeHtml(alert.source)}</div>
                            </div>
                        </div>
                        <div class="mt-5 flex flex-wrap items-center justify-between gap-3 font-accent text-xs uppercase tracking-[0.12em] text-slate-400">
                            <span>Risk ${escapeHtml(alert.manager.risk_score)} / Confidence ${escapeHtml(alert.triage.confidence_score)}</span>
                            <span>${escapeHtml(formatDate(alert.created_at))}</span>
                        </div>
                    </button>
                `;
            })
            .join("");

        document.querySelectorAll("[data-alert-id]").forEach((item) => {
            item.addEventListener("click", () => {
                selectAlert(item.getAttribute("data-alert-id"));
            });
        });
    }

    renderResolvedBacklog();
}

function renderResolvedBacklog() {
    const resolved = state.alerts.filter(isResolved);
    const count = resolved.length;
    elements.resolvedCount.textContent = `(${count})`;

    if (!count) {
        elements.resolvedSection.classList.add("hidden");
        return;
    }
    elements.resolvedSection.classList.remove("hidden");

    elements.resolvedList.innerHTML = resolved
        .map((alert) => {
            const isActive = alert.id === state.selectedAlertId;
            return `
                <button class="feed-item feed-item-resolved ${isActive ? "active" : ""}" data-alert-id="${escapeHtml(alert.id)}">
                    <div class="flex flex-wrap items-center justify-between gap-3">
                        <div class="flex items-center gap-3">
                            <div class="severity-pill severity-pill-sm ${severityClass(alert.manager.severity)}">${escapeHtml(alert.manager.severity)}</div>
                            <span class="font-display text-sm font-bold uppercase tracking-[0.08em] text-white">${escapeHtml(alert.rule_name)}</span>
                        </div>
                        <div class="flex items-center gap-3">
                            <div class="status-chip ${statusClass(alert.governor.status)}">${escapeHtml(alert.governor.status)}</div>
                            <span class="font-accent text-[11px] uppercase tracking-[0.12em] text-slate-500">${escapeHtml(formatDate(alert.created_at))}</span>
                        </div>
                    </div>
                </button>
            `;
        })
        .join("");

    document.querySelectorAll("#resolved-list [data-alert-id]").forEach((item) => {
        item.addEventListener("click", () => {
            selectAlert(item.getAttribute("data-alert-id"));
        });
    });
}

function renderEmptyDetail() {
    state.selectedAlertId = null;
    elements.detailContent.classList.add("hidden");
    elements.detailEmpty.classList.remove("hidden");
    elements.operatorNote.value = "";
}

function renderReasoningFields(output) {
    return Object.entries(output)
        .map(([key, value]) => {
            let formatted = "";
            if (Array.isArray(value)) {
                formatted = value.map((item) => `<span class="token">${escapeHtml(item)}</span>`).join(" ");
            } else {
                formatted = escapeHtml(value);
            }

            const label = key.replaceAll("_", " ");
            return `
                <div class="reasoning-field">
                    <div class="reasoning-field-label">${escapeHtml(label)}</div>
                    <div class="reasoning-field-value">${formatted}</div>
                </div>
            `;
        })
        .join("");
}

function renderDetail(alert) {
    if (!alert) {
        renderEmptyDetail();
        return;
    }

    state.selectedAlertId = alert.id;
    elements.detailEmpty.classList.add("hidden");
    elements.detailContent.classList.remove("hidden");

    elements.detailTitle.textContent = alert.rule_name;
    elements.detailSummary.textContent = alert.summary;
    elements.detailSeverity.className = `severity-pill ${severityClass(alert.manager.severity)}`;
    elements.detailSeverity.textContent = alert.manager.severity;
    elements.detailGovernor.textContent = alert.governor.status;
    elements.detailCreatedAt.textContent = formatDate(alert.created_at);
    elements.riskScore.textContent = `${alert.manager.risk_score}%`;
    elements.confidenceScore.textContent = `${alert.triage.confidence_score}%`;
    elements.riskBarFill.style.width = `${alert.manager.risk_score}%`;
    elements.confidenceBarFill.style.width = `${alert.triage.confidence_score}%`;
    elements.proposedAction.textContent = alert.containment.proposed_action;
    elements.operatorNote.value = alert.governor.operator_note || "";

    elements.reasoningLog.innerHTML = alert.reasoning_log
        .map(
            (step) => `
                <article class="reasoning-card">
                    <div class="flex flex-wrap items-center justify-between gap-3">
                        <div>
                            <div class="text-[11px] uppercase tracking-[0.24em] text-cyanpulse">${escapeHtml(step.stage)}</div>
                            <div class="mt-2 font-display text-xl font-bold uppercase tracking-[0.08em] text-white">${escapeHtml(step.agent_role)}</div>
                        </div>
                    </div>
                    <p class="mt-3 text-sm leading-7 text-slate-300">${escapeHtml(step.summary)}</p>
                    <div class="reasoning-grid">
                        ${renderReasoningFields(step.output)}
                    </div>
                </article>
            `
        )
        .join("");

    elements.telemetryList.innerHTML = alert.telemetry
        .map((entry) => `<div class="telemetry-item">${escapeHtml(entry)}</div>`)
        .join("");

    elements.indicatorList.innerHTML = alert.indicators
        .map((indicator) => `<span class="token">${escapeHtml(indicator)}</span>`)
        .join("");

    const resolved = isResolved(alert);
    elements.approveButton.disabled = resolved;
    elements.rejectButton.disabled = resolved;
    elements.approveButton.style.opacity = resolved ? "0.4" : "1";
    elements.rejectButton.style.opacity = resolved ? "0.4" : "1";
    elements.approveButton.style.cursor = resolved ? "not-allowed" : "pointer";
    elements.rejectButton.style.cursor = resolved ? "not-allowed" : "pointer";

    renderFeed();
}

async function loadAlerts({ preserveSelection = true } = {}) {
    const data = await api("/api/alerts");
    state.alerts = data.alerts || [];

    if (!preserveSelection || !state.selectedAlertId) {
        state.selectedAlertId = state.alerts[0]?.id || null;
    } else if (!state.alerts.some((alert) => alert.id === state.selectedAlertId)) {
        state.selectedAlertId = state.alerts[0]?.id || null;
    }

    renderStats();
    renderFeed();

    if (state.selectedAlertId) {
        const selected = state.alerts.find((alert) => alert.id === state.selectedAlertId);
        renderDetail(selected);
    } else {
        renderEmptyDetail();
    }
}

async function selectAlert(alertId) {
    const selected = state.alerts.find((alert) => alert.id === alertId);
    if (selected) {
        renderDetail(selected);
        return;
    }

    try {
        const data = await api(`/api/alerts/${encodeURIComponent(alertId)}`);
        const alert = data.alert || data;
        const index = state.alerts.findIndex((item) => item.id === alert.id);
        if (index >= 0) {
            state.alerts[index] = alert;
        } else {
            state.alerts.unshift(alert);
        }
        renderStats();
        renderDetail(alert);
    } catch (error) {
        console.error(error);
        showToast(error.message, "error");
    }
}

async function generateAlert() {
    toggleActionState(true);
    try {
        const alert = await api("/api/alerts/generate", { method: "POST" });
        state.alerts.unshift(alert);
        state.selectedAlertId = alert.id;
        renderStats();
        renderDetail(alert);
        showToast("Sample endpoint event generated and triaged.");
    } catch (error) {
        console.error(error);
        showToast(error.message, "error");
    } finally {
        toggleActionState(false);
    }
}

async function submitDecision(decision) {
    if (!state.selectedAlertId) {
        showToast("Select an alert before taking action.", "error");
        return;
    }

    toggleActionState(true);
    try {
        const payload = {
            decision,
            operator_note: elements.operatorNote.value.trim() || null,
        };
        const updated = await api(`/api/alerts/${encodeURIComponent(state.selectedAlertId)}/decision`, {
            method: "POST",
            body: JSON.stringify(payload),
        });

        state.alerts = state.alerts.map((alert) => (alert.id === updated.id ? updated : alert));
        renderStats();
        renderDetail(updated);
        showToast(
            decision === "approve"
                ? "Containment approved by Tier 4 Governor."
                : "Containment rejected and sent back for review."
        );
    } catch (error) {
        console.error(error);
        showToast(error.message, "error");
    } finally {
        toggleActionState(false);
    }
}

function toggleActionState(isBusy) {
    [
        elements.generateButton,
        elements.refreshButton,
        elements.approveButton,
        elements.rejectButton,
    ].forEach((button) => {
        button.disabled = isBusy;
        button.style.opacity = isBusy ? "0.6" : "1";
        button.style.cursor = isBusy ? "wait" : "pointer";
    });
}

function startPolling() {
    setInterval(async () => {
        try {
            await loadAlerts({ preserveSelection: true });
        } catch (error) {
            console.error("Polling failed", error);
        }
    }, 8000);
}

async function init() {
    setRuntimeBadges();

    elements.generateButton.addEventListener("click", generateAlert);
    elements.refreshButton.addEventListener("click", () => loadAlerts({ preserveSelection: true }).catch((error) => {
        console.error(error);
        showToast(error.message, "error");
    }));
    elements.approveButton.addEventListener("click", () => submitDecision("approve"));
    elements.rejectButton.addEventListener("click", () => submitDecision("reject"));

    elements.resolvedToggle.addEventListener("click", () => {
        const isHidden = elements.resolvedList.classList.contains("hidden");
        elements.resolvedList.classList.toggle("hidden");
        elements.resolvedChevron.textContent = isHidden ? "\u2212" : "+";
        elements.resolvedChevron.style.transform = isHidden ? "rotate(0deg)" : "";
    });

    try {
        await loadAlerts({ preserveSelection: false });
    } catch (error) {
        console.error(error);
        showToast(`Initial load failed: ${error.message}`, "error");
    }

    startPolling();
}

init();
