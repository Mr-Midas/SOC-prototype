const toggles = {
    monitor: document.getElementById("toggle-monitor"),
    ai: document.getElementById("toggle-ai"),
    intel: document.getElementById("toggle-intel"),
    samples: document.getElementById("toggle-samples"),
    safe: document.getElementById("toggle-safe"),
};

const statusEl = document.getElementById("collector-status");
const platformEl = document.getElementById("platform-note");
const toastEl = document.getElementById("toast");

let saving = false;

function showToast(message, tone = "info") {
    toastEl.textContent = message;
    toastEl.classList.remove("hidden");
    toastEl.style.borderColor = tone === "error" ? "rgba(255, 94, 122, 0.28)" : "rgba(67, 217, 244, 0.22)";
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => toastEl.classList.add("hidden"), 2800);
}

async function api(path, options = {}) {
    const response = await fetch(path, {
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        ...options,
    });
    if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Authentication required.");
    }
    if (!response.ok) {
        let message = "Request failed.";
        try {
            const payload = await response.json();
            message = payload.detail || message;
        } catch (error) {
            console.error(error);
        }
        throw new Error(message);
    }
    return response.json();
}

function applySettings(view) {
    const settings = view.settings;
    toggles.monitor.checked = settings.monitor_windows_events;
    toggles.ai.checked = settings.use_ai_triage;
    toggles.intel.checked = settings.threat_intel_enabled;
    toggles.samples.checked = settings.sample_events_enabled;
    toggles.safe.checked = settings.safe_mode;

    toggles.monitor.disabled = !view.is_windows;
    if (!view.is_windows) {
        platformEl.textContent = "Windows-only: built-in monitor runs on Windows with Sysmon installed.";
    } else {
        platformEl.textContent = "Windows detected. Turn on 'Watch This Computer' to start monitoring.";
    }

    const status = view.collector_status || {};
    statusEl.innerHTML = `
        <div>Monitor running: <strong>${status.running ? "Yes" : "No"}</strong></div>
        <div>Last check: <strong>${status.last_poll_at || "Not yet"}</strong></div>
        <div>Events forwarded (last poll): <strong>${status.last_forwarded ?? 0}</strong></div>
        <div>Last error: <strong>${status.last_error || "None"}</strong></div>
    `;
}

async function saveSettings() {
    if (saving) return;
    saving = true;
    try {
        const payload = {
            monitor_windows_events: toggles.monitor.checked,
            use_ai_triage: toggles.ai.checked,
            threat_intel_enabled: toggles.intel.checked,
            sample_events_enabled: toggles.samples.checked,
            safe_mode: toggles.safe.checked,
        };
        const view = await api("/api/settings", {
            method: "PUT",
            body: JSON.stringify(payload),
        });
        applySettings(view);
        showToast("Settings saved.");
    } catch (error) {
        console.error(error);
        showToast(error.message, "error");
    } finally {
        saving = false;
    }
}

Object.values(toggles).forEach((toggle) => {
    toggle.addEventListener("change", () => saveSettings());
});

async function init() {
    try {
        const view = await api("/api/settings");
        applySettings(view);
    } catch (error) {
        console.error(error);
        showToast(`Could not load settings: ${error.message}`, "error");
    }

    setInterval(async () => {
        try {
            const view = await api("/api/settings");
            applySettings(view);
        } catch (error) {
            console.error(error);
        }
    }, 10000);
}

init();
