from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import random
import secrets
import sqlite3
import threading
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import quote

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ValidationError

from settings_store import SettingsStore, UserSettings

OPENAI_IMPORT_ERROR: Optional[Exception] = None

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover - keeps the prototype runnable without the SDK installed
    OpenAI = None  # type: ignore[assignment]
    OPENAI_IMPORT_ERROR = exc


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SeverityLevel = Literal["Low", "Medium", "High", "Critical"]
Classification = Literal["True Positive", "False Positive", "Needs More Data"]
GovernorStatus = Literal["Pending Approval", "Approved", "Rejected"]


class ManagerDecision(BaseModel):
    severity: SeverityLevel
    risk_score: int = Field(ge=0, le=100)
    routing_rationale: str
    triage_focus: list[str]
    notable_entities: list[str]


class TriageFinding(BaseModel):
    investigation_summary: str
    confidence_score: int = Field(ge=0, le=100)
    classification: Classification
    supporting_evidence: list[str]


class ContainmentPlan(BaseModel):
    proposed_action: str
    action_type: str
    operator_brief: str
    pre_approval_checklist: list[str]


class GovernorDecision(BaseModel):
    status: GovernorStatus = "Pending Approval"
    operator_note: Optional[str] = None
    decided_at: Optional[datetime] = None


class ReasoningStep(BaseModel):
    stage: str
    agent_role: str
    summary: str
    output: dict[str, Any]


class AlertRecord(BaseModel):
    id: str
    created_at: datetime
    trigger: str
    source: str
    scenario_id: str
    rule_name: str
    summary: str
    mitre_tactic: str
    affected_user: Optional[str] = None
    affected_host: Optional[str] = None
    source_ip: Optional[str] = None
    indicators: list[str]
    telemetry: list[str]
    manager: ManagerDecision
    triage: TriageFinding
    containment: ContainmentPlan
    governor: GovernorDecision = Field(default_factory=GovernorDecision)
    reasoning_log: list[ReasoningStep]
    raw_alert: dict[str, Any]


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    operator_note: Optional[str] = Field(default=None, max_length=400)


class RuntimeStatus(BaseModel):
    live_ai_mode: bool
    model: str
    auto_generate: bool
    generation_interval_seconds: int
    max_alerts: int
    min_risk_for_ai: int


class WebhookIngestRequest(BaseModel):
    source: str = Field(default="External Webhook", min_length=1, max_length=80)
    rule_name: str = Field(min_length=3, max_length=160)
    summary: str = Field(min_length=10, max_length=600)
    severity: Optional[SeverityLevel] = None
    mitre_tactic: str = Field(default="Unknown", max_length=80)
    scenario_id: str = Field(default="external_detection", max_length=80)
    affected_user: Optional[str] = Field(default=None, max_length=120)
    affected_host: Optional[str] = Field(default=None, max_length=120)
    source_ip: Optional[str] = Field(default=None, max_length=80)
    indicators: list[str] = Field(default_factory=list, max_length=25)
    telemetry: list[str] = Field(default_factory=list, max_length=25)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EndpointEventIngestRequest(BaseModel):
    host_id: str = Field(min_length=2, max_length=120)
    event_type: str = Field(min_length=3, max_length=120)
    summary: str = Field(min_length=10, max_length=600)
    severity_hint: Optional[SeverityLevel] = None
    username: Optional[str] = Field(default=None, max_length=120)
    source_ip: Optional[str] = Field(default=None, max_length=80)
    process_name: Optional[str] = Field(default=None, max_length=160)
    command_line: Optional[str] = Field(default=None, max_length=500)
    indicators: list[str] = Field(default_factory=list, max_length=25)
    telemetry: list[str] = Field(default_factory=list, max_length=25)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)


class UserIdentity(BaseModel):
    username: str
    role: Literal["analyst", "governor", "admin"]


class SettingsUpdateRequest(BaseModel):
    monitor_windows_events: Optional[bool] = None
    use_ai_triage: Optional[bool] = None
    threat_intel_enabled: Optional[bool] = None
    sample_events_enabled: Optional[bool] = None
    safe_mode: Optional[bool] = None
    collector_interval_seconds: Optional[int] = Field(default=None, ge=10, le=300)


class SettingsView(BaseModel):
    settings: UserSettings
    collector_status: dict[str, Any]
    platform: str
    is_windows: bool


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class DatabaseManager:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    governor_status TEXT NOT NULL,
                    data_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    note TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS action_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    result_json TEXT
                );
                """
            )
            self.conn.commit()

    def upsert_user(self, username: str, password_hash: str, role: str) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash=excluded.password_hash,
                    role=excluded.role
                """,
                (username, password_hash, role, utc_now().isoformat()),
            )
            self.conn.commit()

    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                "SELECT username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()

    def save_alert(self, alert: AlertRecord) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO alerts (id, created_at, source, rule_name, severity, governor_status, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.created_at.isoformat(),
                    alert.source,
                    alert.rule_name,
                    alert.manager.severity,
                    alert.governor.status,
                    alert.model_dump_json(),
                ),
            )
            self.conn.commit()

    def load_alerts(self, limit: int) -> list[AlertRecord]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT data_json FROM alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AlertRecord.model_validate_json(row["data_json"]) for row in rows]

    def save_approval(self, alert_id: str, username: str, decision: str, note: Optional[str]) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO approvals (alert_id, username, decision, note, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (alert_id, username, decision, note, utc_now().isoformat()),
            )
            self.conn.commit()

    def enqueue_action(self, alert_id: str, action_type: str, payload: dict[str, Any]) -> None:
        now = utc_now().isoformat()
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO action_queue (alert_id, action_type, payload_json, status, created_at, updated_at)
                VALUES (?, ?, ?, 'pending', ?, ?)
                """,
                (alert_id, action_type, json.dumps(payload), now, now),
            )
            self.conn.commit()

    def next_pending_action(self) -> Optional[sqlite3.Row]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, alert_id, action_type, payload_json
                FROM action_queue
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE action_queue SET status = 'running', updated_at = ? WHERE id = ?",
                    (utc_now().isoformat(), row["id"]),
                )
                self.conn.commit()
            return row

    def complete_action(self, action_id: int, status: str, result: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                """
                UPDATE action_queue
                SET status = ?, updated_at = ?, result_json = ?
                WHERE id = ?
                """,
                (status, utc_now().isoformat(), json.dumps(result), action_id),
            )
            self.conn.commit()


class AgenticSOCService:
    def __init__(self) -> None:
        self.db = DatabaseManager(BASE_DIR / "soc.db")
        self.ai_provider = os.getenv("AI_PROVIDER", "ollama").strip().lower()
        self.model = self._resolve_default_model()
        self.auto_generate = env_flag("ENABLE_AUTO_ALERTS", False)
        self.enable_sample_generation = env_flag("ENABLE_SAMPLE_EVENT_GENERATION", True)
        self.generation_interval_seconds = max(15, int(os.getenv("ALERT_INTERVAL_SECONDS", "45")))
        self.max_alerts = max(10, int(os.getenv("MAX_STORED_ALERTS", "40")))
        self.min_risk_for_ai = max(0, min(100, int(os.getenv("MIN_RISK_FOR_AI", "70"))))
        self.webhook_shared_secret = os.getenv("WEBHOOK_SHARED_SECRET", "").strip()
        self.session_secret = os.getenv("SESSION_SECRET", "dev-session-secret-change-me").strip()
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.otx_api_key = os.getenv("OTX_API_KEY", "").strip()
        self.connector_mode = os.getenv("CONNECTOR_MODE", "dry_run").strip().lower()
        self.containment_webhook_url = os.getenv("CONTAINMENT_WEBHOOK_URL", "").strip()
        self.settings_store = SettingsStore(BASE_DIR / "user_settings.json")
        self.collector_stats: dict[str, Any] = {
            "running": False,
            "last_poll_at": None,
            "last_forwarded": 0,
            "last_error": None,
        }
        self.client = self._build_ai_client()
        self.alerts: list[AlertRecord] = []
        self.lock = asyncio.Lock()
        self.generator_task: Optional[asyncio.Task[None]] = None
        self.queue_task: Optional[asyncio.Task[None]] = None
        self.collector_task: Optional[asyncio.Task[None]] = None
        self._apply_settings_from_store()
        self._seed_default_users()

    def _resolve_default_model(self) -> str:
        if self.ai_provider == "ollama":
            return os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        if self.ai_provider == "gemini":
            return os.getenv("GEMINI_MODEL", os.getenv("OPENAI_MODEL", "gemini-2.5-flash"))
        return os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def _seed_default_users(self) -> None:
        defaults = [
            (
                os.getenv("DEFAULT_ADMIN_USERNAME", "admin"),
                os.getenv("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!"),
                "admin",
            ),
            (
                os.getenv("DEFAULT_GOVERNOR_USERNAME", "governor"),
                os.getenv("DEFAULT_GOVERNOR_PASSWORD", "ChangeMe123!"),
                "governor",
            ),
        ]
        for username, password, role in defaults:
            self.db.upsert_user(username, self._hash_password(password), role)

    def _apply_settings_from_store(self) -> None:
        settings = self.settings_store.get()
        self.enable_sample_generation = settings.sample_events_enabled
        self.use_ai_triage = settings.use_ai_triage
        self.threat_intel_enabled = settings.threat_intel_enabled
        if settings.safe_mode:
            self.connector_mode = "dry_run"
        else:
            self.connector_mode = os.getenv("CONNECTOR_MODE", "dry_run").strip().lower()

    def get_settings_view(self) -> SettingsView:
        settings = self.settings_store.get()
        return SettingsView(
            settings=settings,
            collector_status=self.collector_stats.copy(),
            platform=platform.system(),
            is_windows=platform.system().lower() == "windows",
        )

    async def update_settings(self, payload: SettingsUpdateRequest) -> SettingsView:
        updates = {key: value for key, value in payload.model_dump().items() if value is not None}
        self.settings_store.update(updates)
        self._apply_settings_from_store()
        await self._sync_background_tasks()
        return self.get_settings_view()

    async def _sync_background_tasks(self) -> None:
        settings = self.settings_store.get()
        if settings.monitor_windows_events and platform.system().lower() == "windows":
            if self.collector_task is None:
                self.collector_task = asyncio.create_task(self._collector_loop())
        elif self.collector_task is not None:
            self.collector_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.collector_task
            self.collector_task = None
            self.collector_stats["running"] = False

    async def ingest_endpoint_payload(self, payload: dict[str, Any]) -> AlertRecord:
        normalized_alert = await asyncio.to_thread(self._normalize_endpoint_event, payload)
        processed_alert = await asyncio.to_thread(self._process_alert, normalized_alert, "endpoint_event")
        async with self.lock:
            self.alerts.insert(0, processed_alert)
            self.alerts = self.alerts[: self.max_alerts]
            self.db.save_alert(processed_alert)
        return processed_alert.model_copy(deep=True)

    async def _collector_loop(self) -> None:
        import collector as collector_module

        self.collector_stats["running"] = True
        print("[COLLECTOR] Built-in Windows monitor started.")
        try:
            while True:
                settings = self.settings_store.get()
                if not settings.monitor_windows_events:
                    await asyncio.sleep(2)
                    continue

                try:
                    pending = await asyncio.to_thread(
                        collector_module.collect_pending_events,
                        int(os.getenv("COLLECTOR_LOOKBACK_SECONDS", "120")),
                    )
                    for event_payload in pending:
                        await self.ingest_endpoint_payload(event_payload)
                    self.collector_stats.update(
                        {
                            "last_poll_at": utc_now().isoformat(),
                            "last_forwarded": len(pending),
                            "last_error": None,
                        }
                    )
                except Exception as exc:
                    self.collector_stats["last_error"] = str(exc)
                    print(f"[COLLECTOR] poll failed: {exc}")

                await asyncio.sleep(settings.collector_interval_seconds)
        except asyncio.CancelledError:
            self.collector_stats["running"] = False
            print("[COLLECTOR] Built-in Windows monitor stopped.")
            raise

    def _hash_password(self, password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
        return f"{salt}${digest.hex()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        try:
            salt, expected = password_hash.split("$", 1)
        except ValueError:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
        return hmac.compare_digest(digest.hex(), expected)

    def issue_session_token(self, username: str, role: str) -> str:
        payload = f"{username}|{role}"
        signature = hmac.new(
            self.session_secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{payload}|{signature}"

    def verify_session_token(self, token: str) -> Optional[UserIdentity]:
        try:
            username, role, signature = token.split("|", 2)
        except ValueError:
            return None
        payload = f"{username}|{role}"
        expected = hmac.new(
            self.session_secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if role not in {"analyst", "governor", "admin"}:
            return None
        return UserIdentity(username=username, role=role)  # type: ignore[arg-type]

    def authenticate_user(self, username: str, password: str) -> Optional[UserIdentity]:
        row = self.db.get_user(username)
        if not row or not self._verify_password(password, row["password_hash"]):
            return None
        return UserIdentity(username=row["username"], role=row["role"])

    def _build_ai_client(self) -> Any:
        if self.ai_provider == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/api").rstrip("/")
            timeout_seconds = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))
            print(
                f"[CONFIG] Live AI mode enabled. provider={self.ai_provider} "
                f"model={self.model} base_url={base_url}"
            )
            return httpx.Client(base_url=base_url, timeout=timeout_seconds)

        if self.ai_provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            base_url = os.getenv(
                "GEMINI_BASE_URL",
                "https://generativelanguage.googleapis.com/v1beta/openai/",
            )
            key_name = "GEMINI_API_KEY"
        else:
            api_key = os.getenv("OPENAI_API_KEY")
            base_url = os.getenv("OPENAI_BASE_URL")
            key_name = "OPENAI_API_KEY"

        if not api_key:
            print(f"[CONFIG] {key_name} not found. Running in deterministic fallback mode.")
            return None

        if OpenAI is None:
            print(
                f"[CONFIG] OpenAI SDK unavailable ({OPENAI_IMPORT_ERROR}). "
                "Running in deterministic fallback mode."
            )
            return None

        print(f"[CONFIG] Live AI mode enabled. provider={self.ai_provider} model={self.model}")

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        return OpenAI(**client_kwargs)

    def runtime_status(self) -> RuntimeStatus:
        return RuntimeStatus(
            live_ai_mode=bool(self.client),
            model=self.model,
            auto_generate=self.auto_generate,
            generation_interval_seconds=self.generation_interval_seconds,
            max_alerts=self.max_alerts,
            min_risk_for_ai=self.min_risk_for_ai,
        )

    def frontend_bootstrap(self) -> dict[str, Any]:
        status = self.runtime_status()
        return {
            "provider": self.ai_provider,
            "liveAiMode": status.live_ai_mode,
            "model": status.model,
            "autoGenerate": status.auto_generate,
            "generationIntervalSeconds": status.generation_interval_seconds,
            "maxAlerts": status.max_alerts,
            "minRiskForAi": status.min_risk_for_ai,
            "sampleGenerationEnabled": self.enable_sample_generation,
            "realIngestionEnabled": True,
            "settingsUrl": "/settings",
        }

    async def start(self) -> None:
        print("[APP] Starting Agentic SOC service.")
        if not self.alerts:
            self.alerts = self.db.load_alerts(self.max_alerts)
        if self.auto_generate and self.generator_task is None:
            self.generator_task = asyncio.create_task(self._generator_loop())
            print(
                f"[APP] Automatic sample event generation enabled every "
                f"{self.generation_interval_seconds} seconds."
            )
        if self.queue_task is None:
            self.queue_task = asyncio.create_task(self._action_queue_loop())
        await self._sync_background_tasks()

    async def stop(self) -> None:
        print("[APP] Stopping Agentic SOC service.")
        if self.collector_task:
            self.collector_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.collector_task
            self.collector_task = None
        if self.generator_task:
            self.generator_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.generator_task
            self.generator_task = None
        if self.queue_task:
            self.queue_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.queue_task
            self.queue_task = None
        if self.ai_provider == "ollama" and self.client:
            self.client.close()

    async def _generator_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.generation_interval_seconds)
                await self.generate_and_store_alert("timer")
        except asyncio.CancelledError:
            print("[APP] Background generator loop cancelled.")
            raise

    async def _action_queue_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(2)
                await asyncio.to_thread(self._process_next_action)
        except asyncio.CancelledError:
            print("[APP] Action queue loop cancelled.")
            raise

    async def list_alerts(self) -> list[AlertRecord]:
        async with self.lock:
            return [alert.model_copy(deep=True) for alert in self.alerts]

    async def get_alert(self, alert_id: str) -> AlertRecord:
        async with self.lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    return alert.model_copy(deep=True)

        raise KeyError(alert_id)

    def _process_next_action(self) -> None:
        row = self.db.next_pending_action()
        if not row:
            return
        try:
            payload = json.loads(row["payload_json"])
            if self.connector_mode == "webhook" and self.containment_webhook_url:
                response = httpx.post(self.containment_webhook_url, json=payload, timeout=20.0)
                response.raise_for_status()
                result = {
                    "mode": "webhook",
                    "status_code": response.status_code,
                    "response_excerpt": response.text[:500],
                }
                status = "executed"
            else:
                result = {
                    "mode": "dry_run",
                    "message": "Action recorded but not sent to a live downstream connector.",
                    "payload": payload,
                }
                status = "executed"
        except Exception as exc:
            status = "failed"
            result = {"error": str(exc), "mode": self.connector_mode}
        self.db.complete_action(row["id"], status, result)

    async def record_decision(
        self,
        alert_id: str,
        payload: DecisionRequest,
        actor: UserIdentity,
    ) -> AlertRecord:
        decision_status: GovernorStatus = "Approved" if payload.decision == "approve" else "Rejected"
        decision_summary = (
            "Tier 4 Governor approved the containment action and cleared it for execution."
            if payload.decision == "approve"
            else "Tier 4 Governor rejected the proposed action and sent the case back for analyst review."
        )

        async with self.lock:
            for index, alert in enumerate(self.alerts):
                if alert.id != alert_id:
                    continue

                updated_log = [step for step in alert.reasoning_log if step.stage != "Tier 4 Governor"]
                updated_log.append(
                    ReasoningStep(
                        stage="Tier 4 Governor",
                        agent_role="Human Approval",
                        summary=decision_summary,
                        output={
                            "decision": decision_status,
                            "operator_note": payload.operator_note or "No operator note supplied.",
                            "decided_at": utc_now().isoformat(),
                        },
                    )
                )

                alert.governor = GovernorDecision(
                    status=decision_status,
                    operator_note=payload.operator_note,
                    decided_at=utc_now(),
                )
                alert.reasoning_log = updated_log
                self.alerts[index] = alert
                self.db.save_alert(alert)
                self.db.save_approval(alert.id, actor.username, decision_status, payload.operator_note)
                if decision_status == "Approved":
                    self.db.enqueue_action(
                        alert.id,
                        alert.containment.action_type,
                        {
                            "alert_id": alert.id,
                            "source": alert.source,
                            "proposed_action": alert.containment.proposed_action,
                            "action_type": alert.containment.action_type,
                            "approved_by": actor.username,
                            "operator_note": payload.operator_note,
                        },
                    )

                print(
                    f"[GOVERNOR] alert_id={alert.id} decision={decision_status} "
                    f"note={payload.operator_note or 'n/a'}"
                )
                return alert.model_copy(deep=True)

        raise KeyError(alert_id)

    async def generate_and_store_alert(self, trigger: str) -> AlertRecord:
        raw_alert = self._generate_sample_endpoint_alert()
        print(
            f"[SAMPLE] Generated alert_id={raw_alert['alert_id']} "
            f"scenario={raw_alert['scenario_id']} trigger={trigger}"
        )

        processed_alert = await asyncio.to_thread(self._process_alert, raw_alert, trigger)

        async with self.lock:
            self.alerts.insert(0, processed_alert)
            self.alerts = self.alerts[: self.max_alerts]
            self.db.save_alert(processed_alert)

        return processed_alert.model_copy(deep=True)

    async def ingest_external_alert(
        self,
        payload: WebhookIngestRequest,
        raw_body: bytes,
        signature: Optional[str],
    ) -> AlertRecord:
        self._validate_webhook_signature(raw_body, signature)
        normalized_alert = await asyncio.to_thread(self._normalize_external_alert, payload.model_dump())
        print(
            f"[INGEST] Received external alert_id={normalized_alert['alert_id']} "
            f"source={normalized_alert['source']} rule={normalized_alert['rule_name']}"
        )
        processed_alert = await asyncio.to_thread(self._process_alert, normalized_alert, "webhook")

        async with self.lock:
            self.alerts.insert(0, processed_alert)
            self.alerts = self.alerts[: self.max_alerts]
            self.db.save_alert(processed_alert)

        return processed_alert.model_copy(deep=True)

    async def ingest_endpoint_event(
        self,
        payload: EndpointEventIngestRequest,
        raw_body: bytes,
        signature: Optional[str],
    ) -> AlertRecord:
        self._validate_webhook_signature(raw_body, signature)
        normalized_alert = await asyncio.to_thread(self._normalize_endpoint_event, payload.model_dump())
        print(
            f"[INGEST] Received endpoint event alert_id={normalized_alert['alert_id']} "
            f"host={normalized_alert.get('affected_host', 'unknown')} type={payload.event_type}"
        )
        processed_alert = await asyncio.to_thread(self._process_alert, normalized_alert, "endpoint_event")

        async with self.lock:
            self.alerts.insert(0, processed_alert)
            self.alerts = self.alerts[: self.max_alerts]
            self.db.save_alert(processed_alert)

        return processed_alert.model_copy(deep=True)

    def _process_alert(self, raw_alert: dict[str, Any], trigger: str) -> AlertRecord:
        manager = self._fallback_manager(raw_alert)
        ai_used = False
        if self._should_use_ai(raw_alert, manager):
            manager = self._run_manager_agent(raw_alert)
            ai_used = True

        triage = self._fallback_triage(raw_alert, manager)
        containment = self._fallback_containment(raw_alert, manager, triage)
        if ai_used:
            triage = self._run_triage_worker(raw_alert, manager)
            containment = self._run_containment_worker(raw_alert, manager, triage)

        print(
            f"[PIPELINE] alert_id={raw_alert['alert_id']} severity={manager.severity} "
            f"confidence={triage.confidence_score} action={containment.action_type}"
        )

        return AlertRecord(
            id=raw_alert["alert_id"],
            created_at=datetime.fromisoformat(raw_alert["generated_at"]),
            trigger=trigger,
            source=raw_alert["source"],
            scenario_id=raw_alert["scenario_id"],
            rule_name=raw_alert["rule_name"],
            summary=raw_alert["summary"],
            mitre_tactic=raw_alert["mitre_tactic"],
            affected_user=raw_alert.get("affected_user"),
            affected_host=raw_alert.get("affected_host"),
            source_ip=raw_alert.get("source_ip"),
            indicators=raw_alert["indicators"],
            telemetry=raw_alert["telemetry"],
            manager=manager,
            triage=triage,
            containment=containment,
            reasoning_log=[
                ReasoningStep(
                    stage="Manager Agent",
                    agent_role="Router / Severity Scorer",
                    summary=manager.routing_rationale,
                    output=manager.model_dump(),
                ),
                ReasoningStep(
                    stage="Triage Worker",
                    agent_role="Investigator / Evidence Reviewer",
                    summary=triage.investigation_summary,
                    output=triage.model_dump(),
                ),
                ReasoningStep(
                    stage="Containment Worker",
                    agent_role="Responder / Containment Planner",
                    summary=containment.operator_brief,
                    output=containment.model_dump(),
                ),
                ReasoningStep(
                    stage="Token Policy",
                    agent_role="Cost Guardrail",
                    summary=(
                        "Live model inference was used for this case."
                        if ai_used
                        else "Fallback reasoning was used because the case risk stayed below the AI threshold."
                    ),
                    output={
                        "ai_used": ai_used,
                        "min_risk_for_ai": self.min_risk_for_ai,
                        "estimated_risk": manager.risk_score,
                    },
                ),
            ],
            raw_alert=raw_alert,
        )

    def _should_use_ai(self, raw_alert: dict[str, Any], fallback_manager: ManagerDecision) -> bool:
        if not self.client or not getattr(self, "use_ai_triage", True):
            return False
        if raw_alert.get("scenario_id") == "endpoint_sample":
            return False
        return fallback_manager.risk_score >= self.min_risk_for_ai

    def _validate_webhook_signature(self, raw_body: bytes, signature: Optional[str]) -> None:
        if not self.webhook_shared_secret:
            return

        if not signature:
            raise HTTPException(status_code=401, detail="Missing webhook signature.")

        expected = hmac.new(
            self.webhook_shared_secret.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        provided = signature.replace("sha256=", "").strip()

        if not hmac.compare_digest(expected, provided):
            raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    def _normalize_external_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        source_ip = payload.get("source_ip") or None
        affected_user = payload.get("affected_user") or None
        affected_host = payload.get("affected_host") or None
        indicators = [str(item) for item in payload.get("indicators", []) if str(item).strip()]
        telemetry = [str(item) for item in payload.get("telemetry", []) if str(item).strip()]
        metadata = payload.get("metadata", {})

        enrichments = self._enrich_indicators(source_ip)
        enrichment_summary = self._summarize_enrichments(enrichments)

        if source_ip and source_ip not in indicators:
            indicators.insert(0, source_ip)
        if affected_user and affected_user not in indicators:
            indicators.append(affected_user)
        if affected_host and affected_host not in indicators:
            indicators.append(affected_host)

        if enrichment_summary:
            telemetry.extend(enrichment_summary)

        severity = payload.get("severity")
        scenario_id = payload.get("scenario_id") or "external_detection"

        if not severity:
            severity = self._estimate_external_severity(payload, enrichments)

        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": scenario_id,
            "source": payload["source"],
            "rule_name": payload["rule_name"],
            "summary": payload["summary"],
            "mitre_tactic": payload.get("mitre_tactic") or "Unknown",
            "affected_user": affected_user,
            "affected_host": affected_host,
            "source_ip": source_ip,
            "indicators": indicators[:25],
            "telemetry": telemetry[:25],
            "metadata": metadata,
            "enrichments": enrichments,
            "analyst_supplied_severity": severity,
        }

    def _normalize_endpoint_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        source_ip = payload.get("source_ip") or None
        affected_user = payload.get("username") or None
        affected_host = payload.get("host_id") or None
        process_name = payload.get("process_name") or None
        command_line = payload.get("command_line") or None
        indicators = [str(item) for item in payload.get("indicators", []) if str(item).strip()]
        telemetry = [str(item) for item in payload.get("telemetry", []) if str(item).strip()]
        metadata = payload.get("metadata", {})
        event_type = str(payload.get("event_type", "local_event")).strip().lower().replace(" ", "_")
        severity = payload.get("severity_hint")

        if source_ip and source_ip not in indicators:
            indicators.insert(0, source_ip)
        if affected_user and affected_user not in indicators:
            indicators.append(affected_user)
        if affected_host and affected_host not in indicators:
            indicators.append(affected_host)
        if process_name and process_name not in indicators:
            indicators.append(process_name)

        if command_line:
            telemetry.append(f"Command line: {command_line[:260]}")

        enrichments = self._enrich_indicators(source_ip)
        enrichment_summary = self._summarize_enrichments(enrichments)
        if enrichment_summary:
            telemetry.extend(enrichment_summary)

        if not severity:
            severity = self._estimate_external_severity(
                {
                    "rule_name": payload.get("event_type", ""),
                    "summary": payload.get("summary", ""),
                    "telemetry": telemetry,
                    "indicators": indicators,
                },
                enrichments,
            )

        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "endpoint_detection",
            "source": "Local Endpoint Agent",
            "rule_name": f"Endpoint Event: {payload['event_type']}",
            "summary": payload["summary"],
            "mitre_tactic": "Execution",
            "affected_user": affected_user,
            "affected_host": affected_host,
            "source_ip": source_ip,
            "process_name": process_name,
            "command_line": command_line,
            "event_type": event_type,
            "indicators": indicators[:25],
            "telemetry": telemetry[:25],
            "metadata": metadata,
            "enrichments": enrichments,
            "analyst_supplied_severity": severity,
        }

    def _estimate_external_severity(
        self,
        payload: dict[str, Any],
        enrichments: dict[str, Any],
    ) -> SeverityLevel:
        text = " ".join(
            [
                payload.get("rule_name", ""),
                payload.get("summary", ""),
                " ".join(payload.get("telemetry", [])),
                " ".join(payload.get("indicators", [])),
            ]
        ).lower()

        critical_terms = ["ransomware", "exfil", "data theft", "domain admin", "mass encryption"]
        high_terms = ["powershell", "credential", "lateral", "privilege", "c2", "impossible travel"]
        medium_terms = ["brute force", "password spray", "failed login", "phishing"]

        if any(term in text for term in critical_terms):
            return "Critical"
        if any(term in text for term in high_terms):
            return "High"
        if any(term in text for term in medium_terms):
            return "Medium"

        abuse_confidence = enrichments.get("abuseipdb", {}).get("abuseConfidenceScore", 0)
        if abuse_confidence >= 90:
            return "High"
        if abuse_confidence >= 60:
            return "Medium"
        return "Low"

    def _enrich_indicators(self, source_ip: Optional[str]) -> dict[str, Any]:
        enrichments: dict[str, Any] = {}
        if not source_ip or not self._is_public_ip(source_ip):
            return enrichments
        if not getattr(self, "threat_intel_enabled", False):
            return enrichments

        if self.abuseipdb_api_key:
            enrichments["abuseipdb"] = self._lookup_abuseipdb(source_ip)
        if self.otx_api_key:
            enrichments["otx"] = self._lookup_otx(source_ip)
        return enrichments

    def _summarize_enrichments(self, enrichments: dict[str, Any]) -> list[str]:
        summary: list[str] = []

        abuse = enrichments.get("abuseipdb")
        if abuse and not abuse.get("error"):
            score = abuse.get("abuseConfidenceScore", 0)
            reports = abuse.get("totalReports", 0)
            usage = abuse.get("usageType") or "unknown usage type"
            summary.append(
                f"AbuseIPDB reports source IP confidence {score}/100 with {reports} reports; usage type: {usage}."
            )

        otx = enrichments.get("otx")
        if otx and not otx.get("error"):
            pulse_count = otx.get("pulse_info", {}).get("count", 0)
            reputation = otx.get("reputation", 0)
            country = otx.get("country_name") or "unknown country"
            summary.append(
                f"AlienVault OTX returned reputation {reputation} with {pulse_count} pulses for the source IP ({country})."
            )

        return summary

    def _is_public_ip(self, value: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(value)
            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except ValueError:
            return False

    def _lookup_abuseipdb(self, ip_value: str) -> dict[str, Any]:
        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip_value, "maxAgeInDays": 90},
                timeout=15.0,
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except Exception as exc:
            print(f"[ENRICHMENT] AbuseIPDB lookup failed for {ip_value}: {exc}")
            return {"error": str(exc)}

    def _lookup_otx(self, ip_value: str) -> dict[str, Any]:
        try:
            response = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{quote(ip_value)}/general",
                headers={"X-OTX-API-KEY": self.otx_api_key},
                timeout=15.0,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            print(f"[ENRICHMENT] OTX lookup failed for {ip_value}: {exc}")
            return {"error": str(exc)}

    def _run_manager_agent(self, raw_alert: dict[str, Any]) -> ManagerDecision:
        fallback = self._fallback_manager(raw_alert)
        prompt = """
You are the Manager Agent inside an Agentic Security Operations Center.
Read the incoming alert and decide how severe it is before routing it to the Triage Worker.

Return valid JSON only with exactly these keys:
- severity: one of Low, Medium, High, Critical
- risk_score: integer from 0 to 100
- routing_rationale: short SOC-focused explanation
- triage_focus: array of 2 to 4 concrete investigative priorities
- notable_entities: array of usernames, hosts, IPs, or artifacts that deserve attention

Keep the explanation concise, practical, and defensible for a human operator.
"""
        result = self._call_ai_model(
            agent_name="Manager",
            prompt=prompt,
            payload=raw_alert,
            model_class=ManagerDecision,
            fallback=fallback,
        )
        print(
            f"[MANAGER] alert_id={raw_alert['alert_id']} severity={result.severity} "
            f"risk_score={result.risk_score}"
        )
        return result

    def _run_triage_worker(
        self, raw_alert: dict[str, Any], manager: ManagerDecision
    ) -> TriageFinding:
        fallback = self._fallback_triage(raw_alert, manager)
        prompt = """
You are the Triage Worker inside an Agentic Security Operations Center.
Use the raw alert and the Manager Agent output to produce a short investigative assessment.

Return valid JSON only with exactly these keys:
- investigation_summary: a 2 to 3 sentence summary
- confidence_score: integer from 0 to 100 representing confidence in the classification
- classification: one of True Positive, False Positive, Needs More Data
- supporting_evidence: array of 2 to 4 concrete observations

Your summary should sound like a senior SOC analyst writing a fast case note.
"""
        payload = {
            "raw_alert": raw_alert,
            "manager_output": manager.model_dump(),
        }
        result = self._call_ai_model(
            agent_name="Triage",
            prompt=prompt,
            payload=payload,
            model_class=TriageFinding,
            fallback=fallback,
        )
        print(
            f"[TRIAGE] alert_id={raw_alert['alert_id']} classification={result.classification} "
            f"confidence={result.confidence_score}"
        )
        return result

    def _run_containment_worker(
        self,
        raw_alert: dict[str, Any],
        manager: ManagerDecision,
        triage: TriageFinding,
    ) -> ContainmentPlan:
        fallback = self._fallback_containment(raw_alert, manager, triage)
        prompt = """
You are the Containment Worker inside an Agentic Security Operations Center.
Recommend a specific action that a human Tier 4 Governor could approve.

Return valid JSON only with exactly these keys:
- proposed_action: the precise containment or remediation command in plain English
- action_type: short category such as Host Isolation, Identity Containment, or Network Blocking
- operator_brief: 1 to 2 sentences explaining why the action is the safest next move
- pre_approval_checklist: array of 2 to 4 checks the human should confirm before approving

Optimize for least-privilege containment that still meaningfully reduces risk.
"""
        payload = {
            "raw_alert": raw_alert,
            "manager_output": manager.model_dump(),
            "triage_output": triage.model_dump(),
        }
        result = self._call_ai_model(
            agent_name="Containment",
            prompt=prompt,
            payload=payload,
            model_class=ContainmentPlan,
            fallback=fallback,
        )
        print(
            f"[CONTAINMENT] alert_id={raw_alert['alert_id']} action_type={result.action_type} "
            f"proposed_action={result.proposed_action}"
        )
        return result

    def _call_ai_model(
        self,
        *,
        agent_name: str,
        prompt: str,
        payload: dict[str, Any],
        model_class: type[BaseModel],
        fallback: BaseModel,
    ) -> Any:
        if not self.client:
            print(f"[OPENAI:{agent_name}] Live AI unavailable. Using fallback reasoning.")
            return fallback

        try:
            if self.ai_provider == "ollama":
                response = self.client.post(
                    "/chat",
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": prompt},
                            {"role": "user", "content": json.dumps(payload, indent=2)},
                        ],
                        "stream": False,
                        "format": "json",
                        "options": {
                            "temperature": 0.2,
                        },
                    },
                )
                response.raise_for_status()
                response_payload = response.json()
                raw_text = (response_payload.get("message", {}).get("content") or "").strip()
            elif self.ai_provider == "gemini":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": prompt},
                        {"role": "user", "content": json.dumps(payload, indent=2)},
                    ],
                    response_format={"type": "json_object"},
                )
                raw_text = (response.choices[0].message.content or "").strip()
            else:
                response = self.client.responses.create(
                    model=self.model,
                    input=[
                        {"role": "developer", "content": prompt},
                        {"role": "user", "content": json.dumps(payload, indent=2)},
                    ],
                    text={"format": {"type": "json_object"}},
                )
                raw_text = (response.output_text or "").strip()

            print(f"[OPENAI:{agent_name}] raw_response={raw_text}")

            if not raw_text:
                raise ValueError("Model returned an empty response.")

            data = json.loads(raw_text)
            return model_class.model_validate(data)
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            print(f"[OPENAI:{agent_name}] Response validation failed: {exc}. Using fallback.")
        except httpx.HTTPError as exc:
            print(f"[OPENAI:{agent_name}] HTTP call failed: {exc}. Using fallback.")
        except Exception as exc:  # pragma: no cover - external API behavior
            print(f"[OPENAI:{agent_name}] API call failed: {exc}. Using fallback.")

        return fallback

    def _scenario_profile(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        scenario_id = raw_alert["scenario_id"]
        user = raw_alert.get("affected_user") or "unknown-user"
        host = raw_alert.get("affected_host") or "unknown-host"
        source_ip = raw_alert.get("source_ip") or "unknown-ip"
        if scenario_id == "external_detection":
            analyst_supplied_severity = raw_alert.get("analyst_supplied_severity", "Medium")
            telemetry = raw_alert.get("telemetry", [])
            enrichments = raw_alert.get("enrichments", {})
            supporting_evidence = telemetry[:3] if telemetry else [
                "A live webhook alert was received from an external detection source.",
                "The alert payload was normalized into the SOC workflow for investigation.",
            ]
            abuse = enrichments.get("abuseipdb", {})
            abuse_score = abuse.get("abuseConfidenceScore", 0)
            confidence = 55 if analyst_supplied_severity == "Low" else 72 if analyst_supplied_severity == "Medium" else 84
            if abuse_score >= 90:
                confidence = min(96, confidence + 10)
            elif abuse_score >= 60:
                confidence = min(90, confidence + 6)

            action_type = "Network Blocking" if source_ip != "unknown-ip" else "Identity Containment"
            proposed_action = (
                f"Block source IP {source_ip} at the edge and preserve host {host} for deeper review."
                if source_ip != "unknown-ip"
                else f"Require containment review for user {user} and isolate host {host} if additional telemetry confirms impact."
            )

            return {
                "severity": analyst_supplied_severity,
                "risk_score": 35 if analyst_supplied_severity == "Low" else 62 if analyst_supplied_severity == "Medium" else 83 if analyst_supplied_severity == "High" else 95,
                "confidence_score": confidence,
                "classification": "True Positive" if confidence >= 80 else "Needs More Data",
                "routing_rationale": (
                    "A live externally supplied alert entered the SOC pipeline and was prioritized using the "
                    "webhook metadata plus any available threat-intelligence enrichment."
                ),
                "triage_focus": [
                    "Validate the alert source and original telemetry",
                    "Confirm whether the indicators map to a currently affected user or host",
                    "Correlate the inbound indicators with any surrounding authentication or endpoint activity",
                ],
                "notable_entities": [item for item in [user, host, source_ip] if item and item not in {"unknown-user", "unknown-host", "unknown-ip"}],
                "investigation_summary": (
                    "This alert was ingested from a live external source instead of the mock generator, which means the "
                    "case should be validated against the original telemetry and any enrichment evidence before response."
                ),
                "supporting_evidence": supporting_evidence,
                "action_type": action_type,
                "proposed_action": proposed_action,
                "operator_brief": (
                    "The response remains human-gated, but this case now reflects a real inbound event with optional "
                    "external reputation context instead of synthetic demo data."
                ),
                "pre_approval_checklist": [
                    "Verify the alert origin and timestamp against the upstream system",
                    "Confirm the indicator is not an internal scanner or known benign service",
                    "Retain the original event payload for audit and response tracking",
                ],
            }

        if scenario_id in {"endpoint_detection", "endpoint_sample"}:
            analyst_supplied_severity = raw_alert.get("analyst_supplied_severity", "Medium")
            host = raw_alert.get("affected_host") or host
            event_type = raw_alert.get("event_type", "endpoint_event")
            process_name = raw_alert.get("process_name") or "unknown-process"
            source_label = "sample endpoint event" if scenario_id == "endpoint_sample" else "live endpoint event"
            confidence = 58 if analyst_supplied_severity == "Low" else 74 if analyst_supplied_severity == "Medium" else 86
            if "powershell" in event_type or "encoded" in raw_alert.get("summary", "").lower():
                confidence = min(95, confidence + 6)

            action_type = "Process Containment" if process_name != "unknown-process" else "Host Triage"
            return {
                "severity": analyst_supplied_severity,
                "risk_score": 36 if analyst_supplied_severity == "Low" else 64 if analyst_supplied_severity == "Medium" else 84 if analyst_supplied_severity == "High" else 95,
                "confidence_score": confidence,
                "classification": "True Positive" if confidence >= 80 else "Needs More Data",
                "routing_rationale": (
                    f"A {source_label} was normalized into a single-endpoint incident format and prioritized using "
                    "rules-first scoring with optional threat-intelligence enrichment."
                ),
                "triage_focus": [
                    "Verify endpoint event integrity and timestamp alignment",
                    "Confirm whether behavior matches expected admin or automation activity",
                    "Check for repeated patterns from the same host or user in the last hour",
                ],
                "notable_entities": [item for item in [user, host, source_ip, process_name] if item and item not in {"unknown-user", "unknown-host", "unknown-ip", "unknown-process"}],
                "investigation_summary": (
                    f"The endpoint reported event type '{event_type}' on {host}. The case is designed for low-cost "
                    "triage first, then selective AI escalation only when risk justifies model usage."
                ),
                "supporting_evidence": (raw_alert.get("telemetry") or ["Endpoint telemetry was received and normalized."])[:3],
                "action_type": action_type,
                "proposed_action": (
                    f"Contain process {process_name} on {host}, collect forensic artifacts, and keep outbound network "
                    "controls scoped to only the observed indicators."
                    if process_name != "unknown-process"
                    else f"Place {host} into heightened monitoring and block suspicious outbound indicators pending analyst confirmation."
                ),
                "operator_brief": (
                    "This response is intentionally conservative for single-endpoint operations: contain what is known, "
                    "preserve evidence, and avoid broad disruptive actions."
                ),
                "pre_approval_checklist": [
                    "Confirm the event is not part of a planned administrative maintenance task",
                    "Capture process tree and command-line artifacts before containment",
                    "Validate rollback steps are available if activity is later deemed benign",
                ],
            }

        if scenario_id == "impossible_travel":
            locations = raw_alert.get("locations", ["unknown-location-a", "unknown-location-b"])
            return {
                "severity": "High",
                "risk_score": 86,
                "confidence_score": 82,
                "classification": "True Positive",
                "routing_rationale": (
                    "The alert shows a successful identity event from geographically distant regions within an "
                    "unrealistic window, which is consistent with account takeover or token abuse."
                ),
                "triage_focus": [
                    "Validate whether MFA was satisfied for both sessions",
                    "Review session revocation and impossible travel suppression history",
                    f"Confirm whether {user} had any approved travel or VPN exception",
                ],
                "notable_entities": [user, source_ip, locations[0], locations[1]],
                "investigation_summary": (
                    f"{user} authenticated from {locations[0]} and {locations[1]} within minutes, making normal "
                    "travel improbable. No business context is attached to the alert, so the activity should be "
                    "treated as likely credential misuse until the session history is verified."
                ),
                "supporting_evidence": [
                    "Two distant successful logins occurred inside the same identity timeline",
                    "Session locations imply impossible travel without teleporting or proxy chaining",
                    "The alert originated from identity telemetry rather than user-reported activity",
                ],
                "action_type": "Identity Containment",
                "proposed_action": (
                    f"Revoke active sessions for {user}, force password reset, and temporarily block access from "
                    f"{source_ip} pending identity verification."
                ),
                "operator_brief": (
                    "This action reduces account takeover risk while preserving a clear rollback path if the activity "
                    "turns out to be benign travel through a trusted broker."
                ),
                "pre_approval_checklist": [
                    "Confirm whether the user is traveling or using an approved secure access gateway",
                    "Check for other high-risk sign-ins tied to the same user in the last 24 hours",
                    "Ensure the identity team is ready to handle user re-verification",
                ],
            }

        if scenario_id == "ransomware_behavior":
            process_name = raw_alert.get("process_name", "unknown-process")
            return {
                "severity": "Critical",
                "risk_score": 98,
                "confidence_score": 96,
                "classification": "True Positive",
                "routing_rationale": (
                    "Mass encryption behavior on a production endpoint indicates active impact-stage malware and "
                    "requires immediate host containment."
                ),
                "triage_focus": [
                    f"Confirm whether {host} touched mapped drives or file shares",
                    "Determine if the encryption process spawned from a user context or remote tool",
                    "Validate whether backup or EDR tampering occurred before encryption",
                ],
                "notable_entities": [host, user, process_name],
                "investigation_summary": (
                    f"{host} is exhibiting mass file rename and encryption activity from {process_name}, which aligns "
                    "strongly with ransomware tradecraft. Because the activity is already in the impact phase, "
                    "containment speed matters more than perfect attribution."
                ),
                "supporting_evidence": [
                    "EDR observed rapid sequential file modifications with encrypted extensions",
                    "The process lineage includes a non-standard binary executing from a writable path",
                    "Behavior is destructive and not consistent with patching or backup software",
                ],
                "action_type": "Host Isolation",
                "proposed_action": (
                    f"Immediately isolate {host} from the network, disable the user session for {user}, and block "
                    "the observed ransomware hash across EDR."
                ),
                "operator_brief": (
                    "Isolating the endpoint is the lowest-risk high-impact action because it stops lateral movement "
                    "and further encryption while preserving the host for forensics."
                ),
                "pre_approval_checklist": [
                    "Notify incident command and desktop support before isolation if the asset is business critical",
                    "Confirm whether the host has active server connections that need controlled shutdown",
                    "Snapshot volatile evidence if the EDR platform supports it without delaying containment",
                ],
            }

        if scenario_id == "brute_force":
            failed_login_count = raw_alert.get("failed_login_count", 0)
            return {
                "severity": "Medium",
                "risk_score": 68,
                "confidence_score": 74,
                "classification": "True Positive",
                "routing_rationale": (
                    "A concentrated burst of failed authentication attempts against an administrative identity is "
                    "consistent with password spraying or targeted brute force."
                ),
                "triage_focus": [
                    f"Check whether {user} also had successful logins after the failed attempts",
                    "Review whether the source IP appears in any threat intelligence or deny lists",
                    "Determine whether other privileged accounts were targeted in the same window",
                ],
                "notable_entities": [user, source_ip, str(failed_login_count)],
                "investigation_summary": (
                    f"The alert shows {failed_login_count} failed sign-in attempts against {user} from {source_ip}, "
                    "which is above normal error rates and suggests deliberate password guessing. The case should stay "
                    "open until we confirm there was no eventual success from the same source."
                ),
                "supporting_evidence": [
                    "The failed attempts cluster tightly in time from a single origin",
                    "The targeted account carries elevated privileges",
                    "The pattern exceeds a normal human typo rate by a wide margin",
                ],
                "action_type": "Network Blocking",
                "proposed_action": (
                    f"Block {source_ip} at the perimeter, enable a temporary lockout for {user}, and monitor for "
                    "follow-on attempts against adjacent admin accounts."
                ),
                "operator_brief": (
                    "Blocking the source and throttling the account is proportional containment that reduces the chance "
                    "of compromise without unnecessarily isolating systems."
                ),
                "pre_approval_checklist": [
                    "Confirm the source IP is not a corporate NAT or VPN egress point",
                    "Check whether the account is tied to an automation job that would be disrupted",
                    "Verify lockout thresholds will not create a broader availability issue",
                ],
            }

        if scenario_id == "suspicious_powershell":
            payload_domain = raw_alert.get("payload_domain", "unknown-domain")
            return {
                "severity": "High",
                "risk_score": 84,
                "confidence_score": 79,
                "classification": "True Positive",
                "routing_rationale": (
                    "Encoded PowerShell launching a remote payload is common post-exploitation behavior and should be "
                    "treated as malicious until proven otherwise."
                ),
                "triage_focus": [
                    "Review the process tree for parent-child execution anomalies",
                    "Check whether the downloaded payload was written to disk or injected in memory",
                    f"Assess whether {host} initiated any suspicious outbound connections after execution",
                ],
                "notable_entities": [host, user, payload_domain],
                "investigation_summary": (
                    f"{host} executed an encoded PowerShell command under {user}, followed by traffic to "
                    f"{payload_domain}. The sequence is consistent with staged malware delivery and warrants rapid "
                    "scoping before the host pivots further into the environment."
                ),
                "supporting_evidence": [
                    "The command line contains base64-encoded arguments",
                    "The process made outbound contact to a previously unseen domain",
                    "Execution occurred outside a sanctioned administrative change window",
                ],
                "action_type": "Host Isolation",
                "proposed_action": (
                    f"Isolate {host}, block the domain {payload_domain} at the proxy, and suspend {user}'s active "
                    "session pending review."
                ),
                "operator_brief": (
                    "This contains both the suspected compromised endpoint and the command-and-control channel while "
                    "keeping the response targeted."
                ),
                "pre_approval_checklist": [
                    "Verify the domain is not part of an approved internal automation workflow",
                    "Capture the command line and parent process details for later triage",
                    "Confirm whether the user is currently on a support call performing legitimate remediation",
                ],
            }

        if scenario_id == "data_exfiltration":
            data_volume = raw_alert.get("data_volume", "unknown-volume")
            return {
                "severity": "Critical",
                "risk_score": 94,
                "confidence_score": 88,
                "classification": "True Positive",
                "routing_rationale": (
                    "A large outbound transfer to an unsanctioned external destination indicates potential data loss "
                    "and should be escalated immediately."
                ),
                "triage_focus": [
                    f"Identify the data owner for the files accessed by {user}",
                    "Confirm whether the destination is an approved partner or shadow IT service",
                    f"Scope any other outbound transfers from {host} in the same period",
                ],
                "notable_entities": [user, host, source_ip, data_volume],
                "investigation_summary": (
                    f"{user} initiated an outbound transfer of {data_volume} from {host} to an unapproved "
                    f"destination at {source_ip}. The size and direction of the flow exceed the profile for routine "
                    "SaaS use, making suspected exfiltration the leading hypothesis."
                ),
                "supporting_evidence": [
                    "Outbound volume is materially above the user's established baseline",
                    "The destination has no allow-list exception in the alert context",
                    "The event correlates with access to sensitive document repositories",
                ],
                "action_type": "Data Loss Containment",
                "proposed_action": (
                    f"Quarantine {host} from high-risk egress, suspend {user}'s access to data repositories, and block "
                    f"the destination {source_ip} until the data owner validates the transfer."
                ),
                "operator_brief": (
                    "The proposed action narrows egress and repository access without forcing an enterprise-wide block, "
                    "which is useful while ownership and business context are still being confirmed."
                ),
                "pre_approval_checklist": [
                    "Confirm the destination is not an approved merger, legal, or finance transfer endpoint",
                    "Coordinate with the data owner before revoking repository access if the user is business critical",
                    "Preserve netflow or proxy evidence for the full transfer timeline",
                ],
            }

        if scenario_id == "privilege_escalation":
            group_name = raw_alert.get("group_name", "unknown-group")
            return {
                "severity": "High",
                "risk_score": 81,
                "confidence_score": 77,
                "classification": "Needs More Data",
                "routing_rationale": (
                    "Unexpected addition to a privileged group may indicate abuse of administrative rights or a change "
                    "control gap, both of which merit urgent review."
                ),
                "triage_focus": [
                    "Check whether there is a matching change request or service desk ticket",
                    "Validate who performed the group change and from which workstation",
                    f"Review any privileged actions executed by {user} after the elevation",
                ],
                "notable_entities": [user, host, group_name],
                "investigation_summary": (
                    f"{user} was added to {group_name} from {host} without embedded change context. The event could "
                    "be legitimate administration, but the lack of a ticket reference means we should treat it as "
                    "suspicious until the actor and purpose are verified."
                ),
                "supporting_evidence": [
                    "Privileged group membership changed outside the normal approval trail",
                    "The originating workstation is included as a relevant investigation pivot",
                    "The alert has impact potential even if the change later proves authorized",
                ],
                "action_type": "Privilege Revocation",
                "proposed_action": (
                    f"Temporarily remove {user} from {group_name}, keep {host} under heightened monitoring, and "
                    "require change owner validation before restoring privileges."
                ),
                "operator_brief": (
                    "Temporary privilege rollback reduces risk quickly while keeping the response reversible if the "
                    "change turns out to be legitimate."
                ),
                "pre_approval_checklist": [
                    "Confirm whether the group change aligns with an emergency maintenance window",
                    "Check whether removing the role would break production support obligations",
                    "Identify the administrator who performed the change for verbal validation",
                ],
            }

        raise ValueError(f"Unsupported scenario_id: {scenario_id}")

    def _fallback_manager(self, raw_alert: dict[str, Any]) -> ManagerDecision:
        profile = self._scenario_profile(raw_alert)
        return ManagerDecision(
            severity=profile["severity"],
            risk_score=profile["risk_score"],
            routing_rationale=profile["routing_rationale"],
            triage_focus=profile["triage_focus"],
            notable_entities=profile["notable_entities"],
        )

    def _fallback_triage(
        self, raw_alert: dict[str, Any], manager: ManagerDecision
    ) -> TriageFinding:
        profile = self._scenario_profile(raw_alert)
        return TriageFinding(
            investigation_summary=profile["investigation_summary"],
            confidence_score=profile["confidence_score"],
            classification=profile["classification"],
            supporting_evidence=profile["supporting_evidence"],
        )

    def _fallback_containment(
        self,
        raw_alert: dict[str, Any],
        manager: ManagerDecision,
        triage: TriageFinding,
    ) -> ContainmentPlan:
        profile = self._scenario_profile(raw_alert)
        return ContainmentPlan(
            proposed_action=profile["proposed_action"],
            action_type=profile["action_type"],
            operator_brief=profile["operator_brief"],
            pre_approval_checklist=profile["pre_approval_checklist"],
        )

    def _generate_sample_endpoint_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._user()
        process_name = self._choice(["powershell.exe", "cmd.exe", "wscript.exe"])
        source_ip = self._public_ip()
        event_type = self._choice(
            [
                "encoded_powershell_execution",
                "repeated_failed_logins",
                "suspicious_outbound_connection",
            ]
        )
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "endpoint_sample",
            "source": "Local Endpoint Agent",
            "rule_name": f"Sample Endpoint Event: {event_type}",
            "summary": f"{host} produced {event_type} activity requiring analyst review.",
            "mitre_tactic": "Execution",
            "affected_user": user,
            "affected_host": host,
            "source_ip": source_ip,
            "process_name": process_name,
            "event_type": event_type,
            "indicators": [host, user, source_ip, process_name, event_type],
            "telemetry": [
                "Sample endpoint event generated for dashboard testing.",
                f"Observed process: {process_name}",
                "This sample case follows low-token fallback reasoning unless risk threshold is met.",
            ],
            "analyst_supplied_severity": "Medium",
        }

    def _generate_mock_alert(self) -> dict[str, Any]:
        scenario = random.choice(
            [
                self._impossible_travel_alert,
                self._ransomware_alert,
                self._brute_force_alert,
                self._suspicious_powershell_alert,
                self._data_exfiltration_alert,
                self._privilege_escalation_alert,
            ]
        )
        return scenario()

    def _new_alert_id(self) -> str:
        return f"ALR-{utc_now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    def _choice(self, values: list[str]) -> str:
        return random.choice(values)

    def _public_ip(self) -> str:
        block = self._choice(["198.51.100", "203.0.113", "192.0.2"])
        return f"{block}.{random.randint(10, 240)}"

    def _host(self) -> str:
        return self._choice(
            [
                "HOST-ABC",
                "WKSTN-441",
                "ENG-LAPTOP-12",
                "FIN-WS-07",
                "RND-ENDPT-33",
                "OPS-JUMP-02",
            ]
        )

    def _user(self) -> str:
        return self._choice(
            [
                "alex.chen",
                "maria.garcia",
                "samir.patel",
                "olivia.brooks",
                "tier2.admin",
                "svc.backup",
            ]
        )

    def _impossible_travel_alert(self) -> dict[str, Any]:
        locations = self._choice(
            [
                ("New York, USA", "Moscow, Russia"),
                ("Austin, USA", "Singapore"),
                ("Toronto, Canada", "Berlin, Germany"),
            ]
        )
        user = self._choice(["alex.chen", "maria.garcia", "olivia.brooks"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "impossible_travel",
            "source": "Okta Identity Cloud",
            "rule_name": "Impossible Travel: Successful Logins from Distant Regions",
            "summary": f"User {user} authenticated from {locations[0]} and {locations[1]} inside a 10-minute window.",
            "mitre_tactic": "Credential Access",
            "affected_user": user,
            "affected_host": "N/A",
            "source_ip": self._public_ip(),
            "locations": list(locations),
            "indicators": [user, locations[0], locations[1], "successful_login", "impossible_travel"],
            "telemetry": [
                "Identity provider flagged two successful MFA-backed sessions inside the same timeline.",
                "Geo-velocity exceeded internal travel threshold by more than 25x.",
                "No approved travel exception was attached to the alert payload.",
            ],
        }

    def _ransomware_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._choice(["maria.garcia", "samir.patel", "svc.backup"])
        process_name = self._choice(["encryptor.exe", "locker32.exe", "svhosts.exe"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "ransomware_behavior",
            "source": "CrowdStrike Falcon",
            "rule_name": "Ransomware Behavior: Mass File Encryption",
            "summary": f"Mass file encryption detected on {host} under process {process_name}.",
            "mitre_tactic": "Impact",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "process_name": process_name,
            "indicators": [host, process_name, user, "mass_encryption", "shadow_copy_deletion"],
            "telemetry": [
                "Rapid file rename burst with newly encrypted extensions across user profile folders.",
                "Process attempted to disable recovery artifacts before encryption accelerated.",
                "EDR classified the binary as unknown and executing from a writable path.",
            ],
        }

    def _brute_force_alert(self) -> dict[str, Any]:
        user = self._choice(["tier2.admin", "olivia.brooks", "alex.chen"])
        failed_count = random.randint(45, 95)
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "brute_force",
            "source": "Microsoft Entra ID",
            "rule_name": "Brute Force: Repeated Failed Logins",
            "summary": f"{failed_count} failed sign-in attempts detected for {user} from a single source IP.",
            "mitre_tactic": "Initial Access",
            "affected_user": user,
            "affected_host": "N/A",
            "source_ip": self._public_ip(),
            "failed_login_count": failed_count,
            "indicators": [user, "failed_logins", f"count:{failed_count}", "admin_target"],
            "telemetry": [
                "Failed sign-ins were concentrated inside a short authentication window.",
                "No successful login has yet been confirmed from the same source IP.",
                "The targeted identity belongs to a privileged or elevated user profile.",
            ],
        }

    def _suspicious_powershell_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._user()
        domain = self._choice(["cdn-sync-update.net", "assets-sharepoint-login.com", "media-patch-cache.io"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "suspicious_powershell",
            "source": "Microsoft Defender for Endpoint",
            "rule_name": "Suspicious PowerShell: Encoded Command Download Cradle",
            "summary": f"Encoded PowerShell executed on {host} and contacted {domain}.",
            "mitre_tactic": "Execution",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "payload_domain": domain,
            "indicators": [host, user, domain, "powershell", "encoded_command"],
            "telemetry": [
                "PowerShell launched with base64-encoded arguments and hidden window flags.",
                "The process established outbound traffic to a never-before-seen domain.",
                "A follow-on child process spawned outside the expected admin tooling baseline.",
            ],
        }

    def _data_exfiltration_alert(self) -> dict[str, Any]:
        host = self._host()
        user = self._choice(["samir.patel", "alex.chen", "maria.garcia"])
        data_volume = self._choice(["14.2 GB", "27.8 GB", "41.5 GB"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "data_exfiltration",
            "source": "Palo Alto Cortex XDR",
            "rule_name": "Data Exfiltration: Abnormal Outbound Transfer",
            "summary": f"{user} transferred {data_volume} from {host} to an unsanctioned external destination.",
            "mitre_tactic": "Exfiltration",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "data_volume": data_volume,
            "indicators": [host, user, data_volume, "outbound_transfer", "unapproved_destination"],
            "telemetry": [
                "Transfer volume materially exceeded the 30-day baseline for the user.",
                "The destination has no approved business justification in the alert context.",
                "Sensitive file repository access occurred shortly before the transfer began.",
            ],
        }

    def _privilege_escalation_alert(self) -> dict[str, Any]:
        user = self._choice(["olivia.brooks", "samir.patel", "alex.chen"])
        host = self._choice(["OPS-JUMP-02", "IAM-ADMIN-01", "HELPDESK-44"])
        group_name = self._choice(["Domain Admins", "Global Administrators", "Backup Operators"])
        return {
            "alert_id": self._new_alert_id(),
            "generated_at": utc_now().isoformat(),
            "scenario_id": "privilege_escalation",
            "source": "Microsoft Sentinel",
            "rule_name": "Privilege Escalation: Unexpected Administrative Group Membership",
            "summary": f"{user} was added to {group_name} from {host} without a linked change ticket.",
            "mitre_tactic": "Privilege Escalation",
            "affected_user": user,
            "affected_host": host,
            "source_ip": self._public_ip(),
            "group_name": group_name,
            "indicators": [user, host, group_name, "admin_group_change"],
            "telemetry": [
                "Administrative group membership changed outside the normal service catalog workflow.",
                "The event source does not include an approved ticket or CAB reference.",
                "The target identity gained materially expanded rights immediately after the change.",
            ],
        }


soc_service = AgenticSOCService()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await soc_service.start()
    yield
    await soc_service.stop()


app = FastAPI(
    title="Endpoint SOC Copilot",
    description="Single-endpoint security triage with human-approved response actions.",
    version="2.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def current_user_from_request(request: Request) -> Optional[UserIdentity]:
    token = request.cookies.get("soc_session")
    if not token:
        return None
    return soc_service.verify_session_token(token)


def require_user(request: Request) -> UserIdentity:
    user = current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_governor(request: Request) -> UserIdentity:
    user = require_user(request)
    if user.role not in {"governor", "admin"}:
        raise HTTPException(status_code=403, detail="Governor approval role required.")
    return user


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    user = current_user_from_request(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    bootstrap_json = json.dumps(soc_service.frontend_bootstrap())
    return templates.TemplateResponse(
        request,
        "index.html",
        {"bootstrap_json": bootstrap_json, "current_user": user.model_dump()},
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {"login_error": None})


@app.post("/login")
async def login(request: Request) -> RedirectResponse:
    try:
        form = await request.form()
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "login_error": (
                    "Login form parsing failed. Make sure `python-multipart` is installed, "
                    "then restart the server."
                )
            },
            status_code=500,
        )

    try:
        payload = LoginRequest(
            username=str(form.get("username", "")).strip(),
            password=str(form.get("password", "")),
        )
    except ValidationError:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"login_error": "Username or password format is invalid."},
            status_code=400,
        )

    user = soc_service.authenticate_user(payload.username, payload.password)
    if not user:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"login_error": "Invalid username or password."},
            status_code=401,
        )
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie("soc_session", soc_service.issue_session_token(user.username, user.role), httponly=True, samesite="lax")
    return response


@app.post("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("soc_session")
    return response


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    user = current_user_from_request(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    bootstrap_json = json.dumps(soc_service.frontend_bootstrap())
    return templates.TemplateResponse(
        request,
        "settings.html",
        {"bootstrap_json": bootstrap_json, "current_user": user.model_dump()},
    )


@app.get("/api/settings", response_model=SettingsView)
async def get_settings(request: Request) -> SettingsView:
    require_user(request)
    return soc_service.get_settings_view()


@app.put("/api/settings", response_model=SettingsView)
async def update_settings(request: Request, payload: SettingsUpdateRequest) -> SettingsView:
    require_user(request)
    return await soc_service.update_settings(payload)


@app.get("/api/me", response_model=UserIdentity)
async def get_me(request: Request) -> UserIdentity:
    return require_user(request)


@app.get("/api/status", response_model=RuntimeStatus)
async def get_status(request: Request) -> RuntimeStatus:
    require_user(request)
    print("[API] /api/status requested")
    return soc_service.runtime_status()


@app.get("/api/alerts", response_model=list[AlertRecord])
async def list_alerts(request: Request) -> list[AlertRecord]:
    require_user(request)
    print("[API] /api/alerts requested")
    return await soc_service.list_alerts()


@app.post("/api/alerts/generate", response_model=AlertRecord)
async def generate_alert(request: Request) -> AlertRecord:
    require_user(request)
    if not soc_service.enable_sample_generation:
        raise HTTPException(status_code=403, detail="Sample event generation is disabled.")
    print("[API] /api/alerts/generate requested")
    return await soc_service.generate_and_store_alert("manual-sample")


@app.post("/api/ingest/webhook", response_model=AlertRecord)
async def ingest_webhook_alert(
    request: Request,
    payload: WebhookIngestRequest,
) -> AlertRecord:
    print("[API] /api/ingest/webhook requested")
    raw_body = await request.body()
    signature = request.headers.get("X-Signature")
    return await soc_service.ingest_external_alert(payload, raw_body, signature)


@app.post("/api/ingest/endpoint-event", response_model=AlertRecord)
async def ingest_endpoint_event(
    request: Request,
    payload: EndpointEventIngestRequest,
) -> AlertRecord:
    print("[API] /api/ingest/endpoint-event requested")
    raw_body = await request.body()
    signature = request.headers.get("X-Signature")
    return await soc_service.ingest_endpoint_event(payload, raw_body, signature)


@app.get("/api/alerts/{alert_id}", response_model=AlertRecord)
async def get_alert(alert_id: str, request: Request) -> AlertRecord:
    require_user(request)
    print(f"[API] /api/alerts/{alert_id} requested")
    try:
        return await soc_service.get_alert(alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found.") from exc


@app.post("/api/alerts/{alert_id}/decision", response_model=AlertRecord)
async def record_decision(alert_id: str, payload: DecisionRequest, request: Request) -> AlertRecord:
    actor = require_governor(request)
    print(f"[API] /api/alerts/{alert_id}/decision requested with decision={payload.decision}")
    try:
        return await soc_service.record_decision(alert_id, payload, actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found.") from exc
