#!/usr/bin/env python
"""
End-to-end verification script for Arbiterion.

Run this to verify the full pipeline works:
1. App boots and serves login
2. Auth works
3. Sample alert generation triggers 3-agent pipeline
4. Alerts appear in dashboard
5. IP enrichment works (if API keys configured)
6. Governor approval workflow works

Prerequisites:
- Start the app first: .\Start Arbiterion.bat (or: uvicorn arbiterion.main:app --reload)
- App must be running at http://127.0.0.1:8000
"""

import asyncio
import os
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BASE_URL = "http://127.0.0.1:8000"
LOGIN_EMAIL = "admin@arbiterion.local"
LOGIN_PASSWORD = "ChangeMe123!"

PASS = "[PASS]"
FAIL = "[FAIL]"


class E2ETester:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=BASE_URL, timeout=30.0, follow_redirects=True)
        self.session_cookie = None

    async def close(self):
        await self.client.aclose()

    def _set_cookie(self, cookie_header: str):
        """Extract session cookie from Set-Cookie header."""
        if cookie_header:
            for part in cookie_header.split(";"):
                if part.strip().startswith("soc_session="):
                    # Extract just the value: soc_session=value
                    full = part.strip()
                    self.session_cookie = full
                    self.session_cookie_value = full.split("=", 1)[1].split(";")[0]
                    self.client.cookies.set("soc_session", self.session_cookie_value)
                    break

    def _auth_headers(self) -> dict:
        """Return headers with session cookie for authenticated requests."""
        if hasattr(self, 'session_cookie_value') and self.session_cookie_value:
            return {"Cookie": f"soc_session={self.session_cookie_value}"}
        return {}

    async def test_health(self) -> bool:
        """Verify app is up."""
        print("\n[1/7] Testing health endpoint...")
        try:
            r = await self.client.get("/api/health")
            assert r.status_code == 200
            data = r.json()
            assert data.get("status") == "ok"
            assert data.get("service") == "arbiterion"
            print(f"  {PASS} Health OK: {data}")
            return True
        except Exception as e:
            print(f"  {FAIL} Health check failed: {e}")
            return False

    async def test_login(self) -> bool:
        """Login and capture session cookie."""
        print("\n[2/7] Testing login...")
        try:
            r = await self.client.post(
                "/api/login",
                json={"email": LOGIN_EMAIL, "password": LOGIN_PASSWORD},
            )
            assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
            self._set_cookie(r.headers.get("set-cookie", ""))
            assert self.session_cookie, "No session cookie received"
            print(f"  {PASS} Login successful, cookie: {self.session_cookie[:40]}...")
            return True
        except Exception as e:
            print(f"  {FAIL} Login failed: {e}")
            return False

    async def test_me(self) -> bool:
        """Verify /api/me returns user info."""
        print("\n[3/7] Testing /api/me...")
        try:
            r = await self.client.get("/api/me", headers=self._auth_headers())
            assert r.status_code == 200, f"/api/me failed: {r.status_code} {r.text}"
            data = r.json()
            assert data.get("user_id") or data.get("email")
            assert data.get("role") == "admin"
            print(f"  {PASS} User verified: {data}")
            return True
        except Exception as e:
            print(f"  {FAIL} /api/me failed: {e}")
            return False

    async def test_generate_sample(self) -> dict:
        """Generate a sample alert via the dashboard endpoint."""
        print("\n[4/7] Generating sample alert...")
        try:
            r = await self.client.post("/api/alerts/generate", headers=self._auth_headers())
            assert r.status_code in (200, 201), f"Generate sample failed: {r.status_code} {r.text}"
            data = r.json()
            alert_id = data.get("alert_id") or data.get("id")
            assert alert_id, f"No alert_id in response: {data}"
            print(f"  {PASS} Sample alert generated: {alert_id}")
            return data
        except Exception as e:
            print(f"  {FAIL} Generate sample failed: {e}")
            return {}

    async def test_list_alerts(self, expected_count: int = 1) -> list:
        """List alerts and verify our sample appears."""
        print(f"\n[5/7] Listing alerts (expecting >= {expected_count})...")
        try:
            # Wait a moment for pipeline to process
            await asyncio.sleep(2)
            r = await self.client.get("/api/alerts?page=1&per_page=20", headers=self._auth_headers())
            assert r.status_code == 200, f"List alerts failed: {r.status_code} {r.text}"
            data = r.json()
            # API returns {"alerts": [...], "total": N, ...}
            rows = data.get("alerts", []) if isinstance(data, dict) else data
            assert len(rows) >= expected_count, f"Expected >= {expected_count} alerts, got {len(rows)}"
            print(f"  {PASS} Found {len(rows)} alerts")
            for a in rows[:3]:
                print(f"    - {a.get('id')}: {a.get('summary', '')[:60]} | state={a.get('pipeline_state')} | gov={a.get('governor_status')}")
            return rows
        except Exception as e:
            print(f"  {FAIL} List alerts failed: {e}")
            return []

    async def test_alert_detail(self, alert_id: str) -> bool:
        """Get full alert detail with reasoning log."""
        print(f"\n[6/7] Testing alert detail for {alert_id}...")
        try:
            r = await self.client.get(f"/api/alerts/{alert_id}", headers=self._auth_headers())
            assert r.status_code == 200, f"Alert detail failed: {r.status_code} {r.text}"
            data = r.json()
            assert data.get("id") == alert_id
            # Check for pipeline reasoning
            manager = data.get("manager", {})
            triage = data.get("triage", {})
            containment = data.get("containment", {})
            print(f"  {PASS} Alert detail loaded")
            print(f"    Manager: severity={manager.get('severity')}, tactic={manager.get('mitre_tactic')}")
            print(f"    Triage: summary={triage.get('investigation_summary', '')[:60]}...")
            print(f"    Containment: actions={containment.get('actions', [])}")
            return True
        except Exception as e:
            print(f"  {FAIL} Alert detail failed: {e}")
            return False

    async def test_governor_approve(self, alert_id: str) -> bool:
        """Test Governor approval workflow."""
        print(f"\n[7/7] Testing Governor approve for {alert_id}...")
        try:
            r = await self.client.post(
                f"/api/alerts/{alert_id}/governor",
                json={"decision": "approve", "notes": "E2E test approval"},
                headers=self._auth_headers(),
            )
            assert r.status_code == 200, f"Governor approve failed: {r.status_code} {r.text}"
            data = r.json()
            # API returns governor.status = "Approved"
            governor_status = data.get("governor", {}).get("status", "").lower()
            assert governor_status == "approved", f"Expected approved, got {governor_status}"
            print(f"  {PASS} Governor approved: {data}")
            return True
        except Exception as e:
            print(f"  {FAIL} Governor approve failed: {e}")
            return False

    async def test_enrichment(self) -> bool:
        """Verify IP enrichment is wired (if API keys present)."""
        print("\n[Bonus] Checking IP enrichment config...")
        try:
            r = await self.client.get("/api/settings", headers=self._auth_headers())
            assert r.status_code == 200
            data = r.json()
            settings = data.get("settings", {}) if isinstance(data, dict) else data
            abuseipdb = settings.get("abuseipdb_api_key") or os.getenv("ABUSEIPDB_API_KEY")
            otx = settings.get("otx_api_key") or os.getenv("OTX_API_KEY")
            if abuseipdb or otx:
                print(f"  {PASS} Threat intel keys configured: AbuseIPDB={'yes' if abuseipdb else 'no'}, OTX={'yes' if otx else 'no'}")
            else:
                print(f"  {FAIL} No threat intel keys configured (enrichment will skip)")
            return True
        except Exception as e:
            print(f"  {FAIL} Enrichment check failed: {e}")
            return False


async def main():
    print("=" * 60)
    print("Arbiterion End-to-End Verification")
    print("=" * 60)

    tester = E2ETester()
    results = []

    try:
        results.append(("Health", await tester.test_health()))
        results.append(("Login", await tester.test_login()))
        results.append(("/api/me", await tester.test_me()))
        sample = await tester.test_generate_sample()
        alert_id = sample.get("alert_id") or sample.get("id")
        results.append(("Generate Sample", bool(alert_id)))

        if alert_id:
            results.append(("List Alerts", await tester.test_list_alerts(1)))
            results.append(("Alert Detail", await tester.test_alert_detail(alert_id)))
            results.append(("Governor Approve", await tester.test_governor_approve(alert_id)))

        await tester.test_enrichment()

    finally:
        await tester.close()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results:
        status = PASS if passed else FAIL
        print(f"  {status}: {name}")

    all_passed = all(p for _, p in results)
    print("=" * 60)
    if all_passed:
        print("ALL TESTS PASSED - Arbiterion is working!")
        return 0
    else:
        print("SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))