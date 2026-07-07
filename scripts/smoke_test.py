import asyncio
import hashlib
import hmac
import json

import httpx

WEBHOOK_SECRET = "6be905086b263a5d11d90c517a7cdb00e81327d79d2c6bf097341eaa03738830"
BASE_URL = "http://127.0.0.1:8000"


async def test_full_flow():
    print("Starting Arbiterion Smoke Test...")
    print()

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        # 1. Health Check
        print("[1/5] Checking Health...")
        r = await client.get(f"{BASE_URL}/api/health")
        assert r.status_code == 200
        assert r.json()["status"] in ("ok", "degraded")
        print("  OK")

        # 2. Login
        print("[2/5] Testing Login...")
        r = await client.post(f"{BASE_URL}/api/login", json={
            "email": "admin",
            "password": "ChangeMe123!",
        })
        assert r.status_code == 200
        cookie = r.cookies.get("soc_session")
        assert cookie is not None
        print("  OK")

        # 3. Ingest Alert (with webhook signature)
        print("[3/5] Testing Ingestion...")
        payload = {
            "source": "Test-Source",
            "rule_name": "Smoke Test Alert",
            "summary": "This is a test alert for MVP verification",
            "severity": "High",
            "scenario_id": "smoke_test",
            "affected_host": "TEST-HOST-01",
            "affected_user": "test-user",
            "source_ip": "1.2.3.4",
            "indicators": [],
            "telemetry": [],
            "metadata": {},
        }
        raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        headers = {"X-Signature": f"sha256={signature}"}
        r = await client.post(
            f"{BASE_URL}/api/v1/ingest/alert",
            content=raw_body,
            headers=headers,
            cookies={"soc_session": cookie},
        )
        assert r.status_code == 200
        alert_id = r.json()["id"]
        print(f"  OK - Alert created: {alert_id}")

        # 4. Verify Pipeline (Poll until Pending Approval)
        print("[4/5] Waiting for Pipeline...")
        completed = False
        for _ in range(30):
            r = await client.get(
                f"{BASE_URL}/api/alerts/{alert_id}",
                cookies={"soc_session": cookie},
            )
            if r.status_code == 200:
                status = r.json()["governor"]["status"]
                if status == "Pending Approval":
                    completed = True
                    break
            await asyncio.sleep(2)
        assert completed, "Pipeline did not reach 'Pending Approval' state in time"
        print("  OK")

        # 5. Governor Approval
        print("[5/5] Testing Governor Approval...")
        r = await client.post(
            f"{BASE_URL}/api/alerts/{alert_id}/decision",
            json={"decision": "approve", "operator_note": "Smoke test approval"},
            cookies={"soc_session": cookie},
        )
        assert r.status_code == 200
        print("  OK")

    print()
    print("SMOKE TEST PASSED SUCCESSFULLY")


if __name__ == "__main__":
    asyncio.run(test_full_flow())
