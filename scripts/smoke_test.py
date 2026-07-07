import asyncio
import httpx
import pytest
from uuid import UUID

# This is a simplified smoke test script. 
# In a real environment, this would be integrated into the pytest suite.

async def test_full_flow():
    print("Starting Arbiterion Smoke Test...")
    base_url = "http://127.0.0.1:8000"
    
    async with httpx.AsyncClient() as client:
        # 1. Health Check
        print("[1/5] Checking Health...")
        r = await client.get(f"{base_url}/api/health")
        assert r.status_code == 200
        assert r.json()["status"] in ["ok", "degraded"]
        print("  OK")

        # 2. Login
        print("[2/5] Testing Login...")
        # Note: In a real test, we'd use the admin credentials
        r = await client.post(f"{base_url}/api/login", json={
            "email": "admin",
            "password": "ChangeMe123!"
        })
        assert r.status_code == 200
        cookie = r.cookies.get("soc_session")
        assert cookie is not None
        print("  OK")

        # 3. Ingest Alert
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
            "metadata": {}
        }
        # Need to pass the cookie for require_auth
        r = await client.post(f"{base_url}/api/v1/ingest/alert", json=payload, cookies={"soc_session": cookie})
        assert r.status_code == 200
        alert_id = r.json()["id"]
        print(f"  OK - Alert created: {alert_id}")

        # 4. Verify Pipeline (Poll until completed)
        print("[4/5] Waiting for Pipeline...")
        completed = False
        for _ in range(20):
            r = await client.get(f"{base_url}/api/alerts/{alert_id}", cookies={"soc_session": cookie})
            if r.status_code == 200 and r.json()["governor"]["status"] == "Pending Approval":
                # This means it passed the pipeline and is waiting for Governor
                completed = True
                break
            await asyncio.sleep(2)
        assert completed, "Pipeline did not reach 'Pending Approval' state in time"
        print("  OK")

        # 5. Governor Approval
        print("[5/5] Testing Governor Approval...")
        r = await client.post(f"{base_url}/api/alerts/{alert_id}/decision", 
                             json={"decision": "approve", "operator_note": "Smoke test approval"},
                             cookies={"soc_session": cookie})
        assert r.status_code == 200
        print("  OK")

    print("\nSMOKE TEST PASSED SUCCESSFULLY")

if __name__ == "__main__":
    asyncio.run(test_full_flow())
