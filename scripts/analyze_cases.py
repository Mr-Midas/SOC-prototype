import asyncio
import asyncpg
import json
import os
from arbiterion.config import settings

async def get_open_cases():
    conn = await asyncpg.connect(settings.database_url)
    try:
        # Open cases = alerts that are either still in pipeline or pending governor approval
        rows = await conn.fetch(
            "SELECT id, rule_name, summary, severity, risk_score, pipeline_state, governor_status, raw_alert, containment_output "
            "FROM alerts "
            "WHERE pipeline_state != 'completed' OR governor_status = 'pending' "
            "ORDER BY created_at DESC"
        )
        
        results = []
        for row in rows:
            results.append({
                "id": str(row["id"]),
                "rule": row["rule_name"],
                "summary": row["summary"],
                "severity": row["severity"],
                "risk": row["risk_score"],
                "state": row["pipeline_state"],
                "gov_status": row["governor_status"],
                "raw": json.loads(row["raw_alert"]) if isinstance(row["raw_alert"], str) else row["raw_alert"],
                "plan": json.loads(row["containment_output"]) if isinstance(row["containment_output"], str) else row["containment_output"]
            })
        return results
    finally:
        await conn.close()

if __name__ == "__main__":
    cases = asyncio.run(get_open_cases())
    print(json.dumps(cases, indent=2))
