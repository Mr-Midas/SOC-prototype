#!/usr/bin/env python3
"""Bootstrap the first tenant and admin user for Arbiterion."""

import asyncio
import hashlib
import hmac
import os
import secrets
from uuid import uuid4

import asyncpg

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://arbiterion:arbiterion@localhost:5432/arbiterion")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${digest.hex()}"


def generate_api_key() -> str:
    return f"soc_{secrets.token_hex(32)}"


def generate_webhook_secret() -> str:
    return secrets.token_hex(32)


async def seed():
    conn = await asyncpg.connect(DATABASE_URL)

    # Check if already seeded
    existing = await conn.fetchrow(
        "SELECT id FROM users WHERE email = $1",
        "admin@arbiterion.local",
    )
    if existing:
        print("Already seeded â€” nothing to do.")
        await conn.close()
        return

    tenant_id = uuid4()
    admin_id = uuid4()
    password_hash = hash_password("ChangeMe123!")
    api_key = generate_api_key()
    webhook_secret = generate_webhook_secret()

    await conn.execute(
        """
        INSERT INTO tenants (id, name, slug, plan_tier, alert_limit)
        VALUES ($1, 'Default Corp', 'default', 'starter', 100)
        """,
        tenant_id,
    )

    await conn.execute(
        """
        INSERT INTO users (id, tenant_id, email, password_hash, role)
        VALUES ($1, $2, 'admin@arbiterion.local', $3, 'admin')
        """,
        admin_id, tenant_id, password_hash,
    )

    await conn.execute(
        """
        INSERT INTO tenant_settings (tenant_id, llm_provider, llm_model, use_ai_triage, safe_mode, webhook_secret)
        VALUES ($1, 'openai', 'gpt-4o-mini', false, true, $2)
        """,
        tenant_id, webhook_secret,
    )

    print(f"Tenant ID:    {tenant_id}")
    print(f"Admin ID:     {admin_id}")
    print(f"Email:        admin@arbiterion.local")
    print(f"Password:     ChangeMe123!")
    print(f"API Key:      {api_key}")
    print(f"Webhook Key:  {webhook_secret}")

    await conn.close()


if __name__ == "__main__":
    asyncio.run(seed())

