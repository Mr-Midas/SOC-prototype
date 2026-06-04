from __future__ import annotations

import os
from uuid import UUID

import stripe
from fastapi import APIRouter, HTTPException, Request

from copilot_soc.api.auth import require_auth
from copilot_soc.api.deps import get_db

router = APIRouter(tags=["billing"])

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


@router.post("/api/billing/portal")
async def billing_portal(request: Request):
    user_identity = require_auth(request)
    db = await get_db()
    tenant_id = UUID(user_identity["tenant_id"])

    tenant = await db.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    stripe_customer_id = tenant.get("stripe_customer_id")
    if not stripe_customer_id:
        if not STRIPE_SECRET_KEY:
            raise HTTPException(status_code=501, detail="Billing not configured.")
        customer = stripe.Customer.create(
            metadata={"tenant_id": str(tenant_id)},
            email=request.headers.get("X-User-Email"),
        )
        stripe_customer_id = customer.id
        await db.update_tenant_stripe(tenant_id, stripe_customer_id)

    session = stripe.billing_portal.Session.create(
        customer=stripe_customer_id,
        return_url=str(request.base_url) + "dashboard/settings",
    )

    return {"url": session.url}


@router.post("/api/billing/webhook")
async def stripe_webhook(request: Request):
    import json

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if STRIPE_WEBHOOK_SECRET and sig_header:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature.")
    else:
        event = json.loads(payload)

    db = await get_db()

    if event["type"].startswith("customer.subscription."):
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer")
        tenant = await db.get_tenant_by_stripe(customer_id)
        if tenant:
            plan = subscription.get("items", {}).get("data", [{}])[0].get("price", {}).get("lookup_key", "starter")
            await db.update_tenant_plan(UUID(tenant["id"]), plan)
            await db.record_stripe_event(event["id"], event["type"], event)
    elif event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_id = session.get("customer")
        tenant_id = session.get("metadata", {}).get("tenant_id")
        if tenant_id and customer_id:
            await db.update_tenant_stripe(UUID(tenant_id), customer_id)

    return {"status": "ok"}
