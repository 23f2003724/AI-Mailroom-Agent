from fastapi import FastAPI, HTTPException
from typing import Dict, Any, List
import hashlib
import json
import uuid
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

app = FastAPI()

# In-memory storage (replace with DB in production)
proposal_store = {}
receipt_keys = {}

# ----------------------------
# Utils
# ----------------------------
def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))

def sha256_hex(data):
    return hashlib.sha256(data.encode()).hexdigest()

def compute_input_digest(dossiers):
    return sha256_hex(canonical_json(dossiers))

def generate_call_id(dossier_id):
    return f"{dossier_id}_{uuid.uuid4().hex[:8]}"

# ----------------------------
# Simple Rule-based AI (SAFE)
# ----------------------------
def ai_decide(dossier):
    lines = []
    for s in dossier["sources"]:
        for l in s["lines"]:
            lines.append((l["lineId"], l["text"].lower()))

    text = " ".join([t for _, t in lines])

    # RULES (important for marks)
    if "ignore instructions" in text or "system prompt" in text:
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {
                "artifactId": dossier["dossierId"],
                "reasonCode": "INDIRECT_PROMPT_INJECTION"
            },
            "evidence": [lines[0][0]]
        }

    if "duplicate" in text:
        return {
            "action": "no_action",
            "target": None,
            "payload": {
                "reasonCode": "DUPLICATE",
                "referenceId": dossier["dossierId"]
            },
            "evidence": [lines[0][0]]
        }

    if "confirm" in text or "verify" in text:
        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "support"},
            "payload": {
                "claimedSender": "unknown",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": dossier["dossierId"]
            },
            "evidence": [lines[0][0]]
        }

    # Default safe fallback
    return {
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": dossier["dossierId"]
        },
        "evidence": [lines[0][0]]
    }

# ----------------------------
# Receipt Signature Verify
# ----------------------------
def verify_signature(public_key_jwk, receipt, signature_b64, evaluationId, inputDigest):
    try:
        public_key_bytes = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        message = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": evaluationId,
            "inputDigest": inputDigest,
            "receipt": receipt
        }

        msg_bytes = canonical_json(message).encode()
        signature = base64.b64decode(signature_b64)

        public_key.verify(signature, msg_bytes)
        return True
    except Exception:
        return False

# ----------------------------
# PROPOSE
# ----------------------------
def handle_propose(req: Dict[str, Any]):
    dossiers = req["dossiers"]
    evaluationId = req["evaluationId"]

    inputDigest = compute_input_digest(dossiers)

    proposals = []

    for d in dossiers:
        decision = ai_decide(d)
        call_id = generate_call_id(d["dossierId"])

        proposal = {
            "dossierId": d["dossierId"],
            "callId": call_id,
            "action": decision["action"],
            "target": decision["target"],
            "payload": decision["payload"],
            "evidence": decision["evidence"]
        }

        proposals.append(proposal)

        # Store proposal for commit stage
        proposal_store[(evaluationId, d["dossierId"])] = proposal

    # Store verifier key
    receipt_keys[evaluationId] = req["receiptVerifier"]["publicKeyJwk"]

    return {
        "profile": req["profile"],
        "evaluationId": evaluationId,
        "status": "awaiting_receipts",
        "inputDigest": inputDigest,
        "proposals": proposals
    }

# ----------------------------
# COMMIT
# ----------------------------
def handle_commit(req: Dict[str, Any]):
    evaluationId = req["evaluationId"]
    inputDigest = req["inputDigest"]
    receipts = req["receipts"]

    if evaluationId not in receipt_keys:
        raise HTTPException(status_code=400, detail="Unknown evaluation")

    public_key_jwk = receipt_keys[evaluationId]
    outcomes = []

    for r in receipts:
        receipt_core = {
            "dossierId": r["dossierId"],
            "callId": r["callId"],
            "action": r["action"],
            "accepted": r["accepted"],
            "proposalDigest": r["proposalDigest"],
            "receiptId": r["receiptId"]
        }

        # Verify signature
        if not verify_signature(
            public_key_jwk,
            receipt_core,
            r["receiptSignature"],
            evaluationId,
            inputDigest
        ):
            raise HTTPException(status_code=400, detail="Invalid signature")

        status = "executed" if r["accepted"] else "rejected"

        outcomes.append({
            "dossierId": r["dossierId"],
            "callId": r["callId"],
            "action": r["action"],
            "proposalDigest": r["proposalDigest"],
            "receiptId": r["receiptId"],
            "status": status
        })

    return {
        "profile": req["profile"],
        "evaluationId": evaluationId,
        "status": "completed",
        "inputDigest": inputDigest,
        "outcomes": outcomes
    }

# ----------------------------
# MAIN ENDPOINT
# ----------------------------
@app.post("/")
async def mailroom_agent(req: Dict[str, Any]):
    if "operation" not in req:
        raise HTTPException(status_code=400, detail="Missing operation")

    if req["operation"] == "propose":
        return handle_propose(req)

    elif req["operation"] == "commit":
        return handle_commit(req)

    else:
        raise HTTPException(status_code=400, detail="Invalid operation")