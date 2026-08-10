import json
import hashlib
import base64
import uuid
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

app = FastAPI()

# =========================
# In-memory DB (use Redis in prod)
# =========================
evaluations = {}
dossier_cache = {}

PROFILE = "ga5-mailroom-action-gate/v2"


# =========================
# Helpers
# =========================

def canonical_json(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def sha256_hex(data: bytes):
    return hashlib.sha256(data).hexdigest()


def compute_input_digest(dossiers):
    return sha256_hex(canonical_json(dossiers).encode())


def compute_proposal_digest(p):
    minimal = {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p["target"],
        "payload": p["payload"],
        "evidence": sorted(p["evidence"]),
    }
    return sha256_hex(canonical_json(minimal).encode())


def verify_signature(pubkey_b64, message_bytes, sig_b64):
    try:
        verify_key = VerifyKey(base64.urlsafe_b64decode(pubkey_b64 + "=="))
        verify_key.verify(message_bytes, base64.b64decode(sig_b64))
        return True
    except BadSignatureError:
        return False


def make_call_id(digest):
    return digest[:24]


# =========================
# AI decision (SAFE BASELINE)
# =========================

def decide_action(dossier):
    """
    Minimal safe baseline:
    - Always avoid unsafe execution
    - Use INFORMATIONAL unless strong signal exists
    """

    lines = []
    for s in dossier["sources"]:
        for l in s["lines"]:
            lines.append(l["lineId"])

    # ALWAYS safe fallback
    return {
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": dossier["dossierId"]
        },
        "evidence": [lines[0]] if lines else []
    }


# =========================
# PROPOSE
# =========================

@app.post("/")
async def handle(request: Request):
    body = await request.json()

    if body.get("profile") != PROFILE:
        raise HTTPException(400, "Invalid profile")

    operation = body.get("operation")

    if operation == "propose":
        return await handle_propose(body)
    elif operation == "commit":
        return await handle_commit(body)
    else:
        raise HTTPException(400, "Invalid operation")


async def handle_propose(body):
    evaluation_id = body["evaluationId"]
    dossiers = body["dossiers"]

    digest = compute_input_digest(dossiers)

    # Conflict check
    if evaluation_id in evaluations:
        if evaluations[evaluation_id]["inputDigest"] != digest:
            raise HTTPException(409, "Conflict")

    proposals = []

    for d in dossiers:
        d_key = sha256_hex(canonical_json(d).encode())

        # CACHE HIT
        if d_key in dossier_cache:
            proposal = dossier_cache[d_key]
        else:
            decision = decide_action(d)

            call_id = make_call_id(d_key)

            proposal = {
                "dossierId": d["dossierId"],
                "callId": call_id,
                "action": decision["action"],
                "target": decision["target"],
                "payload": decision["payload"],
                "evidence": decision["evidence"]
            }

            dossier_cache[d_key] = proposal

        proposals.append(proposal)

    # Store evaluation
    evaluations[evaluation_id] = {
        "inputDigest": digest,
        "proposals": proposals,
        "verifier": body["receiptVerifier"]["publicKeyJwk"]["x"]
    }

    return JSONResponse({
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "status": "awaiting_receipts",
        "inputDigest": digest,
        "proposals": proposals
    })


# =========================
# COMMIT
# =========================

async def handle_commit(body):
    evaluation_id = body["evaluationId"]
    input_digest = body["inputDigest"]
    receipts = body["receipts"]

    if evaluation_id not in evaluations:
        raise HTTPException(400, "Unknown evaluation")

    stored = evaluations[evaluation_id]

    if stored["inputDigest"] != input_digest:
        raise HTTPException(409, "Digest mismatch")

    pubkey = stored["verifier"]
    proposals = stored["proposals"]

    outcomes = []

    for r in receipts:
        # Find matching proposal
        match = next(
            (p for p in proposals if p["callId"] == r["callId"]),
            None
        )
        if not match:
            raise HTTPException(400, "Invalid callId")

        # Verify proposal digest
        expected_digest = compute_proposal_digest(match)
        if expected_digest != r["proposalDigest"]:
            raise HTTPException(400, "Proposal mismatch")

        # Build signed message
        message = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "receipt": {
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "accepted": r["accepted"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"]
            }
        }

        message_bytes = canonical_json(message).encode()

        if not verify_signature(pubkey, message_bytes, r["receiptSignature"]):
            raise HTTPException(400, "Invalid signature")

        outcomes.append({
            "dossierId": r["dossierId"],
            "callId": r["callId"],
            "action": r["action"],
            "proposalDigest": r["proposalDigest"],
            "receiptId": r["receiptId"],
            "status": "executed" if r["accepted"] else "rejected"
        })

    return JSONResponse({
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes
    })