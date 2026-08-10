from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import hashlib
import json
import uuid
import os

app = FastAPI()

# -----------------------------
# In-memory stores
# -----------------------------
proposal_store = {}
receipt_store = {}

# -----------------------------
# Models
# -----------------------------
class DossierRequest(BaseModel):
    dossier: str
    mode: str = "normal"  # normal / audit

class CommitRequest(BaseModel):
    callId: str
    receipt: dict

# -----------------------------
# Utils
# -----------------------------
def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))

def generate_digest(text):
    return hashlib.sha256(text.encode()).hexdigest()

def extract_evidence(text, keywords):
    evidence = []
    lines = text.split("\n")
    for line in lines:
        for kw in keywords:
            if kw.lower() in line.lower():
                evidence.append(line.strip())
    return evidence[:5]

# -----------------------------
# Rule आधारित decision engine
# -----------------------------
def decide_action(dossier):
    text = dossier.lower()

    if "invoice" in text:
        return "store_document", ["invoice", "amount", "billing"]
    elif "complaint" in text:
        return "escalate_case", ["issue", "complaint", "problem"]
    elif "spam" in text or "unsubscribe" in text:
        return "reject", ["unsubscribe", "offer", "click"]
    else:
        return "reject", ["unknown"]

# -----------------------------
# PROPOSE
# -----------------------------
@app.post("/propose")
def propose(req: DossierRequest):
    dossier = req.dossier

    input_digest = generate_digest(dossier)

    # Replay (same input → same output)
    if input_digest in proposal_store:
        return proposal_store[input_digest]

    action, keywords = decide_action(dossier)
    evidence = extract_evidence(dossier, keywords)

    call_id = str(uuid.uuid4())

    # STRICT contract shape
    proposal = {
        "proposal": {
            "callId": call_id,
            "action": action,
            "target": {
                "recipient": "ops@company.com"
            },
            "payload": {
                "subject": "Auto processed mail",
                "body": dossier[:200]
            },
            "evidence": evidence,
            "inputDigest": input_digest
        }
    }

    # Audit mode → ensure executable
    if req.mode == "audit":
        proposal["proposal"]["payload"]["audit"] = True

    proposal_store[input_digest] = proposal
    receipt_store[call_id] = None

    return proposal

# -----------------------------
# COMMIT
# -----------------------------
@app.post("/commit")
def commit(req: CommitRequest):
    call_id = req.callId

    if call_id not in receipt_store:
        raise HTTPException(status_code=400, detail="Invalid callId")

    # Reject invalid receipt
    if "status" not in req.receipt:
        raise HTTPException(status_code=400, detail="Invalid receipt")

    receipt_store[call_id] = {
        "status": req.receipt["status"],
        "receiptId": str(uuid.uuid4())
    }

    return {
        "message": "committed",
        "receipt": receipt_store[call_id]
    }

# -----------------------------
# COMPLETE
# -----------------------------
@app.post("/complete")
def complete(req: CommitRequest):
    call_id = req.callId

    if call_id not in receipt_store or receipt_store[call_id] is None:
        raise HTTPException(status_code=400, detail="No valid receipt")

    return {
        "status": "completed",
        "callId": call_id,
        "receipt": receipt_store[call_id]
    }

# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.get("/")
def home():
    return {"status": "running"}