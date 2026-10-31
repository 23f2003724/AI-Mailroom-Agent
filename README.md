# Public HTTPS Mailroom Agent

One JSON endpoint handles both operations:

- POST /v1/mailroom/actions with operation "propose"
- POST /v1/mailroom/actions with operation "commit"

The service validates every request, asks AIPipe for grounded action proposals, stores evaluations and dossier decisions
in SQLite, verifies Ed25519 receipts, and records completion only after every receipt is valid.

## Runtime configuration

- AIPIPE_API_KEY: API key from the AIPipe organization
- AIPIPE_BASE_URL: optional, defaults to https://aipipe.org/openrouter/v1
- AIPIPE_MODEL: optional, defaults to openai/gpt-4.1-nano
- MAILROOM_DB_PATH: optional SQLite file path; defaults to mailroom.sqlite3 beside main.py

Start command:

    uvicorn main:app --host 0.0.0.0 --port $PORT

The grader endpoint URL ends with /v1/mailroom/actions.
