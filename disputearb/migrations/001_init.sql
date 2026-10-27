-- Every evaluated dispute. amount_paise is the disputed amount in paise (integer, never float);
-- record holds the claim, evidence packet, ledger and decision as JSON (amounts as decimal strings).
CREATE TABLE disputes (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    dispute_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    amount_paise BIGINT NOT NULL,
    classification TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    status TEXT NOT NULL,
    record TEXT NOT NULL
);
CREATE INDEX disputes_status ON disputes (status, created_at);
CREATE INDEX disputes_dispute_id ON disputes (dispute_id);

-- What an analyst actually did with each dispute, oldest first; disputes.status is the latest.
CREATE TABLE dispute_reviews (
    dispute_ref TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    status TEXT NOT NULL,
    note TEXT NOT NULL
);
CREATE INDEX dispute_reviews_ref ON dispute_reviews (dispute_ref);
