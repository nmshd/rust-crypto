CREATE TABLE keys (
    id TEXT PRIMARY KEY,
    provider TEXT,
    encryption_key_id TEXT,
    signature_key_id TEXT,
    data_blob BLOB
);
