INSERT INTO keys (
        id,
        provider,
        encryption_key_id,
        signature_key_id,
        data_blob
    )
VALUES (
        :id,
        :provider,
        :encryption_key_id,
        :signature_key_id,
        :data_blob
    ) ON CONFLICT(id) DO
UPDATE
SET data_blob = excluded.data_blob;
