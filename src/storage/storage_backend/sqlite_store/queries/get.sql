SELECT data_blob
FROM keys
WHERE id = :id
    AND provider = :provider
    AND encryption_key_id = :encryption_key_id
    AND signature_key_id = :signature_key_id;
