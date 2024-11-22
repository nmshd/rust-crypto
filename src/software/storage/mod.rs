pub mod keys;
pub mod metadata;

const METADATA_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("metadata");
