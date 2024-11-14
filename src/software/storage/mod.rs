use redb::TableDefinition;

pub mod keys;
pub mod metadata;

const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
// const KEY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
