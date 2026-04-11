/// SQLite-backed swap state persistence.
///
/// Stores swap state as JSON blobs keyed by 32-byte swap_id. Optionally
/// stores encrypted secret scalars alongside the state. The config table
/// holds per-database settings like the password salt.
///
/// ## Schema
///
/// ```sql
/// CREATE TABLE swaps (
///     swap_id          BLOB PRIMARY KEY,
///     state            TEXT NOT NULL,
///     updated          INTEGER NOT NULL,
///     encrypted_secret BLOB          -- argon2id + AES-256-GCM encrypted secret scalar
/// );
///
/// CREATE TABLE config (
///     key   TEXT PRIMARY KEY,
///     value BLOB NOT NULL
/// );
/// ```
use rusqlite::{Connection, params};

pub struct SwapStore {
    conn: Connection,
}

impl SwapStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS swaps (
                swap_id BLOB PRIMARY KEY,
                state   TEXT NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
        ")?;

        // Migration: add encrypted_secret column if not present.
        // Ignoring "duplicate column name" error for idempotency.
        match conn.execute(
            "ALTER TABLE swaps ADD COLUMN encrypted_secret BLOB",
            [],
        ) {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("duplicate column") {
                    return Err(e.into());
                }
            }
        }

        Ok(Self { conn })
    }

    /// Open an in-memory store (useful for tests).
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::open(":memory:")
    }

    /// Save swap state without encrypted secret (backward-compatible).
    ///
    /// Note: does not persist encrypted secrets. Use `save_with_secret`
    /// for full secret persistence.
    pub fn save(&self, swap_id: &[u8; 32], state_json: &str) -> anyhow::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO swaps (swap_id, state, updated) VALUES (?1, ?2, ?3)
             ON CONFLICT(swap_id) DO UPDATE SET state = ?2, updated = ?3",
            params![swap_id.as_ref(), state_json, now],
        )?;
        Ok(())
    }

    /// Load swap state without encrypted secret (backward-compatible).
    ///
    /// Note: does not load encrypted secrets. Use `load_with_secret`
    /// for full secret retrieval.
    pub fn load(&self, swap_id: &[u8; 32]) -> anyhow::Result<Option<String>> {
        let result = self.conn.query_row(
            "SELECT state FROM swaps WHERE swap_id = ?1",
            params![swap_id.as_ref()],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(s) => Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save swap state with an optional encrypted secret.
    ///
    /// This MUST be called BEFORE broadcasting any
    /// lock transaction. If the process crashes after broadcast but before
    /// persistence, funds are permanently lost.
    ///
    /// * `swap_id` - 32-byte swap identifier
    /// * `state_json` - JSON-serialized swap state
    /// * `encrypted_secret` - Optional encrypted secret blob (60 bytes from crypto_store)
    pub fn save_with_secret(
        &self,
        swap_id: &[u8; 32],
        state_json: &str,
        encrypted_secret: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO swaps (swap_id, state, updated, encrypted_secret)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(swap_id) DO UPDATE
             SET state = ?2, updated = ?3, encrypted_secret = ?4",
            params![
                swap_id.as_ref(),
                state_json,
                now,
                encrypted_secret,
            ],
        )?;
        Ok(())
    }

    /// Load swap state and optional encrypted secret.
    ///
    /// Returns `(state_json, optional_encrypted_secret_blob)`.
    pub fn load_with_secret(
        &self,
        swap_id: &[u8; 32],
    ) -> anyhow::Result<Option<(String, Option<Vec<u8>>)>> {
        let result = self.conn.query_row(
            "SELECT state, encrypted_secret FROM swaps WHERE swap_id = ?1",
            params![swap_id.as_ref()],
            |row| {
                let state: String = row.get(0)?;
                let secret: Option<Vec<u8>> = row.get(1)?;
                Ok((state, secret))
            },
        );
        match result {
            Ok(pair) => Ok(Some(pair)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get or create the password salt for this database.
    ///
    /// The salt is a random 16-byte value stored in the config table.
    /// It is generated once and reused for all secret encryption in
    /// this database. This ensures the same password always derives
    /// the same key for a given database file.
    pub fn get_or_create_salt(&self) -> anyhow::Result<[u8; 16]> {
        let result = self.conn.query_row(
            "SELECT value FROM config WHERE key = 'salt'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(blob) if blob.len() == 16 => {
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&blob);
                Ok(salt)
            }
            Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Generate new salt
                let salt: [u8; 16] = rand::random();
                self.conn.execute(
                    "INSERT OR REPLACE INTO config (key, value) VALUES ('salt', ?1)",
                    params![salt.as_ref()],
                )?;
                Ok(salt)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_all(&self) -> anyhow::Result<Vec<([u8; 32], String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT swap_id, state FROM swaps ORDER BY updated DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            let id_blob: Vec<u8> = row.get(0)?;
            let state: String = row.get(1)?;
            Ok((id_blob, state))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (id_blob, state) = row?;
            let mut arr = [0u8; 32];
            if id_blob.len() == 32 {
                arr.copy_from_slice(&id_blob);
            }
            result.push((arr, state));
        }
        Ok(result)
    }

    /// Returns the receive cursor for `coord_id`, or 0 if unset.
    pub fn get_cursor(&self, coord_id: &[u8; 32]) -> anyhow::Result<usize> {
        let key = format!("cursor:{}", hex::encode(coord_id));
        let result = self.conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![key],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match result {
            Ok(blob) => {
                let arr: [u8; 8] = blob.try_into()
                    .map_err(|_| rusqlite::Error::InvalidColumnType(0, key.clone(), rusqlite::types::Type::Blob))?;
                Ok(u64::from_le_bytes(arr) as usize)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Persists the receive cursor for `coord_id`.
    pub fn set_cursor(&self, coord_id: &[u8; 32], index: usize) -> anyhow::Result<()> {
        let key = format!("cursor:{}", hex::encode(coord_id));
        let blob = (index as u64).to_le_bytes().to_vec();
        self.conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, blob],
        )?;
        Ok(())
    }

    pub fn delete(&self, swap_id: &[u8; 32]) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM swaps WHERE swap_id = ?1",
            params![swap_id.as_ref()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [1u8; 32];
        store.save(&id, r#"{"role":"alice","state":"key_generated"}"#).unwrap();
        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded, r#"{"role":"alice","state":"key_generated"}"#);
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let store = SwapStore::open_in_memory().unwrap();
        assert!(store.load(&[0u8; 32]).unwrap().is_none());
    }

    #[test]
    fn list_all_returns_all_swaps() {
        let store = SwapStore::open_in_memory().unwrap();
        store.save(&[1u8; 32], r#"{"state":"a"}"#).unwrap();
        store.save(&[2u8; 32], r#"{"state":"b"}"#).unwrap();
        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn save_updates_existing() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [5u8; 32];
        store.save(&id, r#"{"state":"v1"}"#).unwrap();
        store.save(&id, r#"{"state":"v2"}"#).unwrap();
        let loaded = store.load(&id).unwrap().unwrap();
        assert_eq!(loaded, r#"{"state":"v2"}"#);
    }

    #[test]
    fn delete_removes_swap() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [7u8; 32];
        store.save(&id, "{}").unwrap();
        store.delete(&id).unwrap();
        assert!(store.load(&id).unwrap().is_none());
    }

    #[test]
    fn list_empty() {
        let store = SwapStore::open_in_memory().unwrap();
        assert!(store.list_all().unwrap().is_empty());
    }

    #[test]
    fn save_with_secret_stores_encrypted_blob() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [0xAA; 32];
        let secret_blob = vec![0x42u8; 60];
        store.save_with_secret(&id, r#"{"state":"locked"}"#, Some(&secret_blob)).unwrap();

        let (state, secret) = store.load_with_secret(&id).unwrap().unwrap();
        assert_eq!(state, r#"{"state":"locked"}"#);
        assert_eq!(secret.unwrap(), secret_blob);
    }

    #[test]
    fn save_with_secret_none_stores_null() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [0xBB; 32];
        store.save_with_secret(&id, r#"{"state":"init"}"#, None).unwrap();

        let (state, secret) = store.load_with_secret(&id).unwrap().unwrap();
        assert_eq!(state, r#"{"state":"init"}"#);
        assert!(secret.is_none(), "secret should be None when stored as NULL");
    }

    #[test]
    fn load_with_secret_nonexistent_returns_none() {
        let store = SwapStore::open_in_memory().unwrap();
        assert!(store.load_with_secret(&[0u8; 32]).unwrap().is_none());
    }

    #[test]
    fn get_or_create_salt_returns_consistent_16_bytes() {
        let store = SwapStore::open_in_memory().unwrap();
        let salt1 = store.get_or_create_salt().unwrap();
        let salt2 = store.get_or_create_salt().unwrap();
        assert_eq!(salt1.len(), 16);
        assert_eq!(salt1, salt2, "same store must return same salt");
    }

    #[test]
    fn cursor_default_is_zero() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [0xCCu8; 32];
        let cursor = store.get_cursor(&id).unwrap();
        assert_eq!(cursor, 0, "get_cursor on unknown coord_id must return 0");
    }

    #[test]
    fn cursor_set_then_get() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [0xDDu8; 32];
        store.set_cursor(&id, 42).unwrap();
        let cursor = store.get_cursor(&id).unwrap();
        assert_eq!(cursor, 42, "get_cursor must return previously set value");
    }

    #[test]
    fn cursor_overwrite() {
        let store = SwapStore::open_in_memory().unwrap();
        let id = [0xEEu8; 32];
        store.set_cursor(&id, 1).unwrap();
        store.set_cursor(&id, 5).unwrap();
        let cursor = store.get_cursor(&id).unwrap();
        assert_eq!(cursor, 5, "set_cursor must overwrite previous value for same coord_id");
    }

    #[test]
    fn migration_from_old_schema_succeeds() {
        // Simulate old schema without encrypted_secret column
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("
            CREATE TABLE swaps (
                swap_id BLOB PRIMARY KEY,
                state   TEXT NOT NULL,
                updated INTEGER NOT NULL
            );
        ").unwrap();
        // Insert a row with old schema
        conn.execute(
            "INSERT INTO swaps (swap_id, state, updated) VALUES (?1, ?2, ?3)",
            params![[1u8; 32].as_ref(), r#"{"old":"data"}"#, 12345i64],
        ).unwrap();
        drop(conn);

        // Now open via SwapStore (which runs migration)
        // Use a temp file to test the migration path
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("test_migration_{}.db", rand::random::<u32>()));
        let path_str = db_path.to_str().unwrap();

        // Create old schema in a temp file
        {
            let conn = Connection::open(path_str).unwrap();
            conn.execute_batch("
                CREATE TABLE swaps (
                    swap_id BLOB PRIMARY KEY,
                    state   TEXT NOT NULL,
                    updated INTEGER NOT NULL
                );
            ").unwrap();
            conn.execute(
                "INSERT INTO swaps (swap_id, state, updated) VALUES (?1, ?2, ?3)",
                params![[1u8; 32].as_ref(), r#"{"old":"data"}"#, 12345i64],
            ).unwrap();
        }

        // Open via SwapStore to trigger migration
        let store = SwapStore::open(path_str).unwrap();
        let loaded = store.load(&[1u8; 32]).unwrap().unwrap();
        assert_eq!(loaded, r#"{"old":"data"}"#);

        // Verify encrypted_secret column works after migration
        store.save_with_secret(&[1u8; 32], r#"{"new":"data"}"#, Some(&[0x42; 60])).unwrap();
        let (state, secret) = store.load_with_secret(&[1u8; 32]).unwrap().unwrap();
        assert_eq!(state, r#"{"new":"data"}"#);
        assert_eq!(secret.unwrap().len(), 60);

        // Cleanup
        let _ = std::fs::remove_file(db_path);
    }
}
