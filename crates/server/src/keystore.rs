use std::collections::HashMap;
use std::path::{Path, PathBuf};

use picrypt_common::crypto;
use picrypt_common::error::PicryptError;
use picrypt_common::protocol::DeviceRecord;
use uuid::Uuid;

/// Persistent storage for encrypted device records and master key material.
///
/// On-disk layout under `data_dir`:
/// ```text
/// data/
/// ├── kdf_params.json                  # Argon2id salt + cost params
/// ├── encrypted_master_key_pw.bin      # Master key encrypted with password-derived key
/// ├── encrypted_master_key_yk.bin      # Master key encrypted with YubiKey-derived key
/// ├── yubikey_challenge.bin            # Challenge for YubiKey HMAC-SHA1
/// └── devices/
///     ├── {uuid1}.json
///     └── {uuid2}.json
/// ```
pub struct KeyStore {
    data_dir: PathBuf,
}

impl KeyStore {
    pub fn new(data_dir: &Path) -> Result<Self, PicryptError> {
        let devices_dir = data_dir.join("devices");
        std::fs::create_dir_all(&devices_dir).map_err(|e| {
            PicryptError::Storage(format!(
                "failed to create devices directory {}: {e}",
                devices_dir.display()
            ))
        })?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
        })
    }

    // -----------------------------------------------------------------------
    // Master key storage
    // -----------------------------------------------------------------------

    /// Save the master key encrypted with a password-derived key.
    pub fn save_encrypted_master_key_password(&self, encrypted: &[u8]) -> Result<(), PicryptError> {
        self.write_file("encrypted_master_key_pw.bin", encrypted)
    }

    /// Load the password-encrypted master key, if it exists.
    pub fn load_encrypted_master_key_password(&self) -> Result<Option<Vec<u8>>, PicryptError> {
        self.read_file_optional("encrypted_master_key_pw.bin")
    }

    /// Save the master key encrypted with a YubiKey-derived key.
    pub fn save_encrypted_master_key_yubikey(&self, encrypted: &[u8]) -> Result<(), PicryptError> {
        self.write_file("encrypted_master_key_yk.bin", encrypted)
    }

    /// Load the YubiKey-encrypted master key, if it exists.
    pub fn load_encrypted_master_key_yubikey(&self) -> Result<Option<Vec<u8>>, PicryptError> {
        self.read_file_optional("encrypted_master_key_yk.bin")
    }

    /// Save the YubiKey challenge.
    pub fn save_yubikey_challenge(&self, challenge: &[u8]) -> Result<(), PicryptError> {
        self.write_file("yubikey_challenge.bin", challenge)
    }

    /// Load the YubiKey challenge, if it exists.
    pub fn load_yubikey_challenge(&self) -> Result<Option<Vec<u8>>, PicryptError> {
        self.read_file_optional("yubikey_challenge.bin")
    }

    // -----------------------------------------------------------------------
    // KDF params
    // -----------------------------------------------------------------------

    pub fn load_kdf_params(&self) -> Result<Option<crypto::KeyDerivationParams>, PicryptError> {
        let path = self.data_dir.join("kdf_params.json");
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| PicryptError::Storage(format!("failed to read kdf params: {e}")))?;
        let params: crypto::KeyDerivationParams = serde_json::from_str(&contents)?;
        Ok(Some(params))
    }

    pub fn save_kdf_params(
        &self,
        params: &crypto::KeyDerivationParams,
    ) -> Result<(), PicryptError> {
        let path = self.data_dir.join("kdf_params.json");
        let contents = serde_json::to_string_pretty(params)?;
        std::fs::write(&path, contents)
            .map_err(|e| PicryptError::Storage(format!("failed to write kdf params: {e}")))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Device records
    // -----------------------------------------------------------------------

    pub fn load_all_devices(&self) -> Result<HashMap<Uuid, DeviceRecord>, PicryptError> {
        let devices_dir = self.data_dir.join("devices");
        let mut devices = HashMap::new();

        let entries = std::fs::read_dir(&devices_dir).map_err(|e| {
            PicryptError::Storage(format!(
                "failed to read devices directory {}: {e}",
                devices_dir.display()
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| PicryptError::Storage(e.to_string()))?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "json") {
                let contents = std::fs::read_to_string(&path).map_err(|e| {
                    PicryptError::Storage(format!(
                        "failed to read device record {}: {e}",
                        path.display()
                    ))
                })?;

                let record: DeviceRecord = serde_json::from_str(&contents).map_err(|e| {
                    PicryptError::Storage(format!(
                        "failed to parse device record {}: {e}",
                        path.display()
                    ))
                })?;

                devices.insert(record.id, record);
            }
        }

        tracing::info!("loaded {} device records from disk", devices.len());
        Ok(devices)
    }

    pub fn save_device(&self, record: &DeviceRecord) -> Result<(), PicryptError> {
        let path = self
            .data_dir
            .join("devices")
            .join(format!("{}.json", record.id));
        let contents = serde_json::to_string_pretty(record)?;
        std::fs::write(&path, &contents).map_err(|e| {
            PicryptError::Storage(format!(
                "failed to write device record to {}: {e}",
                path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(|e| {
                PicryptError::Storage(format!(
                    "failed to set permissions on {}: {e}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    pub fn delete_device(&self, device_id: &Uuid) -> Result<(), PicryptError> {
        let path = self
            .data_dir
            .join("devices")
            .join(format!("{device_id}.json"));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                PicryptError::Storage(format!(
                    "failed to delete device record {}: {e}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Initialization check
    // -----------------------------------------------------------------------

    /// Server is initialized if at least one encrypted master key exists.
    pub fn is_initialized(&self) -> bool {
        self.data_dir.join("encrypted_master_key_pw.bin").exists()
            || self.data_dir.join("encrypted_master_key_yk.bin").exists()
    }

    /// Check if password-based unseal is available.
    pub fn has_password_unseal(&self) -> bool {
        self.data_dir.join("encrypted_master_key_pw.bin").exists()
    }

    /// Check if YubiKey-based unseal is available.
    pub fn has_yubikey_unseal(&self) -> bool {
        self.data_dir.join("encrypted_master_key_yk.bin").exists()
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn write_file(&self, name: &str, data: &[u8]) -> Result<(), PicryptError> {
        let path = self.data_dir.join(name);
        std::fs::write(&path, data).map_err(|e| {
            PicryptError::Storage(format!("failed to write {}: {e}", path.display()))
        })?;
        // Set restrictive permissions (owner read/write only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(|e| {
                PicryptError::Storage(format!(
                    "failed to set permissions on {}: {e}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    fn read_file_optional(&self, name: &str) -> Result<Option<Vec<u8>>, PicryptError> {
        let path = self.data_dir.join(name);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).map_err(|e| {
            PicryptError::Storage(format!("failed to read {}: {e}", path.display()))
        })?;
        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use picrypt_common::protocol::Platform;
    use tempfile::TempDir;

    fn make_device_record(name: &str) -> DeviceRecord {
        DeviceRecord {
            id: Uuid::new_v4(),
            name: name.to_string(),
            platform: Platform::Linux,
            token_hash: vec![0xAA; 32],
            encrypted_keyfile: vec![0xBB; 64],
            revoked: false,
            registered_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn new_creates_directories() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let data_dir = tmp.path().join("data");
        let _ks = KeyStore::new(&data_dir).expect("KeyStore::new failed");

        let devices_dir = data_dir.join("devices");
        assert!(devices_dir.exists(), "devices directory must be created");
        assert!(devices_dir.is_dir(), "devices path must be a directory");
    }

    #[test]
    fn save_and_load_device() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        let record = make_device_record("test-laptop");
        ks.save_device(&record).expect("save_device failed");

        let all = ks.load_all_devices().expect("load_all_devices failed");
        assert_eq!(all.len(), 1);

        let loaded = all.get(&record.id).expect("device not found after load");
        assert_eq!(loaded.name, "test-laptop");
        assert_eq!(loaded.id, record.id);
        assert_eq!(loaded.token_hash, record.token_hash);
    }

    #[test]
    fn load_all_devices_empty() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        let devices = ks.load_all_devices().expect("load_all_devices failed");
        assert!(devices.is_empty(), "fresh keystore should have no devices");
    }

    #[test]
    fn load_all_devices_multiple() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        for name in ["device-a", "device-b", "device-c"] {
            let record = make_device_record(name);
            ks.save_device(&record).expect("save_device failed");
        }

        let all = ks.load_all_devices().expect("load_all_devices failed");
        assert_eq!(all.len(), 3, "should have exactly 3 devices");
    }

    #[test]
    fn save_load_kdf_params() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        let params = crypto::KeyDerivationParams::generate();
        ks.save_kdf_params(&params).expect("save_kdf_params failed");

        let loaded = ks
            .load_kdf_params()
            .expect("load_kdf_params failed")
            .expect("kdf params should exist after save");

        assert_eq!(loaded.salt, params.salt);
        assert_eq!(loaded.time_cost, params.time_cost);
        assert_eq!(loaded.memory_cost, params.memory_cost);
        assert_eq!(loaded.parallelism, params.parallelism);
    }

    #[test]
    fn save_load_encrypted_master_key() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        let pw_data = vec![0x11u8; 48];
        ks.save_encrypted_master_key_password(&pw_data)
            .expect("save pw master key failed");
        let loaded_pw = ks
            .load_encrypted_master_key_password()
            .expect("load pw master key failed")
            .expect("pw master key should exist");
        assert_eq!(loaded_pw, pw_data);

        let yk_data = vec![0x22u8; 48];
        ks.save_encrypted_master_key_yubikey(&yk_data)
            .expect("save yk master key failed");
        let loaded_yk = ks
            .load_encrypted_master_key_yubikey()
            .expect("load yk master key failed")
            .expect("yk master key should exist");
        assert_eq!(loaded_yk, yk_data);
    }

    #[test]
    fn is_initialized_false_initially() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        assert!(
            !ks.is_initialized(),
            "fresh keystore should not be initialized"
        );
    }

    #[test]
    fn is_initialized_after_save() {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        ks.save_encrypted_master_key_password(&[0xFFu8; 48])
            .expect("save failed");
        assert!(
            ks.is_initialized(),
            "keystore should be initialized after saving master key"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("failed to create temp dir");
        let ks = KeyStore::new(tmp.path()).expect("KeyStore::new failed");

        // Test with a device file
        let record = make_device_record("perm-test");
        ks.save_device(&record).expect("save_device failed");

        let device_path = tmp
            .path()
            .join("devices")
            .join(format!("{}.json", record.id));
        let mode = std::fs::metadata(&device_path)
            .expect("metadata failed")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "device file should have mode 0600, got {mode:o}"
        );

        // Test with a binary file via write_file (e.g., encrypted master key)
        ks.save_encrypted_master_key_password(&[0xAA; 32])
            .expect("save master key failed");
        let mk_path = tmp.path().join("encrypted_master_key_pw.bin");
        let mk_mode = std::fs::metadata(&mk_path)
            .expect("metadata failed")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mk_mode, 0o600,
            "master key file should have mode 0600, got {mk_mode:o}"
        );
    }
}
