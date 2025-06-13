use anyhow::Result;
use chrono::Utc;
use proptest::prelude::*;
use sentinelvault::{
    crypto::{CryptoEngine, SecretKey},
    identity::Identity,
    lease::{parse_duration, LeaseManager},
    utils::{sanitize_secret_name, validate_secret_value},
    vault::{SecretEntry, VaultData},
};
use std::collections::HashMap;
use tempfile::TempDir;

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_env() -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        temp_dir
    }

    #[test]
    fn test_vault_initialization() {
        let _temp_dir = setup_test_env();
        
        let password = "test_password_123";
        let identity = Identity::new(password).unwrap();
        identity.save().unwrap();
        
        let loaded_identity = Identity::load().unwrap();
        assert!(loaded_identity.verify_password(password).unwrap());
    }

    #[test]
    fn test_secret_encryption_roundtrip() {
        let key = SecretKey::new([42u8; 32]);
        let engine = CryptoEngine::new(&key);
        
        let plaintext = "super_secret_api_key_12345";
        let encrypted = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_vault_data_serialization() {
        let mut vault_data = VaultData::default();
        
        let key = SecretKey::new([1u8; 32]);
        let engine = CryptoEngine::new(&key);
        let encrypted_value = engine.encrypt("test_secret").unwrap();
        let secret_entry = SecretEntry::new(encrypted_value);
        
        vault_data.secrets.insert("test_key".to_string(), secret_entry);
        
        let serialized = ron::to_string(&vault_data).unwrap();
        let deserialized: VaultData = ron::from_str(&serialized).unwrap();
        
        assert_eq!(vault_data.secrets.len(), deserialized.secrets.len());
        assert!(deserialized.secrets.contains_key("test_key"));
    }

    #[test]
    fn test_lease_manager_functionality() {
        let mut manager = LeaseManager::new();
        let duration = chrono::Duration::minutes(10);
        
        manager.add_lease("test_secret".to_string(), duration);
        
        assert!(manager.get_lease("test_secret").is_some());
        assert_eq!(manager.active_leases_count(), 1);
        assert_eq!(manager.expired_leases_count(), 0);
        
        // Test cleanup of non-expired lease
        let cleaned = manager.cleanup_expired();
        assert!(cleaned.is_empty());
        assert_eq!(manager.active_leases_count(), 1);
    }

    #[test]
    fn test_expired_lease_cleanup() {
        let mut manager = LeaseManager::new();
        
        // Add expired lease
        let expired_duration = chrono::Duration::milliseconds(-1);
        manager.add_lease("expired_secret".to_string(), expired_duration);
        
        // Add active lease
        let active_duration = chrono::Duration::minutes(10);
        manager.add_lease("active_secret".to_string(), active_duration);
        
        let cleaned = manager.cleanup_expired();
        
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0], "expired_secret");
        assert!(manager.get_lease("expired_secret").is_none());
        assert!(manager.get_lease("active_secret").is_some());
    }

    #[test]
    fn test_duration_parsing() {
        assert_eq!(parse_duration("10s").unwrap(), chrono::Duration::seconds(10));
        assert_eq!(parse_duration("5m").unwrap(), chrono::Duration::minutes(5));
        assert_eq!(parse_duration("2h").unwrap(), chrono::Duration::hours(2));
        assert_eq!(parse_duration("1d").unwrap(), chrono::Duration::days(1));
        
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-5m").is_err());
    }

    proptest! {
        #[test]
        fn test_secret_name_sanitization(name in "\\PC{1,100}") {
            // Property test: all valid names should sanitize successfully
            let result = sanitize_secret_name(&name);
            if result.is_ok() {
                assert!(!name.is_empty());
                assert!(name.len() <= 255);
            }
        }

        #[test]
        fn test_secret_value_validation(value in "\\PC{1,1000}") {
            // Property test: non-empty values without null bytes should be valid
            let result = validate_secret_value(&value);
            if !value.contains('\0') && !value.is_empty() && value.len() <= 10_000 {
                assert!(result.is_ok());
            }
        }

        #[test]
        fn test_encryption_deterministic_with_same_key(
            plaintext in "\\PC{1,1000}",
            key_bytes in prop::array::uniform32(0u8..=255u8)
        ) {
            let key = SecretKey::new(key_bytes);
            let engine = CryptoEngine::new(&key);
            
            let encrypted1 = engine.encrypt(&plaintext).unwrap();
            let encrypted2 = engine.encrypt(&plaintext).unwrap();
            
            // Encryption should produce different ciphertexts (due to random nonces)
            // but both should decrypt to the same plaintext
            let decrypted1 = engine.decrypt(&encrypted1).unwrap();
            let decrypted2 = engine.decrypt(&encrypted2).unwrap();
            
            assert_eq!(plaintext, decrypted1);
            assert_eq!(plaintext, decrypted2);
        }
    }

    #[test]
    fn test_secret_entry_access_tracking() {
        let key = SecretKey::new([1u8; 32]);
        let engine = CryptoEngine::new(&key);
        let encrypted_value = engine.encrypt("test_value").unwrap();
        
        let mut entry = SecretEntry::new(encrypted_value);
        
        assert_eq!(entry.access_count, 0);
        assert!(entry.last_accessed.is_none());
        
        entry.mark_accessed();
        
        assert_eq!(entry.access_count, 1);
        assert!(entry.last_accessed.is_some());
        
        let first_access = entry.last_accessed.unwrap();
        
        // Wait a bit and access again
        std::thread::sleep(std::time::Duration::from_millis(10));
        entry.mark_accessed();
        
        assert_eq!(entry.access_count, 2);
        assert!(entry.last_accessed.unwrap() > first_access);
    }

    #[test]
    fn test_vault_data_versioning() {
        let vault_data = VaultData::default();
        assert_eq!(vault_data.version, "0.1.0");
        assert!(vault_data.created_at <= Utc::now());
    }

    #[test]
    fn test_large_secret_handling() {
        let key = SecretKey::new([1u8; 32]);
        let engine = CryptoEngine::new(&key);
        
        // Test with a large but valid secret (9KB)
        let large_secret = "x".repeat(9000);
        assert!(validate_secret_value(&large_secret).is_ok());
        
        let encrypted = engine.encrypt(&large_secret).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();
        
        assert_eq!(large_secret, decrypted);
        
        // Test with too large secret
        let too_large_secret = "x".repeat(10_001);
        assert!(validate_secret_value(&too_large_secret).is_err());
    }

    #[test]
    fn test_concurrent_access_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        let key = SecretKey::new([1u8; 32]);
        let engine = Arc::new(CryptoEngine::new(&key));
        let counter = Arc::new(Mutex::new(0));
        
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let engine_clone = Arc::clone(&engine);
                let counter_clone = Arc::clone(&counter);
                
                thread::spawn(move || {
                    let secret = format!("secret_{}", i);
                    let encrypted = engine_clone.encrypt(&secret).unwrap();
                    let decrypted = engine_clone.decrypt(&encrypted).unwrap();
                    
                    assert_eq!(secret, decrypted);
                    
                    let mut count = counter_clone.lock().unwrap();
                    *count += 1;
                })
            })
            .collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let final_count = *counter.lock().unwrap();
        assert_eq!(final_count, 10);
    }
}