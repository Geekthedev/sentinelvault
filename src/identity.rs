use anyhow::{anyhow, Result};
use inquire::{Password, PasswordDisplayMode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::crypto::{derive_key_from_password, hash_password, verify_password, SecretKey, generate_salt};
use crate::utils::get_vault_dir;

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub password_hash: String,
    pub salt: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Identity {
    pub fn new(password: &str) -> Result<Self> {
        let password_hash = hash_password(password)?;
        let salt = generate_salt().to_vec();
        let created_at = chrono::Utc::now();
        
        Ok(Self {
            password_hash,
            salt,
            created_at,
        })
    }
    
    pub fn verify_password(&self, password: &str) -> Result<bool> {
        verify_password(password, &self.password_hash)
    }
    
    pub fn derive_key(&self, password: &str) -> Result<SecretKey> {
        if !self.verify_password(password)? {
            return Err(anyhow!("Invalid password"));
        }
        
        derive_key_from_password(password, &self.salt)
    }
    
    pub fn save(&self) -> Result<()> {
        let vault_dir = get_vault_dir()?;
        fs::create_dir_all(&vault_dir)?;
        
        let identity_path = vault_dir.join("identity.ron");
        let identity_data = ron::to_string(&self)?;
        
        fs::write(identity_path, identity_data)?;
        Ok(())
    }
    
    pub fn load() -> Result<Self> {
        let vault_dir = get_vault_dir()?;
        let identity_path = vault_dir.join("identity.ron");
        
        if !identity_path.exists() {
            return Err(anyhow!("Vault not initialized. Run 'sentinel init' first."));
        }
        
        let identity_data = fs::read_to_string(identity_path)?;
        let identity: Identity = ron::from_str(&identity_data)?;
        
        Ok(identity)
    }
    
    pub fn exists() -> bool {
        let vault_dir = get_vault_dir().ok();
        if let Some(dir) = vault_dir {
            dir.join("identity.ron").exists()
        } else {
            false
        }
    }
}

pub fn prompt_master_password() -> Result<String> {
    let password = Password::new("Enter master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;
    
    if password.len() < 8 {
        return Err(anyhow!("Password must be at least 8 characters long"));
    }
    
    Ok(password)
}

pub fn prompt_new_master_password() -> Result<String> {
    let password = Password::new("Create master password (min 8 characters):")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;
    
    if password.len() < 8 {
        return Err(anyhow!("Password must be at least 8 characters long"));
    }
    
    let confirm = Password::new("Confirm master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;
    
    if password != confirm {
        return Err(anyhow!("Passwords do not match"));
    }
    
    Ok(password)
}

pub fn authenticate() -> Result<SecretKey> {
    let identity = Identity::load()?;
    let password = prompt_master_password()?;
    
    identity.derive_key(&password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_identity_creation_and_verification() {
        let password = "test_password_123";
        let identity = Identity::new(password).unwrap();
        
        assert!(identity.verify_password(password).unwrap());
        assert!(!identity.verify_password("wrong_password").unwrap());
    }
    
    #[test]
    fn test_key_derivation() {
        let password = "test_password_123";
        let identity = Identity::new(password).unwrap();
        
        let key1 = identity.derive_key(password).unwrap();
        let key2 = identity.derive_key(password).unwrap();
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }
    
    #[test]
    fn test_identity_persistence() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let password = "test_password_123";
        let identity = Identity::new(password).unwrap();
        identity.save().unwrap();
        
        let loaded_identity = Identity::load().unwrap();
        assert!(loaded_identity.verify_password(password).unwrap());
    }
}