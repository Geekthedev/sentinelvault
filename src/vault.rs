use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use inquire::{Password, PasswordDisplayMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use crate::crypto::{CryptoEngine, EncryptedData, SecretKey};
use crate::identity::{authenticate, prompt_new_master_password, Identity};
use crate::lease::{parse_duration, Lease, LeaseManager};
use crate::utils::{get_vault_path, sanitize_secret_name, validate_secret_value, format_bytes};

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretEntry {
    pub encrypted_value: EncryptedData,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub access_count: u64,
    pub last_accessed: Option<DateTime<Utc>>,
}

impl SecretEntry {
    pub fn new(encrypted_value: EncryptedData) -> Self {
        let now = Utc::now();
        Self {
            encrypted_value,
            created_at: now,
            updated_at: now,
            access_count: 0,
            last_accessed: None,
        }
    }
    
    pub fn mark_accessed(&mut self) {
        self.access_count += 1;
        self.last_accessed = Some(Utc::now());
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultData {
    pub secrets: HashMap<String, SecretEntry>,
    pub lease_manager: LeaseManager,
    pub created_at: DateTime<Utc>,
    pub version: String,
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            secrets: HashMap::new(),
            lease_manager: LeaseManager::new(),
            created_at: Utc::now(),
            version: "0.1.0".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct VaultStats {
    pub total_secrets: usize,
    pub active_leases: usize,
    pub expired_secrets: usize,
    pub vault_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupData {
    pub vault_data: VaultData,
    pub identity_hash: String,
    pub created_at: DateTime<Utc>,
    pub version: String,
}

pub struct Vault {
    data: VaultData,
    crypto_engine: CryptoEngine,
}

impl Vault {
    pub fn init() -> Result<()> {
        if Identity::exists() {
            return Err(anyhow!("Vault already initialized. Use 'sentinel add' to add secrets."));
        }
        
        let password = prompt_new_master_password()?;
        let identity = Identity::new(&password)?;
        identity.save()?;
        
        let vault_data = VaultData::default();
        let vault_data_str = ron::to_string(&vault_data)?;
        
        let vault_path = get_vault_path()?;
        if let Some(parent) = vault_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        fs::write(vault_path, vault_data_str)?;
        
        Ok(())
    }
    
    pub fn load() -> Result<Self> {
        let key = authenticate()?;
        let crypto_engine = CryptoEngine::new(&key);
        
        let vault_path = get_vault_path()?;
        
        if !vault_path.exists() {
            return Err(anyhow!("Vault file not found. Run 'sentinel init' first."));
        }
        
        let vault_data_str = fs::read_to_string(vault_path)?;
        let mut data: VaultData = ron::from_str(&vault_data_str)?;
        
        // Clean up expired secrets
        let expired_secrets = data.lease_manager.cleanup_expired();
        for secret_name in expired_secrets {
            data.secrets.remove(&secret_name);
        }
        
        Ok(Self {
            data,
            crypto_engine,
        })
    }
    
    pub fn save(&self) -> Result<()> {
        let vault_path = get_vault_path()?;
        let vault_data_str = ron::to_string(&self.data)?;
        fs::write(vault_path, vault_data_str)?;
        Ok(())
    }
    
    pub fn add_secret(&mut self, name: &str, value: &str) -> Result<()> {
        let name = sanitize_secret_name(name)?;
        validate_secret_value(value)?;
        
        let encrypted_value = self.crypto_engine.encrypt(value)?;
        let secret_entry = SecretEntry::new(encrypted_value);
        
        self.data.secrets.insert(name.clone(), secret_entry);
        self.save()?;
        
        Ok(())
    }
    
    pub fn get_secret(&self, name: &str) -> Result<Option<String>> {
        let name = sanitize_secret_name(name)?;
        
        if let Some(mut entry) = self.data.secrets.get(&name).cloned() {
            // Check if secret has expired
            if let Some(lease) = self.data.lease_manager.get_lease(&name) {
                if lease.is_expired() {
                    return Ok(None);
                }
            }
            
            let decrypted = self.crypto_engine.decrypt(&entry.encrypted_value)?;
            
            // Update access statistics (we can't modify self here, so we'll skip this for now)
            // In a real implementation, you might want to handle this differently
            
            Ok(Some(decrypted))
        } else {
            Ok(None)
        }
    }
    
    pub fn list_secrets(&self) -> Result<Vec<(String, Option<DateTime<Utc>>)>> {
        let mut secrets = Vec::new();
        
        for (name, _) in &self.data.secrets {
            // Check if secret has expired
            let expires_at = if let Some(lease) = self.data.lease_manager.get_lease(name) {
                if lease.is_expired() {
                    continue; // Skip expired secrets
                }
                Some(lease.expires_at)
            } else {
                None
            };
            
            secrets.push((name.clone(), expires_at));
        }
        
        secrets.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(secrets)
    }
    
    pub fn remove_secret(&mut self, name: &str) -> Result<bool> {
        let name = sanitize_secret_name(name)?;
        
        let removed = self.data.secrets.remove(&name).is_some();
        self.data.lease_manager.remove_lease(&name);
        
        if removed {
            self.save()?;
        }
        
        Ok(removed)
    }
    
    pub fn set_expiry(&mut self, name: &str, duration_str: &str) -> Result<()> {
        let name = sanitize_secret_name(name)?;
        
        if !self.data.secrets.contains_key(&name) {
            return Err(anyhow!("Secret '{}' not found", name));
        }
        
        let duration = parse_duration(duration_str)?;
        self.data.lease_manager.add_lease(name, duration);
        
        self.save()?;
        Ok(())
    }
    
    pub fn create_backup(&self) -> Result<BackupData> {
        let identity = Identity::load()?;
        
        Ok(BackupData {
            vault_data: self.data.clone(),
            identity_hash: identity.password_hash.clone(),
            created_at: Utc::now(),
            version: "0.1.0".to_string(),
        })
    }
    
    pub fn get_stats(&self) -> Result<VaultStats> {
        let vault_path = get_vault_path()?;
        let vault_size = if vault_path.exists() {
            fs::metadata(vault_path)?.len()
        } else {
            0
        };
        
        let total_secrets = self.data.secrets.len();
        let active_leases = self.data.lease_manager.active_leases_count();
        let expired_secrets = self.data.lease_manager.expired_leases_count();
        
        Ok(VaultStats {
            total_secrets,
            active_leases,
            expired_secrets,
            vault_size,
        })
    }
}

// Update CLI to handle missing value parameter
impl crate::cli::Commands {
    pub fn get_secret_value(&self) -> Result<String> {
        match self {
            crate::cli::Commands::Add { value: Some(v), .. } => Ok(v.clone()),
            crate::cli::Commands::Add { value: None, .. } => {
                let secret_value = Password::new("Enter secret value:")
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .prompt()?;
                
                if secret_value.is_empty() {
                    return Err(anyhow!("Secret value cannot be empty"));
                }
                
                Ok(secret_value)
            }
            _ => Err(anyhow!("Not an add command")),
        }
    }
}