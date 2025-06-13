use aes_gcm::{
  aead::{Aead, AeadCore, KeyInit, OsRng},
  Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
  pub ciphertext: Vec<u8>,
  pub nonce: Vec<u8>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
  pub fn new(key: [u8; 32]) -> Self {
      Self(key)
  }
  
  pub fn as_bytes(&self) -> &[u8; 32] {
      &self.0
  }
}

pub struct CryptoEngine {
  cipher: Aes256Gcm,
}

impl CryptoEngine {
  pub fn new(key: &SecretKey) -> Self {
      let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
      let cipher = Aes256Gcm::new(cipher_key);
      
      Self { cipher }
  }
  
  pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedData> {
      let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
      let ciphertext = self.cipher
          .encrypt(&nonce, plaintext.as_bytes())
          .map_err(|e| anyhow!("Encryption failed: {}", e))?;
      
      Ok(EncryptedData {
          ciphertext,
          nonce: nonce.to_vec(),
      })
  }
  
  pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<String> {
      let nonce = Nonce::from_slice(&encrypted.nonce);
      let plaintext = self.cipher
          .decrypt(nonce, encrypted.ciphertext.as_ref())
          .map_err(|e| anyhow!("Decryption failed: {}", e))?;
      
      String::from_utf8(plaintext)
          .map_err(|e| anyhow!("Invalid UTF-8 in decrypted data: {}", e))
  }
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<SecretKey> {
  let argon2 = Argon2::default();
  let salt = SaltString::encode_b64(salt)
      .map_err(|e| anyhow!("Failed to encode salt: {}", e))?;
  
  let password_hash = argon2
      .hash_password(password.as_bytes(), &salt)
      .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
  
  let hash_bytes = password_hash.hash
      .ok_or_else(|| anyhow!("No hash in password hash"))?;
  
  if hash_bytes.len() < 32 {
      return Err(anyhow!("Hash too short for key derivation"));
  }
  
  let mut key = [0u8; 32];
  key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
  
  Ok(SecretKey::new(key))
}

pub fn verify_password(password: &str, hash_str: &str) -> Result<bool> {
  let parsed_hash = PasswordHash::new(hash_str)
      .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
  
  let argon2 = Argon2::default();
  Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

pub fn hash_password(password: &str) -> Result<String> {
  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();
  
  let password_hash = argon2
      .hash_password(password.as_bytes(), &salt)
      .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
  
  Ok(password_hash.to_string())
}

pub fn generate_salt() -> [u8; 32] {
  let mut salt = [0u8; 32];
  OsRng.fill_bytes(&mut salt);
  salt
}

pub fn encode_base64(data: &[u8]) -> String {
  general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
  general_purpose::STANDARD
      .decode(data)
      .map_err(|e| anyhow!("Base64 decode error: {}", e))
}

#[cfg(test)]
mod tests {
  use super::*;
  
  #[test]
  fn test_encryption_roundtrip() {
      let key = SecretKey::new([42u8; 32]);
      let engine = CryptoEngine::new(&key);
      let plaintext = "Hello, World!";
      
      let encrypted = engine.encrypt(plaintext).unwrap();
      let decrypted = engine.decrypt(&encrypted).unwrap();
      
      assert_eq!(plaintext, decrypted);
  }
  
  #[test]
  fn test_password_hashing() {
      let password = "test_password";
      let hash = hash_password(password).unwrap();
      
      assert!(verify_password(password, &hash).unwrap());
      assert!(!verify_password("wrong_password", &hash).unwrap());
  }
  
  #[test]
  fn test_key_derivation() {
      let password = "test_password";
      let salt = generate_salt();
      
      let key1 = derive_key_from_password(password, &salt).unwrap();
      let key2 = derive_key_from_password(password, &salt).unwrap();
      
      assert_eq!(key1.as_bytes(), key2.as_bytes());
  }
}