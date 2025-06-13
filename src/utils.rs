use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// Get the vault directory path (~/.sentinelvault)
pub fn get_vault_dir() -> Result<PathBuf> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| anyhow!("Could not determine home directory"))?;
    
    Ok(home_dir.join(".sentinelvault"))
}

/// Get the vault file path (~/.sentinelvault/vault.ron)
pub fn get_vault_path() -> Result<PathBuf> {
    Ok(get_vault_dir()?.join("vault.ron"))
}

/// Format bytes into human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;
    
    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }
    
    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Sanitize secret names to prevent path traversal
pub fn sanitize_secret_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(anyhow!("Secret name cannot be empty"));
    }
    
    if name.len() > 255 {
        return Err(anyhow!("Secret name too long (max 255 characters)"));
    }
    
    // Check for invalid characters
    let invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    if name.chars().any(|c| invalid_chars.contains(&c) || c.is_control()) {
        return Err(anyhow!("Secret name contains invalid characters"));
    }
    
    // Prevent reserved names
    let reserved_names = [".", "..", "CON", "PRN", "AUX", "NUL"];
    let upper_name = name.to_uppercase();
    if reserved_names.contains(&upper_name.as_str()) {
        return Err(anyhow!("Secret name is reserved"));
    }
    
    Ok(name.to_string())
}

/// Validate secret value
pub fn validate_secret_value(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow!("Secret value cannot be empty"));
    }
    
    if value.len() > 10_000 {
        return Err(anyhow!("Secret value too long (max 10,000 characters)"));
    }
    
    // Check for null bytes
    if value.contains('\0') {
        return Err(anyhow!("Secret value cannot contain null bytes"));
    }
    
    Ok(())
}

/// Secure string comparison to prevent timing attacks
pub fn secure_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }
    
    result == 0
}

/// Clear sensitive data from memory
pub fn clear_sensitive_data(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }
    
    #[test]
    fn test_sanitize_secret_name() {
        assert!(sanitize_secret_name("valid_name").is_ok());
        assert!(sanitize_secret_name("valid-name").is_ok());
        assert!(sanitize_secret_name("valid.name").is_ok());
        
        assert!(sanitize_secret_name("").is_err());
        assert!(sanitize_secret_name("name/with/slash").is_err());
        assert!(sanitize_secret_name("name\\with\\backslash").is_err());
        assert!(sanitize_secret_name("CON").is_err());
        assert!(sanitize_secret_name("name\0with\0null").is_err());
    }
    
    #[test]
    fn test_validate_secret_value() {
        assert!(validate_secret_value("valid_value").is_ok());
        assert!(validate_secret_value("").is_err());
        assert!(validate_secret_value("value\0with\0null").is_err());
        
        let long_value = "a".repeat(10_001);
        assert!(validate_secret_value(&long_value).is_err());
    }
    
    #[test]
    fn test_secure_compare() {
        assert!(secure_compare("hello", "hello"));
        assert!(!secure_compare("hello", "world"));
        assert!(!secure_compare("hello", "hello world"));
        assert!(!secure_compare("", "hello"));
    }
}