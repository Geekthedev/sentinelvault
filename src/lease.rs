use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lease {
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Lease {
    pub fn new(duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            expires_at: now + duration,
            created_at: now,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
    
    pub fn time_remaining(&self) -> Option<Duration> {
        let now = Utc::now();
        if now < self.expires_at {
            Some(self.expires_at - now)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LeaseManager {
    leases: HashMap<String, Lease>,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
        }
    }
    
    pub fn add_lease(&mut self, secret_name: String, duration: Duration) {
        let lease = Lease::new(duration);
        self.leases.insert(secret_name, lease);
    }
    
    pub fn get_lease(&self, secret_name: &str) -> Option<&Lease> {
        self.leases.get(secret_name)
    }
    
    pub fn remove_lease(&mut self, secret_name: &str) -> Option<Lease> {
        self.leases.remove(secret_name)
    }
    
    pub fn get_expired_secrets(&self) -> Vec<String> {
        self.leases
            .iter()
            .filter(|(_, lease)| lease.is_expired())
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    pub fn cleanup_expired(&mut self) -> Vec<String> {
        let expired = self.get_expired_secrets();
        for name in &expired {
            self.leases.remove(name);
        }
        expired
    }
    
    pub fn active_leases_count(&self) -> usize {
        self.leases
            .values()
            .filter(|lease| !lease.is_expired())
            .count()
    }
    
    pub fn expired_leases_count(&self) -> usize {
        self.leases
            .values()
            .filter(|lease| lease.is_expired())
            .count()
    }
    
    pub fn list_active_leases(&self) -> Vec<(String, &Lease)> {
        self.leases
            .iter()
            .filter(|(_, lease)| !lease.is_expired())
            .map(|(name, lease)| (name.clone(), lease))
            .collect()
    }
}

pub fn parse_duration(duration_str: &str) -> Result<Duration> {
    let duration_str = duration_str.trim();
    
    if duration_str.is_empty() {
        return Err(anyhow!("Duration cannot be empty"));
    }
    
    let (number_part, unit_part) = if let Some(pos) = duration_str.rfind(char::is_alphabetic) {
        let split_pos = duration_str.len() - duration_str[pos..].len() + 1;
        (
            &duration_str[..split_pos - 1],
            &duration_str[split_pos - 1..],
        )
    } else {
        return Err(anyhow!("Duration must include a unit (s, m, h, d)"));
    };
    
    let number: i64 = number_part
        .parse()
        .map_err(|_| anyhow!("Invalid number in duration: {}", number_part))?;
    
    if number <= 0 {
        return Err(anyhow!("Duration must be positive"));
    }
    
    let duration = match unit_part.to_lowercase().as_str() {
        "s" | "sec" | "seconds" => Duration::seconds(number),
        "m" | "min" | "minutes" => Duration::minutes(number),
        "h" | "hour" | "hours" => Duration::hours(number),
        "d" | "day" | "days" => Duration::days(number),
        "w" | "week" | "weeks" => Duration::weeks(number),
        _ => return Err(anyhow!("Invalid duration unit: {}. Use s, m, h, d, or w", unit_part)),
    };
    
    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lease_creation() {
        let duration = Duration::minutes(10);
        let lease = Lease::new(duration);
        
        assert!(!lease.is_expired());
        assert!(lease.time_remaining().is_some());
    }
    
    #[test]
    fn test_lease_expiry() {
        let duration = Duration::milliseconds(-1);
        let lease = Lease::new(duration);
        
        assert!(lease.is_expired());
        assert!(lease.time_remaining().is_none());
    }
    
    #[test]
    fn test_lease_manager() {
        let mut manager = LeaseManager::new();
        let duration = Duration::minutes(10);
        
        manager.add_lease("test_secret".to_string(), duration);
        
        assert!(manager.get_lease("test_secret").is_some());
        assert_eq!(manager.active_leases_count(), 1);
        assert_eq!(manager.expired_leases_count(), 0);
    }
    
    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::seconds(10));
        assert_eq!(parse_duration("5m").unwrap(), Duration::minutes(5));
        assert_eq!(parse_duration("2h").unwrap(), Duration::hours(2));
        assert_eq!(parse_duration("1d").unwrap(), Duration::days(1));
        assert_eq!(parse_duration("3w").unwrap(), Duration::weeks(3));
        
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("-5m").is_err());
    }
    
    #[test]
    fn test_cleanup_expired() {
        let mut manager = LeaseManager::new();
        
        // Add an expired lease
        manager.add_lease("expired".to_string(), Duration::milliseconds(-1));
        // Add an active lease
        manager.add_lease("active".to_string(), Duration::minutes(10));
        
        let expired = manager.cleanup_expired();
        
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "expired");
        assert!(manager.get_lease("expired").is_none());
        assert!(manager.get_lease("active").is_some());
    }
}