use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(about = "A lightweight zero-trust secrets management CLI")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault with master password
    Init,
    
    /// Add a new secret to the vault
    Add {
        /// Name of the secret
        name: String,
        /// Value of the secret (will be prompted if not provided)
        #[arg(short, long)]
        value: Option<String>,
    },
    
    /// Retrieve a secret from the vault
    Get {
        /// Name of the secret to retrieve
        name: String,
    },
    
    /// List all secret names (not values)
    List,
    
    /// Set expiration time for a secret
    Expire {
        /// Name of the secret
        name: String,
        /// Expiration duration (e.g., "10m", "1h", "1d")
        #[arg(long)]
        after: String,
    },
    
    /// Remove a secret from the vault
    Remove {
        /// Name of the secret to remove
        name: String,
    },
    
    /// Create a backup of the vault
    Backup {
        /// Output format: ron, json, qr
        #[arg(short, long, default_value = "ron")]
        format: String,
    },
    
    /// Show vault statistics
    Stats,
}