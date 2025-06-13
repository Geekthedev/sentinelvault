use anyhow::Result;
use clap::Parser;

mod cli;
mod crypto;
mod identity;
mod lease;
mod utils;
mod vault;

use cli::{Cli, Commands};
use vault::Vault;

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Init => {
            println!("Initializing SentinelVault...");
            Vault::init()?;
            println!("Vault initialized successfully!");
        }
        Commands::Add { name, value } => {
            let mut vault = Vault::load()?;
            let secret_value = match value {
                Some(v) => v,
                None => {
                    use inquire::{Password, PasswordDisplayMode};
                    Password::new("Enter secret value:")
                        .with_display_mode(PasswordDisplayMode::Masked)
                        .prompt()?
                }
            };
            vault.add_secret(&name, &secret_value)?;
            println!("Secret '{}' added successfully!", name);
        }
        Commands::Get { name } => {
            let vault = Vault::load()?;
            match vault.get_secret(&name)? {
                Some(value) => println!("{}", value),
                None => println!("Secret '{}' not found", name),
            }
        }
        Commands::List => {
            let vault = Vault::load()?;
            let secrets = vault.list_secrets()?;
            if secrets.is_empty() {
                println!("No secrets stored in vault");
            } else {
                println!("Stored secrets:");
                for (name, expires_at) in secrets {
                    match expires_at {
                        Some(exp) => println!("  • {} (expires: {})", name, exp.format("%Y-%m-%d %H:%M:%S")),
                        None => println!("  • {} (no expiration)", name),
                    }
                }
            }
        }
        Commands::Expire { name, after } => {
            let mut vault = Vault::load()?;
            vault.set_expiry(&name, &after)?;
            println!("Set expiry for '{}' to {}", name, after);
        }
        Commands::Remove { name } => {
            let mut vault = Vault::load()?;
            if vault.remove_secret(&name)? {
                println!("Secret '{}' removed successfully!", name);
            } else {
                println!("Secret '{}' not found", name);
            }
        }
        Commands::Backup { format } => {
            let vault = Vault::load()?;
            let backup_data = vault.create_backup()?;
            
            match format.as_str() {
                "json" => {
                    let json_backup = serde_json::to_string_pretty(&backup_data)?;
                    println!("{}", json_backup);
                }
                #[cfg(feature = "qr-backup")]
                "qr" => {
                    use qrcode::QrCode;
                    let backup_str = ron::to_string(&backup_data)?;
                    let code = QrCode::new(&backup_str)?;
                    let string = code.render::<char>()
                        .quiet_zone(false)
                        .module_dimensions(2, 1)
                        .build();
                    println!("{}", string);
                }
                _ => {
                    let ron_backup = ron::to_string(&backup_data)?;
                    println!("{}", ron_backup);
                }
            }
        }
        Commands::Stats => {
            let vault = Vault::load()?;
            let stats = vault.get_stats()?;
            println!("Vault Statistics:");
            println!("  Total secrets: {}", stats.total_secrets);
            println!("  Active leases: {}", stats.active_leases);
            println!("  Expired secrets: {}", stats.expired_secrets);
            println!("  Vault size: {} bytes", stats.vault_size);
        }
    }
    
    Ok(())
}
