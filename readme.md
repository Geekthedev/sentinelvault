

# SentinelVault

**A Lightweight Zero-Trust Secrets Management CLI in Rust**

SentinelVault is a minimalist, command-line secrets manager that provides secure, encrypted storage for your sensitive data like API keys, tokens, and passwords. Built with a zero-trust, local-first approach.

---

## Features

* **Zero-Trust Security**: Every secret is encrypted with AES-256-GCM
* **Local-First**: No network dependencies, works completely offline
* **Time-Based Leases**: Automatically expire secrets after specified durations
* **Master Password Protection**: Single password protects your entire vault
* **Encrypted Storage**: All data encrypted at rest using industry-standard cryptography
* **Single Binary**: Self-contained CLI with no external dependencies
* **Usage Statistics**: Track vault usage and active leases
* **Secure Backups**: Export encrypted vault data with optional QR codes

---

## Installation

### From Source

```bash
git clone https://github.com/yourusername/sentinelvault.git
cd sentinelvault
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
```

### Using Cargo

```bash
cargo install sentinelvault
```

---

## Quick Start

### 1. Initialize Your Vault

```bash
sentinel init
```

You'll be prompted to create a master password. This password encrypts your entire vault.

### 2. Add Your First Secret

```bash
# Add a secret interactively (value will be masked)
sentinel add "github_token"

# Or provide the value directly
sentinel add "api_key" --value "sk-1234567890abcdef"
```

### 3. Retrieve Secrets

```bash
# Get a secret value
sentinel get "github_token"

# List all secret names (not values)
sentinel list
```

### 4. Set Expiration Times

```bash
# Expire after 10 minutes
sentinel expire "temp_token" --after 10m

# Expire after 1 hour
sentinel expire "session_key" --after 1h

# Expire after 7 days
sentinel expire "backup_key" --after 7d
```

---

## Command Reference

### Core Commands

| Command                  | Description            | Example                     |
| ------------------------ | ---------------------- | --------------------------- |
| `sentinel init`          | Initialize a new vault | `sentinel init`             |
| `sentinel add <name>`    | Add a new secret       | `sentinel add "my_key"`     |
| `sentinel get <name>`    | Retrieve a secret      | `sentinel get "my_key"`     |
| `sentinel list`          | List all secret names  | `sentinel list`             |
| `sentinel remove <name>` | Delete a secret        | `sentinel remove "old_key"` |

### Lease Management

| Command                                     | Description    | Example                              |
| ------------------------------------------- | -------------- | ------------------------------------ |
| `sentinel expire <name> --after <duration>` | Set expiration | `sentinel expire "temp" --after 30m` |

### Utility Commands

| Command           | Description             | Example                         |
| ----------------- | ----------------------- | ------------------------------- |
| `sentinel stats`  | Show vault statistics   | `sentinel stats`                |
| `sentinel backup` | Create encrypted backup | `sentinel backup --format json` |

### Duration Formats

* **Seconds**: `30s`, `seconds`, `sec`
* **Minutes**: `10m`, `minutes`, `min`
* **Hours**: `2h`, `hours`, `hour`
* **Days**: `7d`, `days`, `day`
* **Weeks**: `2w`, `weeks`, `week`

---

## Security Model

### Encryption

* **Algorithm**: AES-256-GCM with authenticated encryption
* **Key Derivation**: Argon2 password hashing with random salts
* **Nonces**: Cryptographically secure random nonces for each encryption

### Storage

* **Location**: `~/.sentinelvault/`

  * `identity.ron` - Encrypted identity and salt
  * `vault.ron` - Encrypted secrets database
* **Permissions**: Files created with restrictive permissions (600)

### Zero-Trust Principles

* Secrets never stored in plaintext
* Master password required for every operation
* Memory cleared after sensitive operations
* No network communication

---

## Vault Structure

```
~/.sentinelvault/
├── identity.ron      # Master password hash and salt
└── vault.ron         # Encrypted secrets and metadata
```

---

## Configuration

SentinelVault works out of the box with sensible defaults:

* **Vault Location**: `~/.sentinelvault/`
* **Encryption**: AES-256-GCM
* **Password Hashing**: Argon2 with secure defaults
* **Max Secret Size**: 10,000 characters
* **Max Secret Name**: 255 characters

---

## Development

### Building

```bash
cargo build
```

### Testing

```bash
# Run unit tests
cargo test

# Run property-based tests
cargo test --features proptest

# Run with QR code support
cargo build --features qr-backup
```

### Linting

```bash
cargo clippy
cargo fmt
```

---

## Statistics Example

```bash
$ sentinel stats
Vault Statistics:
  Total secrets: 15
  Active leases: 3  
  Expired secrets: 1
  Vault size: 2.3 KB
```

---

## Best Practices

1. Use a unique, strong password for your vault
2. Periodically backup your vault data
3. Set appropriate expiration times for temporary secrets
4. Run commands in a secure terminal environment
5. Remove unused secrets to minimize attack surface

---

## Troubleshooting

### Common Issues

**"Vault not initialized"**

```bash
sentinel init
```

**"Invalid password"**
Double-check your master password. There's no recovery mechanism by design.

**"Permission denied"**
Ensure proper file permissions on vault directory:

```bash
chmod 700 ~/.sentinelvault
chmod 600 ~/.sentinelvault/*
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is Open Source.

---

## Disclaimer

SentinelVault is designed for secure local secret storage. While the author follow security best practices, please evaluate the tool's suitability for your specific security requirements. The author is not responsible for any data loss or security breaches.

---
