# CLI Usage Documentation

GFuel provides a comprehensive command-line interface for wallet operations, transaction management, and blockchain interactions.

## Installation and Setup

### Building the CLI

```bash
git clone https://github.com/ghostkellz/gfuel.git
cd gfuel
zig build

# CLI binary will be available at:
./zig-out/bin/gfuel
```

### Adding to PATH

```bash
# Add to your shell profile (.bashrc, .zshrc, etc.)
export PATH="$PATH:/path/to/gfuel/zig-out/bin"

# Or create symlink
sudo ln -s /path/to/gfuel/zig-out/bin/gfuel /usr/local/bin/gfuel
```

## Basic Usage

### Help and Version

```bash
# Show help
gfuel help

# Show version
gfuel version

# Show help for specific command
gfuel help send
```

### Command Structure

```bash
gfuel <COMMAND> [OPTIONS] [ARGUMENTS]
```

## Wallet Management

### Generate New Wallet

Create a new wallet with random keys:

```bash
# Generate wallet with Ed25519 keys
gfuel generate --type ed25519 --name mywalletm

# Generate wallet with secp256k1 keys
gfuel generate --type secp256k1 --name bitcoin_wallet

# Generate device-bound wallet
gfuel generate --type ed25519 --name secure_wallet --device-bound
```

**Options:**
- `--type` - Key type: `ed25519`, `secp256k1`, `curve25519`
- `--name` - Wallet name (optional)
- `--device-bound` - Create device-bound wallet
- `--output` - Output file path (default: `~/.gfuel/wallet.keystore`)

### Import from Mnemonic

Import wallet from BIP-39 mnemonic phrase:

```bash
# Import from mnemonic
gfuel import --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Import with custom name
gfuel import --mnemonic "word1 word2 ..." --name imported_wallet

# Import with passphrase
gfuel import --mnemonic "word1 word2 ..." --passphrase "additional_security"
```

**Options:**
- `--mnemonic` - BIP-39 mnemonic phrase (required)
- `--name` - Wallet name (optional)
- `--passphrase` - Additional BIP-39 passphrase (optional)
- `--output` - Output file path

### Load Existing Wallet

```bash
# Load wallet from keystore
gfuel load --file ~/.gfuel/wallet.keystore

# Load with specific name
gfuel load --file wallet.keystore --name loaded_wallet
```

## Account Management

### List Accounts

```bash
# List all accounts
gfuel accounts

# List accounts for specific protocol
gfuel accounts --protocol ghostchain

# Show detailed account information
gfuel accounts --verbose
```

### Create Accounts

```bash
# Create GhostChain account
gfuel account create --protocol ghostchain --type ed25519 --name "Main GC Account"

# Create Ethereum account
gfuel account create --protocol ethereum --type secp256k1 --name "ETH Trading"

# Create Stellar account
gfuel account create --protocol stellar --type ed25519 --name "XLM Savings"

# Create Hedera account
gfuel account create --protocol hedera --type ed25519 --name "HBAR Operations"
```

**Supported Protocols:**
- `ghostchain` - GhostChain network
- `ethereum` - Ethereum network
- `stellar` - Stellar network
- `hedera` - Hedera Hashgraph
- `ripple` - Ripple/XRP Ledger

## Balance Management

### Check Balances

```bash
# Check GCC balance
gfuel balance --token gcc

# Check ETH balance
gfuel balance --token eth --protocol ethereum

# Check all balances
gfuel balance --all

# Check balance for specific address
gfuel balance --address gc1abc123... --token gcc
```

### Update Balance (Development)

For testing and development:

```bash
# Set test balance
gfuel balance set --token gcc --amount 1000.5

# Add to existing balance
gfuel balance add --token eth --amount 0.1
```

## Transaction Operations

### Send Tokens

```bash
# Send GCC tokens
gfuel send --to gc1recipient123... --amount 100 --token gcc

# Send ETH with custom gas
gfuel send --to 0x742d35cc... --amount 0.5 --token eth --gas-price 20 --gas-limit 21000

# Send with memo
gfuel send --to gc1recipient123... --amount 50 --token gcc --memo "Payment for services"

# Send with privacy features
gfuel send --to 0x123... --amount 1 --token eth --private --identity ephemeral_tx
```

**Options:**
- `--to` - Recipient address (required)
- `--amount` - Amount to send (required)
- `--token` - Token/currency symbol (required)
- `--protocol` - Blockchain protocol (auto-detected from address)
- `--memo` - Transaction memo/message
- `--gas-price` - Gas price (Ethereum only, in gwei)
- `--gas-limit` - Gas limit (Ethereum only)
- `--private` - Use privacy features
- `--identity` - Shroud identity ID for privacy
- `--dry-run` - Simulate transaction without broadcasting

### Receive Tokens

Generate receive addresses and QR codes:

```bash
# Generate receive address for GhostChain
gfuel receive --protocol ghostchain

# Generate QR code for receiving
gfuel receive --protocol ethereum --qr

# Generate with amount and memo
gfuel receive --protocol ghostchain --amount 100 --memo "Invoice #123" --qr
```

### Transaction History

```bash
# Show transaction history
gfuel history

# Show history for specific protocol
gfuel history --protocol ethereum

# Show last N transactions
gfuel history --limit 10

# Export history to CSV
gfuel history --export transactions.csv
```

## Security Operations

### Lock/Unlock Wallet

```bash
# Lock wallet
gfuel lock

# Unlock wallet (will prompt for passphrase)
gfuel unlock

# Unlock with timeout (auto-lock after 30 minutes)
gfuel unlock --timeout 30m
```

### Change Passphrase

```bash
# Change wallet passphrase
gfuel passphrase change

# Change with backup
gfuel passphrase change --backup old_wallet.keystore
```

### Backup and Recovery

```bash
# Create encrypted backup
gfuel backup --output backup_$(date +%Y%m%d).keystore

# Export mnemonic (for recovery)
gfuel export mnemonic

# Verify backup integrity
gfuel verify --file backup.keystore
```

## Bridge and API Server

### Start Web3 Bridge

GFuel can act as a Web3 bridge for dApps:

```bash
# Start bridge on default port (8443)
gfuel bridge

# Start with custom port and HTTP/3
gfuel bridge --port 8443 --enable-http3

# Start with CORS configuration
gfuel bridge --port 8443 --cors-origin "https://app.uniswap.org,https://1inch.io"

# Start with SSL
gfuel bridge --port 8443 --ssl-cert cert.pem --ssl-key key.pem
```

**Bridge Features:**
- Web3 JSON-RPC compatibility
- Multi-protocol support
- Privacy-preserving operations
- Audit trail logging

## Privacy and Identity

### Shroud Identity Management

```bash
# Create new identity
gfuel identity create --name user_session --type ephemeral

# List identities
gfuel identity list

# Create privacy transaction
gfuel send --to 0x123... --amount 1 --token eth --identity user_session

# Generate access token
gfuel identity token --identity user_session --duration 1h
```

### Privacy Operations

```bash
# Enable privacy mode for session
gfuel privacy enable

# Create anonymous transaction
gfuel send --to gc1... --amount 100 --token gcc --anonymous

# View audit trail
gfuel audit list

# Verify audit integrity
gfuel audit verify
```

## Configuration

### Configuration File

GFuel uses a configuration file at `~/.gfuel/config.toml`:

```toml
[wallet]
default_keystore = "~/.gfuel/wallet.keystore"
auto_lock_timeout = "30m"
backup_on_change = true

[network]
default_protocol = "ghostchain"
rpc_timeout = "30s"

[privacy]
default_mode = "hybrid"
audit_logging = true
identity_rotation = "weekly"

[bridge]
default_port = 8443
enable_cors = true
allowed_origins = ["https://app.uniswap.org"]
```

### Network Configuration

```bash
# Configure custom RPC endpoints
gfuel config set ethereum.rpc_url "https://mainnet.infura.io/v3/YOUR_KEY"
gfuel config set ghostchain.rpc_url "https://rpc.ghostchain.network"

# Set default protocol
gfuel config set default_protocol ghostchain

# Enable/disable privacy features
gfuel config set privacy.enabled true
```

## Advanced Usage

### Batch Operations

```bash
# Batch send from CSV file
gfuel batch send --file transactions.csv

# CSV format: protocol,to_address,amount,token,memo
# ghostchain,gc1abc...,100,gcc,"Payment 1"
# ethereum,0x123...,0.1,eth,"Payment 2"

# Batch account creation
gfuel batch accounts --file accounts.json
```

### Scripting and Automation

```bash
#!/bin/bash
# Example: Automated balance monitoring

BALANCE=$(gfuel balance --token gcc --json | jq -r '.balance')
if (( $(echo "$BALANCE < 1000" | bc -l) )); then
    echo "Low balance alert: $BALANCE GCC"
    # Send notification or top up
fi
```

### Integration with External Tools

```bash
# Export to other formats
gfuel export --format json > wallet_data.json
gfuel export --format csv > accounts.csv

# Import from other wallets
gfuel import --format metamask --file metamask_backup.json
gfuel import --format ledger --derivation-path "m/44'/60'/0'/0/0"
```

## Output Formats

### JSON Output

Most commands support JSON output for scripting:

```bash
# JSON output
gfuel balance --token gcc --json
gfuel accounts --json
gfuel history --json

# Example JSON response
{
  "balance": "1500000000",
  "token": "gcc",
  "protocol": "ghostchain",
  "address": "gc1abc123...",
  "formatted": "1500.0 GCC"
}
```

### Table Output

Default human-readable format:

```bash
gfuel accounts
# Output:
# Protocol    | Address              | Balance     | Name
# ------------|---------------------|-------------|-------------
# ghostchain  | gc1abc123...        | 1500.0 GCC  | Main Account
# ethereum    | 0x742d35cc...       | 0.5 ETH     | ETH Trading
```

## Error Handling

### Common Errors and Solutions

```bash
# Error: Wallet locked
gfuel unlock

# Error: Insufficient balance
gfuel balance --token gcc  # Check balance first

# Error: Invalid address
# Verify address format for the protocol

# Error: Network connection
gfuel config set ethereum.rpc_url "https://alternative-rpc.com"

# Error: Permission denied
chmod +x ./zig-out/bin/gfuel
```

### Debug Mode

```bash
# Enable debug output
gfuel --debug send --to gc1... --amount 100 --token gcc

# Verbose logging
gfuel --verbose history

# Trace network requests
gfuel --trace bridge --port 8443
```

## Examples

### Daily Usage Examples

```bash
# Check all balances
gfuel balance --all

# Send payment with confirmation
gfuel send --to gc1recipient... --amount 100 --token gcc --confirm

# Start bridge for dApp interaction
gfuel bridge --port 8443 &

# Create backup before important operation
gfuel backup --output "backup_$(date +%Y%m%d_%H%M%S).keystore"
```

### Development and Testing

```bash
# Create test wallet
gfuel generate --type ed25519 --name test_wallet

# Create accounts for all protocols
for protocol in ghostchain ethereum stellar hedera ripple; do
  gfuel account create --protocol $protocol --type ed25519 --name "Test $protocol"
done

# Set test balances
gfuel balance set --token gcc --amount 10000
gfuel balance set --token eth --amount 10

# Test transaction
gfuel send --to gc1test... --amount 1 --token gcc --dry-run
```

### Privacy-Focused Operations

```bash
# Create ephemeral identity
gfuel identity create --name tx_session --type ephemeral

# Anonymous transaction
gfuel send --to 0x123... --amount 0.1 --token eth --identity tx_session --anonymous

# Verify privacy audit
gfuel audit verify --privacy-mode

# Rotate identity
gfuel identity rotate --name tx_session
```

## Shell Completions

### Bash Completion

```bash
# Generate bash completion
gfuel completion bash > /etc/bash_completion.d/gfuel

# Or for user only
gfuel completion bash > ~/.local/share/bash-completion/completions/gfuel
```

### Zsh Completion

```bash
# Generate zsh completion
gfuel completion zsh > ~/.config/zsh/completions/_gfuel

# Add to .zshrc
fpath=(~/.config/zsh/completions $fpath)
autoload -U compinit && compinit
```

## Environment Variables

```bash
# Configuration
export GFUEL_CONFIG_DIR="~/.gfuel"
export GFUEL_KEYSTORE_PATH="~/.gfuel/wallet.keystore"
export GFUEL_LOG_LEVEL="info"

# Network settings
export GFUEL_ETHEREUM_RPC="https://mainnet.infura.io/v3/YOUR_KEY"
export GFUEL_GHOSTCHAIN_RPC="https://rpc.ghostchain.network"

# Privacy settings
export GFUEL_PRIVACY_MODE="enabled"
export GFUEL_AUDIT_LOGGING="true"
```

## Performance and Optimization

### Caching

```bash
# Enable caching for faster operations
gfuel config set cache.enabled true
gfuel config set cache.duration "5m"

# Clear cache when needed
gfuel cache clear
```

### Parallel Operations

```bash
# Check multiple balances in parallel
gfuel balance --all --parallel

# Batch operations with concurrency
gfuel batch send --file transactions.csv --parallel 5
```

This completes the comprehensive CLI documentation for GFuel, covering all major features and use cases.