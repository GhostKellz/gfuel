# Getting Started with GFuel

This guide will help you get up and running with GFuel, a secure wallet implementation for Zig.

## Installation

### Prerequisites

- Zig 0.16.0 or later
- Git

### Building from Source

```bash
git clone https://github.com/ghostkellz/gfuel.git
cd gfuel
zig build
```

### Dependencies

GFuel automatically fetches its dependencies via Zig's package manager:

- **zledger v0.5.0** - Cryptographic operations with integrated zsig
- **shroud** - Privacy and identity management

## Basic Usage

### Creating Your First Wallet

```zig
const std = @import("std");
const gfuel = @import("gfuel");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new hybrid wallet
    var wallet = try gfuel.wallet.Wallet.create(
        allocator,
        "your_secure_passphrase",
        .hybrid,
        null  // keystore path (optional)
    );
    defer wallet.deinit();

    std.debug.print("Wallet created successfully!\n", .{});
}
```

### Wallet Modes

GFuel supports different wallet modes for various security requirements:

- **`.hybrid`** - Balanced security and functionality
- **`.public_identity`** - Public operations with full transparency
- **`.private_cold`** - Cold storage with minimal network interaction
- **`.privacy_focused`** - Maximum privacy with Shroud integration

### Creating Accounts

```zig
// Create accounts for different protocols
try wallet.createAccount(.ghostchain, .ed25519, "Main GhostChain Account");
try wallet.createAccount(.ethereum, .secp256k1, "Ethereum Account");
try wallet.createAccount(.stellar, .ed25519, "Stellar Account");

// List all accounts
for (wallet.accounts.items, 0..) |account, i| {
    std.debug.print("Account {}: {} - {s}\n", .{
        i + 1,
        account.protocol,
        account.address
    });
}
```

### Protocol Support

GFuel supports multiple blockchain protocols:

| Protocol | Key Types | Currency |
|----------|-----------|----------|
| GhostChain | Ed25519, secp256k1 | GCC |
| Ethereum | secp256k1 | ETH |
| Stellar | Ed25519 | XLM |
| Hedera | Ed25519 | HBAR |
| Ripple | secp256k1, Ed25519 | XRP |

### Creating Transactions

```zig
const tx = try gfuel.transaction.ProtocolFactory.createTransaction(
    allocator,
    .ethereum,
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",  // from
    "0x123...",  // to
    1000000000000000000  // 1 ETH in wei
);
defer tx.deinit(allocator);

// Sign the transaction
const private_key = "your_private_key_here";
try tx.sign(allocator, private_key);
```

## CLI Usage

GFuel includes a command-line interface for wallet operations:

```bash
# Generate a new wallet
./zig-out/bin/gfuel generate --type ed25519 --name mywalletm

# Check balance
./zig-out/bin/gfuel balance --token gcc

# Send tokens
./zig-out/bin/gfuel send --to recipient_address --amount 100 --token gcc

# Show help
./zig-out/bin/gfuel help
```

## Examples

Run the included examples to see GFuel in action:

```bash
# Basic wallet operations
./zig-out/bin/gfuel_example

# Privacy features with Shroud
./zig-out/bin/gfuel_shroud_cli
```

## Next Steps

- Read the [Wallet API](wallet-api.md) documentation for detailed usage
- Explore [Privacy Features](privacy.md) for Shroud integration
- Check out [Transaction API](transaction-api.md) for advanced transaction handling
- See [Examples](examples.md) for more code samples

## Security Considerations

- Always use strong passphrases for wallet creation
- Store wallet files securely and create backups
- Verify transaction details before signing
- Use privacy modes when anonymity is required
- Keep your private keys secure and never share them

## Troubleshooting

### Build Issues

If you encounter build issues:

1. Ensure you have Zig 0.16.0 or later
2. Clear the cache: `zig build clean`
3. Rebuild: `zig build`

### Memory Issues

If you see memory leaks in examples, this is typically from zledger library usage and doesn't affect core functionality.

### Version Compatibility

Make sure you're using compatible versions:
- GFuel: latest
- zledger: v0.5.0
- shroud: latest compatible version