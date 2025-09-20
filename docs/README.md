# GFuel Documentation

GFuel is a secure, programmable wallet for Zig with multi-protocol support, privacy features, and cryptographic audit trails.

## Table of Contents

- [Getting Started](getting-started.md)
- [Wallet API](wallet-api.md)
- [Cryptography](crypto-api.md)
- [Transactions](transaction-api.md)
- [Protocol Support](protocols.md)
- [Privacy Features](privacy.md)
- [FFI Integration](ffi-api.md)
- [CLI Usage](cli-usage.md)
- [Examples](examples.md)
- [Migration Guide](migration.md)

## Quick Start

```zig
const std = @import("std");
const gfuel = @import("gfuel");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new wallet
    var wallet = try gfuel.wallet.Wallet.create(
        allocator,
        "secure_passphrase",
        .hybrid,
        null
    );
    defer wallet.deinit();

    // Create accounts for different protocols
    try wallet.createAccount(.ghostchain, .ed25519, "Main Account");
    try wallet.createAccount(.ethereum, .secp256k1, "ETH Account");

    std.debug.print("Created {} accounts\n", .{wallet.accounts.items.len});
}
```

## Key Features

- **Multi-Protocol Support**: GhostChain, Ethereum, Stellar, Hedera, Ripple
- **Advanced Cryptography**: Ed25519, secp256k1, Curve25519 with zledger integration
- **Privacy Protection**: Shroud identity management and ephemeral identities
- **Audit Trails**: Cryptographic transaction logging with zledger
- **FFI Integration**: C-compatible API for external language bindings
- **Secure Storage**: Encrypted keystore with multiple wallet modes
- **Transaction Signing**: Integrated zsig for secure transaction signing

## Architecture

GFuel is built on three core components:

1. **Core Wallet** (`src/core/`) - Account management, key derivation, and wallet operations
2. **Protocol Layer** (`src/protocol/`) - Blockchain-specific transaction handling
3. **Privacy Layer** (`src/privacy/`) - Shroud integration for identity protection

## Dependencies

- **zledger v0.5.0** - Cryptographic operations and audit trails (includes integrated zsig)
- **shroud** - Privacy and identity management
- **Zig 0.16+** - Programming language and build system

## License

MIT License - see LICENSE file for details.