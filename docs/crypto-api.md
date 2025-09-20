# Cryptography API Documentation

GFuel's cryptographic functionality is built on top of zledger v0.5.0, which provides integrated zsig signing and verification. This document covers the crypto utilities and their usage.

## Overview

The crypto module (`src/utils/crypto.zig`) provides a unified interface for cryptographic operations while leveraging zledger's robust cryptographic primitives.

## Key Types

### KeyType Enum

```zig
pub const KeyType = enum {
    ed25519,    // Edwards-curve Digital Signature Algorithm
    secp256k1,  // Bitcoin/Ethereum elliptic curve
    curve25519, // Curve25519 for key exchange
};
```

**Protocol Recommendations:**
- **Ed25519**: GhostChain, Stellar, Hedera (fast, secure, small signatures)
- **secp256k1**: Ethereum, Bitcoin, Ripple (widespread compatibility)
- **Curve25519**: Key exchange and advanced privacy features

## KeyPair Structure

### KeyPair Wrapper

The `KeyPair` struct wraps zledger's integrated keypair functionality:

```zig
pub const KeyPair = struct {
    inner: zledger.Keypair,
    key_type: KeyType,

    // Methods documented below...
};
```

## KeyPair Methods

### Generation

#### `generate()`

Creates a new random keypair using zledger's integrated zsig.

```zig
pub fn generate(key_type: KeyType, allocator: Allocator) !KeyPair
```

**Example:**
```zig
const allocator = std.heap.page_allocator;

// Generate Ed25519 keypair for GhostChain
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();

// Generate secp256k1 keypair for Ethereum
var eth_keypair = try KeyPair.generate(.secp256k1, allocator);
defer eth_keypair.deinit();
```

#### `fromSeed()`

Creates a keypair from a 32-byte seed using deterministic generation.

```zig
pub fn fromSeed(seed: [32]u8, key_type: KeyType, allocator: Allocator) !KeyPair
```

**Example:**
```zig
// Deterministic keypair from seed
var seed: [32]u8 = undefined;
std.crypto.random.bytes(&seed);

var keypair = try KeyPair.fromSeed(seed, .ed25519, allocator);
defer keypair.deinit();

// Same seed will always produce the same keypair
var keypair2 = try KeyPair.fromSeed(seed, .ed25519, allocator);
defer keypair2.deinit();
// keypair.publicKey() == keypair2.publicKey()
```

### Public Key Operations

#### `publicKey()`

Returns the 32-byte public key.

```zig
pub fn publicKey(self: *const KeyPair) [32]u8
```

**Example:**
```zig
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();

const pubkey = keypair.publicKey();
std.debug.print("Public key: {}\n", .{std.fmt.fmtSliceHexLower(&pubkey)});
```

### Signing Operations

#### `sign()`

Signs a message using zledger's integrated signing.

```zig
pub fn sign(self: *const KeyPair, message: []const u8, allocator: Allocator) !zledger.Signature
```

**Example:**
```zig
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();

const message = "Hello, GFuel!";
const signature = try keypair.sign(message, allocator);

std.debug.print("Message: {s}\n", .{message});
std.debug.print("Signature: {}\n", .{std.fmt.fmtSliceHexLower(&signature.bytes)});
```

#### `verify()`

Verifies a signature against a message and public key.

```zig
pub fn verify(self: *const KeyPair, message: []const u8, signature: *const zledger.Signature) bool
```

**Example:**
```zig
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();

const message = "Hello, GFuel!";
const signature = try keypair.sign(message, allocator);

// Verify the signature
const is_valid = keypair.verify(message, &signature);
std.debug.print("Signature valid: {}\n", .{is_valid});
```

## Convenience Functions

### `createWalletKeypair()`

Creates a standard Ed25519 keypair for wallet operations.

```zig
pub fn createWalletKeypair(allocator: Allocator) !KeyPair
```

**Example:**
```zig
var wallet_keypair = try createWalletKeypair(allocator);
defer wallet_keypair.deinit();
```

### `createWalletKeypairFromSeed()`

Creates a deterministic wallet keypair from a seed.

```zig
pub fn createWalletKeypairFromSeed(seed: [32]u8, allocator: Allocator) !KeyPair
```

**Example:**
```zig
var seed: [32]u8 = undefined;
// Derive seed from mnemonic or other source...

var wallet_keypair = try createWalletKeypairFromSeed(seed, allocator);
defer wallet_keypair.deinit();
```

## BIP-39 Support

### `generateMnemonic()`

Generates a BIP-39 mnemonic phrase (placeholder implementation).

```zig
pub fn generateMnemonic(allocator: Allocator, entropy_bits: u16) ![]const u8
```

**Example:**
```zig
// Generate 12-word mnemonic (128 bits entropy)
const mnemonic = try generateMnemonic(allocator, 128);
defer allocator.free(mnemonic);

// Generate 24-word mnemonic (256 bits entropy)
const strong_mnemonic = try generateMnemonic(allocator, 256);
defer allocator.free(strong_mnemonic);
```

### `mnemonicToSeed()`

Converts a BIP-39 mnemonic to a seed (placeholder implementation).

```zig
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8, allocator: Allocator) ![64]u8
```

**Example:**
```zig
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = try mnemonicToSeed(mnemonic, null, allocator);

// Use first 32 bytes as keypair seed
var keypair_seed: [32]u8 = undefined;
@memcpy(&keypair_seed, seed[0..32]);

var keypair = try KeyPair.fromSeed(keypair_seed, .ed25519, allocator);
defer keypair.deinit();
```

## zledger Integration

### zledger.Keypair

GFuel uses zledger's internal keypair structure for all cryptographic operations:

```zig
// Access the underlying zledger keypair
var gfuel_keypair = try KeyPair.generate(.ed25519, allocator);
const zledger_keypair = gfuel_keypair.inner;

// Use zledger functions directly if needed
const pubkey = zledger_keypair.publicKey();
```

### zledger.Signature

All signatures are zledger.Signature types:

```zig
const signature = try keypair.sign("message", allocator);
// signature is of type zledger.Signature

// Access raw bytes if needed
const signature_bytes = signature.bytes;
```

## Error Handling

### CryptoError

Cryptographic operation errors:

```zig
pub const CryptoError = error{
    InvalidKey,
    InvalidSignature,
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
};
```

**Error Handling Example:**
```zig
const keypair = KeyPair.generate(.ed25519, allocator) catch |err| switch (err) {
    CryptoError.KeyGenerationFailed => {
        std.debug.print("Failed to generate keypair\n", .{});
        return;
    },
    else => return err,
};
```

## Security Best Practices

### Key Generation

1. **Use cryptographically secure randomness**:
```zig
// Good: Use system random number generator
var keypair = try KeyPair.generate(.ed25519, allocator);

// Bad: Predictable seed
const bad_seed = [_]u8{0} ** 32;
var bad_keypair = try KeyPair.fromSeed(bad_seed, .ed25519, allocator);
```

2. **Verify key generation**:
```zig
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();

// Ensure public key is not all zeros
const pubkey = keypair.publicKey();
if (std.mem.allEqual(u8, &pubkey, 0)) {
    return error.InvalidKey;
}
```

### Memory Security

1. **Clear sensitive data**:
```zig
// KeyPair.deinit() handles cleanup automatically
defer keypair.deinit();

// For manual seed handling
var seed: [32]u8 = undefined;
defer @memset(&seed, 0); // Clear seed from memory
```

2. **Use secure allocators** for sensitive operations:
```zig
// Use page allocator for keypairs
var keypair = try KeyPair.generate(.ed25519, std.heap.page_allocator);
defer keypair.deinit();
```

### Signature Security

1. **Always verify signatures**:
```zig
const signature = try keypair.sign(message, allocator);
if (!keypair.verify(message, &signature)) {
    return error.VerificationFailed;
}
```

2. **Use appropriate key types**:
```zig
// For high-security applications
var ed25519_keypair = try KeyPair.generate(.ed25519, allocator);

// For Ethereum compatibility
var secp256k1_keypair = try KeyPair.generate(.secp256k1, allocator);
```

## Performance Considerations

### Key Type Performance

| Key Type | Generation Speed | Signature Speed | Verification Speed | Signature Size |
|----------|------------------|-----------------|-------------------|----------------|
| Ed25519 | Fast | Very Fast | Very Fast | 64 bytes |
| secp256k1 | Medium | Medium | Medium | 64-65 bytes |
| Curve25519 | Fast | N/A (key exchange) | N/A | N/A |

### Memory Usage

- **KeyPair**: ~100 bytes + zledger overhead
- **Signature**: 64 bytes
- **Public Key**: 32 bytes
- **Private Key**: 32 bytes (managed by zledger)

### Optimization Tips

1. **Reuse keypairs** when possible:
```zig
// Good: Reuse for multiple signatures
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();

for (messages) |message| {
    const signature = try keypair.sign(message, allocator);
    // Use signature...
}
```

2. **Batch operations** when feasible:
```zig
// Generate multiple keypairs efficiently
var keypairs = std.ArrayList(KeyPair).init(allocator);
defer {
    for (keypairs.items) |*kp| kp.deinit();
    keypairs.deinit();
}

for (0..num_accounts) |_| {
    const kp = try KeyPair.generate(.ed25519, allocator);
    try keypairs.append(kp);
}
```

## Integration Examples

### Wallet Integration

```zig
// Create account with cryptographic keypair
pub fn createAccount(
    wallet: *Wallet,
    protocol: Protocol,
    key_type: KeyType,
    name: ?[]const u8
) !void {
    const keypair = try KeyPair.generate(key_type, wallet.allocator);

    const account = Account{
        .keypair = keypair,
        .key_type = key_type,
        .protocol = protocol,
        .name = name,
        // ... other fields
    };

    try wallet.accounts.append(account);
}
```

### Transaction Signing

```zig
// Sign transaction with account keypair
pub fn signTransaction(account: *Account, tx_data: []const u8, allocator: Allocator) ![]u8 {
    if (account.keypair) |keypair| {
        const signature = try keypair.sign(tx_data, allocator);
        return try allocator.dupe(u8, &signature.bytes);
    }
    return error.NoKeypair;
}
```