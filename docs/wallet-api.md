# Wallet API Documentation

The GFuel Wallet API provides comprehensive functionality for creating, managing, and securing cryptocurrency wallets with multi-protocol support.

## Core Types

### WalletMode

Defines the security and operational mode of the wallet:

```zig
pub const WalletMode = enum {
    public_identity,    // Public operations with full transparency
    private_cold,       // Cold storage with minimal network interaction
    hybrid,            // Balanced security and functionality
    privacy_focused,   // Maximum privacy with Shroud integration
};
```

### Protocol

Supported blockchain protocols:

```zig
pub const Protocol = enum {
    ghostchain,
    ethereum,
    stellar,
    hedera,
    ripple,
};
```

### KeyType

Supported cryptographic key types:

```zig
pub const KeyType = enum {
    ed25519,
    secp256k1,
    curve25519,
};
```

## Wallet Structure

### Main Wallet

```zig
pub const Wallet = struct {
    allocator: Allocator,
    mode: WalletMode,
    accounts: std.ArrayList(Account),
    keystore_path: ?[]const u8,
    is_locked: bool,
    master_seed: ?[32]u8,
    shroud_guardian: ?shroud.guardian.Guardian,
    audit_ledger: ?zledger.journal.Journal,

    // Methods documented below...
};
```

### Account Structure

```zig
pub const Account = struct {
    address: []const u8,
    protocol: Protocol,
    key_type: KeyType,
    keypair: ?crypto.KeyPair,
    name: ?[]const u8,
    balance: i64,
    currency: []const u8,
    shroud_identity: ?shroud.identity.Identity,
    ledger_account: ?zledger.account.Account,

    // Methods documented below...
};
```

## Wallet Methods

### Creation and Initialization

#### `Wallet.create()`

Creates a new wallet with a passphrase.

```zig
pub fn create(
    allocator: Allocator,
    passphrase: []const u8,
    mode: WalletMode,
    keystore_path: ?[]const u8
) !Wallet
```

**Parameters:**
- `allocator`: Memory allocator
- `passphrase`: Secure passphrase for wallet encryption
- `mode`: Wallet operational mode
- `keystore_path`: Optional path for keystore file

**Example:**
```zig
var wallet = try Wallet.create(
    allocator,
    "secure_passphrase_123",
    .hybrid,
    "~/.gfuel/wallet.keystore"
);
defer wallet.deinit();
```

#### `Wallet.fromMnemonic()`

Creates a wallet from a BIP-39 mnemonic phrase.

```zig
pub fn fromMnemonic(
    allocator: Allocator,
    mnemonic: []const u8,
    password: ?[]const u8,
    mode: WalletMode
) !Wallet
```

**Example:**
```zig
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
var wallet = try Wallet.fromMnemonic(allocator, mnemonic, null, .hybrid);
defer wallet.deinit();
```

#### `Wallet.generate()`

Generates a new random wallet.

```zig
pub fn generate(allocator: Allocator, mode: WalletMode) !Wallet
```

**Example:**
```zig
var wallet = try Wallet.generate(allocator, .privacy_focused);
defer wallet.deinit();
```

### Account Management

#### `createAccount()`

Creates a new account for a specific protocol.

```zig
pub fn createAccount(
    self: *Wallet,
    protocol: Protocol,
    key_type: KeyType,
    name: ?[]const u8
) !void
```

**Example:**
```zig
try wallet.createAccount(.ghostchain, .ed25519, "Main Account");
try wallet.createAccount(.ethereum, .secp256k1, "ETH Trading");
```

#### `getAccount()`

Retrieves an account by address.

```zig
pub fn getAccount(self: *Wallet, address: []const u8) ?*Account
```

**Example:**
```zig
if (wallet.getAccount("gc1abc123...")) |account| {
    std.debug.print("Found account: {s}\n", .{account.name.?});
}
```

#### `getBalance()`

Gets the balance for a specific address and currency.

```zig
pub fn getBalance(self: *Wallet, address: []const u8, currency: []const u8) !i64
```

**Example:**
```zig
const balance = try wallet.getBalance("gc1abc123...", "GCC");
std.debug.print("Balance: {} GCC\n", .{balance});
```

### Security Operations

#### `lock()`

Locks the wallet and clears sensitive data from memory.

```zig
pub fn lock(self: *Wallet) void
```

**Example:**
```zig
wallet.lock();
std.debug.print("Wallet locked: {}\n", .{wallet.is_locked});
```

#### `unlock()`

Unlocks the wallet with a password.

```zig
pub fn unlock(self: *Wallet, password: []const u8) !void
```

**Example:**
```zig
try wallet.unlock("secure_passphrase_123");
std.debug.print("Wallet unlocked: {}\n", .{!wallet.is_locked});
```

### Persistence

#### `save()`

Saves the wallet to an encrypted keystore file.

```zig
pub fn save(self: *Wallet, path: []const u8, password: []const u8) !void
```

**Example:**
```zig
try wallet.save("~/.gfuel/my_wallet.keystore", "file_password");
```

#### `load()`

Loads a wallet from an encrypted keystore file.

```zig
pub fn load(allocator: Allocator, path: []const u8, password: []const u8) !Wallet
```

**Example:**
```zig
var wallet = try Wallet.load(allocator, "~/.gfuel/my_wallet.keystore", "file_password");
defer wallet.deinit();
```

## Account Methods

### Key Operations

#### `getPublicKey()`

Returns the public key for the account.

```zig
pub fn getPublicKey(self: *const Account) ?[32]u8
```

**Example:**
```zig
if (account.getPublicKey()) |pubkey| {
    std.debug.print("Public key: {}\n", .{std.fmt.fmtSliceHexLower(&pubkey)});
}
```

#### `sign()`

Signs a message with the account's private key.

```zig
pub fn sign(self: *const Account, message: []const u8, allocator: Allocator) ![]u8
```

**Example:**
```zig
const message = "Hello, GFuel!";
const signature = try account.sign(message, allocator);
defer allocator.free(signature);
std.debug.print("Signature: {}\n", .{std.fmt.fmtSliceHexLower(signature)});
```

## Error Handling

### WalletError

Common wallet errors:

```zig
pub const WalletError = error{
    InvalidMnemonic,
    InvalidKey,
    InvalidAddress,
    InsufficientFunds,
    NetworkError,
    KeyDerivationFailed,
    UnknownProtocol,
    WalletLocked,
    InvalidPassword,
    IdentityGenerationFailed,
    AuditTrailFailed,
    SigningFailed,
    PrivacyTokenFailed,
};
```

**Error Handling Example:**
```zig
const result = wallet.createAccount(.ethereum, .secp256k1, "ETH Account");
result catch |err| switch (err) {
    WalletError.WalletLocked => {
        std.debug.print("Please unlock wallet first\n", .{});
        try wallet.unlock("password");
        try wallet.createAccount(.ethereum, .secp256k1, "ETH Account");
    },
    WalletError.InvalidKey => {
        std.debug.print("Invalid key type for protocol\n", .{});
    },
    else => return err,
};
```

## Best Practices

### Security

1. **Always lock wallets** when not in use:
```zig
defer wallet.lock(); // Ensure wallet is locked when done
```

2. **Use strong passphrases**:
```zig
// Good: Long, complex passphrase
const passphrase = "My$ecure!Wallet#Passphrase@2024";

// Bad: Short, simple password
const passphrase = "123456";
```

3. **Clear sensitive data**:
```zig
// The wallet handles this automatically in deinit()
defer wallet.deinit();
```

### Memory Management

1. **Always free allocated memory**:
```zig
const signature = try account.sign(message, allocator);
defer allocator.free(signature); // Important!
```

2. **Use appropriate allocators**:
```zig
// For long-lived wallets
var gpa = std.heap.GeneralPurposeAllocator(.{});
const allocator = gpa.allocator();

// For temporary operations
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const temp_allocator = arena.allocator();
```

### Protocol Selection

Choose appropriate key types for each protocol:

```zig
// Recommended key types
try wallet.createAccount(.ghostchain, .ed25519, "GhostChain");
try wallet.createAccount(.ethereum, .secp256k1, "Ethereum");
try wallet.createAccount(.stellar, .ed25519, "Stellar");
try wallet.createAccount(.hedera, .ed25519, "Hedera");
try wallet.createAccount(.ripple, .secp256k1, "Ripple");
```

## Privacy Features

When using `.privacy_focused` mode, the wallet automatically integrates with Shroud for enhanced privacy:

```zig
var wallet = try Wallet.create(allocator, "passphrase", .privacy_focused, null);

// Shroud guardian is automatically initialized
if (wallet.shroud_guardian) |guardian| {
    std.debug.print("Privacy features enabled\n", .{});
}

// Audit ledger tracks all operations
if (wallet.audit_ledger) |ledger| {
    std.debug.print("Audit trail active\n", .{});
}
```

See [Privacy Features](privacy.md) for detailed privacy documentation.