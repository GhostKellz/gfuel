# Transaction API Documentation

GFuel provides comprehensive transaction support for multiple blockchain protocols with integrated signing, audit trails, and privacy features.

## Overview

The transaction system is located in `src/protocol/transaction.zig` and provides protocol-specific transaction handling with zledger audit trails and optional privacy features.

## Core Transaction Structure

### Transaction

The base transaction structure supports all protocols:

```zig
pub const Transaction = struct {
    from: []const u8,               // Source address
    to: []const u8,                 // Destination address
    amount: i64,                    // Amount in micro-units
    currency: []const u8,           // Currency/token symbol
    protocol: wallet.Protocol,      // Blockchain protocol
    fee: i64,                       // Transaction fee
    memo: ?[]const u8,              // Optional memo/message
    nonce: ?u64,                    // Sequence number (protocol-specific)
    gas_limit: ?u64,                // Gas limit (Ethereum)
    gas_price: ?i64,                // Gas price (Ethereum)
    signature: ?[]const u8,         // Transaction signature
    hash: ?[]const u8,              // Transaction hash
    metadata: ?[]const u8,          // Privacy tokens and audit info
    ledger_entry_id: ?[]const u8,   // Reference to audit trail entry
};
```

## Transaction Methods

### Creation

#### `init()`

Creates a new transaction instance.

```zig
pub fn init(
    allocator: Allocator,
    protocol: wallet.Protocol,
    from: []const u8,
    to: []const u8,
    amount: i64,
    currency: []const u8
) !Transaction
```

**Example:**
```zig
var tx = try Transaction.init(
    allocator,
    .ethereum,
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
    "0x123456789abcdef123456789abcdef123456789a",
    1000000000000000000, // 1 ETH in wei
    "ETH"
);
defer tx.deinit(allocator);
```

### Signing

#### `calculateHash()`

Calculates the transaction hash for signing.

```zig
pub fn calculateHash(self: *Transaction, allocator: Allocator) ![]u8
```

**Example:**
```zig
const hash = try tx.calculateHash(allocator);
defer allocator.free(hash);
std.debug.print("Transaction hash: {}\n", .{std.fmt.fmtSliceHexLower(hash)});
```

#### `sign()`

Signs the transaction with a private key using zledger integrated signing.

```zig
pub fn sign(self: *Transaction, allocator: Allocator, private_key: []const u8) !void
```

**Example:**
```zig
const private_key = "your_private_key_32_bytes_exactly!";
try tx.sign(allocator, private_key);

if (tx.signature) |sig| {
    std.debug.print("Transaction signed successfully\n", .{});
}
```

## Protocol-Specific Implementations

### GhostChain

#### `GhostChain.createTransaction()`

Creates a GhostChain transaction with GCC currency.

```zig
pub fn createTransaction(
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
    amount: i64
) !Transaction
```

**Example:**
```zig
var gc_tx = try GhostChain.createTransaction(
    allocator,
    "gc1sender123...",
    "gc1recipient456...",
    500000 // 0.5 GCC in micro-units
);
defer gc_tx.deinit(allocator);
```

#### `GhostChain.createTransactionWithAudit()`

Creates a GhostChain transaction with automatic audit trail logging.

```zig
pub fn createTransactionWithAudit(
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
    amount: i64,
    ledger: *zledger.journal.Journal
) !Transaction
```

**Example:**
```zig
var ledger = zledger.journal.Journal.init(allocator, null);
defer ledger.deinit();

var tx = try GhostChain.createTransactionWithAudit(
    allocator,
    "gc1sender123...",
    "gc1recipient456...",
    1000000,
    &ledger
);
defer tx.deinit(allocator);

// Audit entry automatically created
if (tx.ledger_entry_id) |entry_id| {
    std.debug.print("Audit entry: {s}\n", .{entry_id});
}
```

#### `GhostChain.estimateFee()`

Estimates the transaction fee for GhostChain.

```zig
pub fn estimateFee(amount: i64) i64
```

**Example:**
```zig
const fee = GhostChain.estimateFee(1000000);
std.debug.print("Estimated fee: {} GCC\n", .{fee});
```

### Ethereum

#### `Ethereum.createTransaction()`

Creates an Ethereum transaction with gas parameters.

```zig
pub fn createTransaction(
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
    amount: i64
) !Transaction
```

**Example:**
```zig
var eth_tx = try Ethereum.createTransaction(
    allocator,
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
    "0x123456789abcdef123456789abcdef123456789a",
    1000000000000000000 // 1 ETH in wei
);
defer eth_tx.deinit(allocator);

std.debug.print("Gas limit: {}\n", .{eth_tx.gas_limit.?});
std.debug.print("Gas price: {} wei\n", .{eth_tx.gas_price.?});
```

#### `Ethereum.createPrivateTransaction()`

Creates an Ethereum transaction with privacy features using Shroud identity.

```zig
pub fn createPrivateTransaction(
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
    amount: i64,
    identity: *shroud.identity.Identity
) !Transaction
```

**Example:**
```zig
var identity = shroud.identity.Identity.init(allocator, "user_id", .{ .bytes = [_]u8{0} ** 32 });
defer identity.deinit();

var private_tx = try Ethereum.createPrivateTransaction(
    allocator,
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
    "0x123456789abcdef123456789abcdef123456789a",
    1000000000000000000,
    &identity
);
defer private_tx.deinit(allocator);

// Privacy metadata automatically attached
if (private_tx.metadata) |metadata| {
    std.debug.print("Privacy token attached\n", .{});
}
```

#### `Ethereum.estimateFee()`

Estimates Ethereum transaction fees based on gas parameters.

```zig
pub fn estimateFee(gas_limit: u64, gas_price: i64) i64
```

**Example:**
```zig
const gas_limit: u64 = 21000;  // Standard ETH transfer
const gas_price: i64 = 20000000000;  // 20 gwei

const fee = Ethereum.estimateFee(gas_limit, gas_price);
std.debug.print("Estimated fee: {} wei\n", .{fee});
```

### Stellar

#### `Stellar.createTransaction()`

Creates a Stellar transaction with XLM currency.

```zig
pub fn createTransaction(
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
    amount: i64
) !Transaction
```

**Example:**
```zig
var stellar_tx = try Stellar.createTransaction(
    allocator,
    "GAIUIQ...", // Stellar address
    "GBXXII...", // Stellar address
    10000000    // 1 XLM (7 decimal places)
);
defer stellar_tx.deinit(allocator);
```

### Hedera

#### `Hedera.createTransaction()`

Creates a Hedera transaction with HBAR currency.

```zig
pub fn createTransaction(
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
    amount: i64
) !Transaction
```

**Example:**
```zig
var hedera_tx = try Hedera.createTransaction(
    allocator,
    "0.0.123456",  // Hedera account ID
    "0.0.789012",  // Hedera account ID
    100000000      // 1 HBAR (8 decimal places)
);
defer hedera_tx.deinit(allocator);
```

## Protocol Factory

### `ProtocolFactory`

Provides a unified interface for creating transactions across all protocols.

#### `createTransaction()`

Creates a transaction for any supported protocol.

```zig
pub fn createTransaction(
    allocator: Allocator,
    protocol: wallet.Protocol,
    from: []const u8,
    to: []const u8,
    amount: i64
) !Transaction
```

**Example:**
```zig
// Create transactions for different protocols
var gc_tx = try ProtocolFactory.createTransaction(
    allocator, .ghostchain, "gc1from...", "gc1to...", 1000000
);
defer gc_tx.deinit(allocator);

var eth_tx = try ProtocolFactory.createTransaction(
    allocator, .ethereum, "0xfrom...", "0xto...", 1000000000000000000
);
defer eth_tx.deinit(allocator);
```

#### `estimateFee()`

Estimates fees for any protocol.

```zig
pub fn estimateFee(
    protocol: wallet.Protocol,
    amount: i64,
    gas_limit: ?u64,
    gas_price: ?i64
) i64
```

**Example:**
```zig
// GhostChain fee estimation
const gc_fee = ProtocolFactory.estimateFee(.ghostchain, 1000000, null, null);

// Ethereum fee estimation
const eth_fee = ProtocolFactory.estimateFee(.ethereum, 0, 21000, 20000000000);

// Stellar fee estimation
const xlm_fee = ProtocolFactory.estimateFee(.stellar, 1000000, null, null);
```

#### `broadcast()`

Broadcasts a transaction to the appropriate network.

```zig
pub fn broadcast(transaction: Transaction) ![]const u8
```

**Example:**
```zig
// Sign transaction first
try tx.sign(allocator, private_key);

// Broadcast to network
const tx_hash = try ProtocolFactory.broadcast(tx);
std.debug.print("Transaction broadcast: {s}\n", .{tx_hash});
```

## Currency Formats

### Amount Precision

Different protocols use different decimal precision:

| Protocol | Currency | Decimal Places | Example |
|----------|----------|----------------|---------|
| GhostChain | GCC | 6 | 1 GCC = 1,000,000 micro-units |
| Ethereum | ETH | 18 | 1 ETH = 1,000,000,000,000,000,000 wei |
| Stellar | XLM | 7 | 1 XLM = 10,000,000 stroops |
| Hedera | HBAR | 8 | 1 HBAR = 100,000,000 tinybars |
| Ripple | XRP | 6 | 1 XRP = 1,000,000 drops |

### Conversion Utilities

```zig
// Convert user amounts to protocol micro-units
pub fn toMicroUnits(amount: f64, protocol: Protocol) i64 {
    return switch (protocol) {
        .ghostchain => @intFromFloat(amount * 1_000_000),
        .ethereum => @intFromFloat(amount * 1_000_000_000_000_000_000),
        .stellar => @intFromFloat(amount * 10_000_000),
        .hedera => @intFromFloat(amount * 100_000_000),
        .ripple => @intFromFloat(amount * 1_000_000),
    };
}

// Example usage
const amount_gcc = toMicroUnits(1.5, .ghostchain);  // 1,500,000
const amount_eth = toMicroUnits(0.1, .ethereum);    // 100,000,000,000,000,000
```

## Audit Trails

### Integration with zledger

GFuel automatically creates audit trail entries for transactions when using audit-enabled methods:

```zig
// Create transaction with audit trail
var ledger = zledger.journal.Journal.init(allocator, null);
defer ledger.deinit();

var tx = try GhostChain.createTransactionWithAudit(
    allocator,
    "gc1from...",
    "gc1to...",
    1000000,
    &ledger
);
defer tx.deinit(allocator);

// Verify audit trail integrity
const integrity_ok = try ledger.verifyIntegrity();
std.debug.print("Audit trail integrity: {}\n", .{integrity_ok});
```

### Manual Audit Entry

```zig
// Create manual audit entry
const ledger_tx = try zledger.tx.Transaction.init(
    allocator,
    tx.amount,
    tx.currency,
    tx.from,
    tx.to,
    "Manual transaction entry"
);

try ledger.append(ledger_tx);
```

## Privacy Features

### Privacy Metadata

Transactions can include privacy tokens and metadata when using Shroud:

```zig
var identity = shroud.identity.Identity.init(allocator, "user_id", .{ .bytes = [_]u8{0} ** 32 });
defer identity.deinit();

var private_tx = try Ethereum.createPrivateTransaction(
    allocator,
    "0xfrom...",
    "0xto...",
    amount,
    &identity
);

// Privacy token automatically generated and attached
if (private_tx.metadata) |metadata| {
    std.debug.print("Privacy metadata: {s}\n", .{metadata});
}
```

### Anonymous Transactions

For maximum privacy, use ephemeral identities:

```zig
// Create ephemeral identity for single transaction
var ephemeral_identity = shroud.identity.Identity.init(
    allocator,
    "ephemeral_tx_id",
    .{ .bytes = random_bytes }
);
defer ephemeral_identity.deinit();

var anon_tx = try Ethereum.createPrivateTransaction(
    allocator,
    "0xfrom...",
    "0xto...",
    amount,
    &ephemeral_identity
);
defer anon_tx.deinit(allocator);
```

## Error Handling

### Transaction Errors

Common transaction-related errors are handled through the wallet error system:

```zig
const tx_result = Transaction.init(allocator, .ethereum, from, to, amount, "ETH");
tx_result catch |err| switch (err) {
    error.InsufficientFunds => {
        std.debug.print("Insufficient balance for transaction\n", .{});
    },
    error.InvalidAddress => {
        std.debug.print("Invalid address format\n", .{});
    },
    error.OutOfMemory => {
        std.debug.print("Memory allocation failed\n", .{});
    },
    else => return err,
};
```

### Signing Errors

```zig
tx.sign(allocator, private_key) catch |err| switch (err) {
    error.SigningFailed => {
        std.debug.print("Transaction signing failed\n", .{});
    },
    error.InvalidKey => {
        std.debug.print("Invalid private key\n", .{});
    },
    else => return err,
};
```

## Best Practices

### Memory Management

Always properly deallocate transaction memory:

```zig
var tx = try Transaction.init(allocator, .ethereum, from, to, amount, "ETH");
defer tx.deinit(allocator); // Essential!

// For multiple transactions
var transactions = std.ArrayList(Transaction).init(allocator);
defer {
    for (transactions.items) |*tx| tx.deinit(allocator);
    transactions.deinit();
}
```

### Security

1. **Always verify addresses** before creating transactions:
```zig
if (!isValidAddress(to_address, protocol)) {
    return error.InvalidAddress;
}
```

2. **Use appropriate gas limits** for Ethereum:
```zig
// Standard ETH transfer
tx.gas_limit = 21000;

// Smart contract interaction
tx.gas_limit = 200000;
```

3. **Verify transaction details** before signing:
```zig
std.debug.print("Confirm transaction:\n", .{});
std.debug.print("From: {s}\n", .{tx.from});
std.debug.print("To: {s}\n", .{tx.to});
std.debug.print("Amount: {} {s}\n", .{tx.amount, tx.currency});
std.debug.print("Fee: {} {s}\n", .{tx.fee, tx.currency});

// Only sign after verification
try tx.sign(allocator, private_key);
```

### Performance

1. **Reuse allocators** for multiple transactions:
```zig
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const tx_allocator = arena.allocator();

// Create multiple transactions with same allocator
for (transaction_data) |data| {
    var tx = try Transaction.init(tx_allocator, data.protocol, data.from, data.to, data.amount, data.currency);
    // Process transaction...
}
// All memory freed at once with arena.deinit()
```

2. **Batch operations** when possible:
```zig
// Batch multiple transactions for same protocol
const transactions = try batchCreateTransactions(allocator, .ethereum, transaction_requests);
defer {
    for (transactions) |*tx| tx.deinit(allocator);
    allocator.free(transactions);
}
```