# Protocol Support Documentation

GFuel provides comprehensive support for multiple blockchain protocols, each with their own addressing schemes, transaction formats, and cryptographic requirements.

## Supported Protocols

### GhostChain
- **Currency**: GCC (GhostChain Coin)
- **Key Types**: Ed25519, secp256k1
- **Decimal Places**: 6
- **Address Format**: `gc_` prefix with base58 encoding
- **Default Fee**: 1000 micro-units (0.001 GCC)

### Ethereum
- **Currency**: ETH (Ether)
- **Key Types**: secp256k1
- **Decimal Places**: 18 (wei)
- **Address Format**: `0x` prefix with 40 hex characters
- **Gas System**: Uses gas limit and gas price

### Stellar
- **Currency**: XLM (Stellar Lumens)
- **Key Types**: Ed25519
- **Decimal Places**: 7 (stroops)
- **Address Format**: `G` prefix with base32 encoding
- **Default Fee**: 100 micro-units (0.00001 XLM)

### Hedera
- **Currency**: HBAR (Hedera Hashgraph)
- **Key Types**: Ed25519
- **Decimal Places**: 8 (tinybars)
- **Address Format**: Account ID format `0.0.xxxxx`
- **Default Fee**: 5000 micro-units (0.0005 HBAR)

### Ripple
- **Currency**: XRP (Ripple)
- **Key Types**: secp256k1, Ed25519
- **Decimal Places**: 6 (drops)
- **Address Format**: `r` prefix with base58 encoding
- **Default Fee**: 10 micro-units (0.00001 XRP)

## Protocol-Specific Implementation Details

### GhostChain Implementation

```zig
// Create GhostChain transaction
var gc_tx = try GhostChain.createTransaction(
    allocator,
    "gc1sender123...",
    "gc1recipient456...",
    1000000  // 1 GCC
);
defer gc_tx.deinit(allocator);

// Estimate fee
const fee = GhostChain.estimateFee(1000000);
// Returns: 1000 (0.001 GCC base fee)
```

**Address Generation:**
```zig
// GhostChain addresses use SHA256 hash of public key
// Format: gc_ + base58(hash(public_key))
fn generateGhostChainAddress(public_key: [32]u8, allocator: Allocator) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&public_key, &hash, .{});

    // Simplified - actual implementation would use proper base58
    return try std.fmt.allocPrint(allocator, "gc_placeholder_{d}", .{std.time.timestamp()});
}
```

**Audit Trail Integration:**
```zig
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

// Audit entry automatically created and linked
if (tx.ledger_entry_id) |entry_id| {
    std.debug.print("Audit entry: {s}\n", .{entry_id});
}
```

### Ethereum Implementation

```zig
// Create Ethereum transaction
var eth_tx = try Ethereum.createTransaction(
    allocator,
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
    "0x123456789abcdef123456789abcdef123456789a",
    1000000000000000000  // 1 ETH in wei
);
defer eth_tx.deinit(allocator);

// Gas parameters automatically set
// gas_limit: 21000 (standard transfer)
// gas_price: 20000000000 (20 gwei)
```

**Gas Estimation:**
```zig
const gas_limit: u64 = 21000;        // Standard ETH transfer
const gas_price: i64 = 20000000000;  // 20 gwei

const fee = Ethereum.estimateFee(gas_limit, gas_price);
// Returns: 420000000000000 wei (0.00042 ETH)
```

**Privacy Transactions:**
```zig
var identity = shroud.identity.Identity.init(allocator, "user_id", .{ .bytes = [_]u8{0} ** 32 });
defer identity.deinit();

var private_tx = try Ethereum.createPrivateTransaction(
    allocator,
    "0xfrom...",
    "0xto...",
    1000000000000000000,
    &identity
);
defer private_tx.deinit(allocator);

// Privacy token automatically attached to metadata
```

**Address Generation:**
```zig
// Ethereum addresses use Keccak256 hash of public key
// Format: 0x + last 20 bytes of keccak256(public_key)
fn generateEthereumAddress(public_key: [32]u8, allocator: Allocator) ![]const u8 {
    var hash: [32]u8 = undefined;
    // TODO: Use Keccak256 instead of SHA256
    std.crypto.hash.sha2.Sha256.hash(&public_key, &hash, .{});

    return try std.fmt.allocPrint(allocator, "0x_placeholder_{d}", .{std.time.timestamp()});
}
```

### Stellar Implementation

```zig
// Create Stellar transaction
var stellar_tx = try Stellar.createTransaction(
    allocator,
    "GAIUIQNOMFK2XGOITW6NMB2MZLNQYFK2NFJZRXMUR3FD2VKZK7CJIVNOE",
    "GBXXIIPRN6ZXJJYJ7LJM7HW5C36MM2GGDLDKPIHVK3Q7GSLMXXQFVVCO",
    10000000  // 1 XLM in stroops
);
defer stellar_tx.deinit(allocator);

// Fixed base fee
const fee = Stellar.estimateFee();  // Returns: 100 stroops
```

**Address Generation:**
```zig
// Stellar addresses use base32 encoding with checksum
// Format: G + base32(public_key + checksum)
fn generateStellarAddress(public_key: [32]u8, allocator: Allocator) ![]const u8 {
    // Simplified - actual implementation would use proper base32 + checksum
    return try std.fmt.allocPrint(allocator, "G_placeholder_{d}", .{std.time.timestamp()});
}
```

### Hedera Implementation

```zig
// Create Hedera transaction
var hedera_tx = try Hedera.createTransaction(
    allocator,
    "0.0.123456",  // Account ID format
    "0.0.789012",
    100000000      // 1 HBAR in tinybars
);
defer hedera_tx.deinit(allocator);

// Fixed base fee
const fee = Hedera.estimateFee();  // Returns: 5000 tinybars
```

**Address Generation:**
```zig
// Hedera uses account ID format derived from public key
// Format: 0.0.xxxxx where xxxxx is derived from public key
fn generateHederaAddress(public_key: [32]u8, allocator: Allocator) ![]const u8 {
    const account_num = @as(u64, @intCast(public_key[0])) |
        (@as(u64, @intCast(public_key[1])) << 8) |
        (@as(u64, @intCast(public_key[2])) << 16);

    return try std.fmt.allocPrint(allocator, "0.0.{}", .{account_num});
}
```

### Ripple Implementation

```zig
// Create Ripple transaction (XRP)
var ripple_tx = try Transaction.init(
    allocator,
    .ripple,
    "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH",
    "rLNaPoKeeBjZe2qs6x52yVPZpZ8td4dc6w",
    1000000  // 1 XRP in drops
);
defer ripple_tx.deinit(allocator);

// Fixed base fee (placeholder implementation)
const fee = 10;  // drops
```

**Address Generation:**
```zig
// XRPL addresses use base58 encoding with checksum
// Format: r + base58(public_key + checksum)
fn generateRippleAddress(public_key: [32]u8, allocator: Allocator) ![]const u8 {
    // Simplified - actual implementation would use proper base58 + checksum
    return try std.fmt.allocPrint(allocator, "r_placeholder_{d}", .{std.time.timestamp()});
}
```

## Protocol Factory Usage

The `ProtocolFactory` provides a unified interface for all protocols:

```zig
// Create transactions for different protocols
const protocols = [_]wallet.Protocol{ .ghostchain, .ethereum, .stellar, .hedera };
const amounts = [_]i64{ 1000000, 1000000000000000000, 10000000, 100000000 };

for (protocols, amounts) |protocol, amount| {
    var tx = try ProtocolFactory.createTransaction(
        allocator,
        protocol,
        from_addresses[@intFromEnum(protocol)],
        to_addresses[@intFromEnum(protocol)],
        amount
    );
    defer tx.deinit(allocator);

    const fee = ProtocolFactory.estimateFee(protocol, amount, null, null);
    std.debug.print("{}: fee = {}\n", .{ protocol, fee });
}
```

## Key Type Recommendations

### By Protocol

| Protocol | Recommended Key Type | Alternative | Rationale |
|----------|---------------------|-------------|-----------|
| GhostChain | Ed25519 | secp256k1 | Fast, secure, native support |
| Ethereum | secp256k1 | - | Required for compatibility |
| Stellar | Ed25519 | - | Native protocol requirement |
| Hedera | Ed25519 | - | Optimized for consensus |
| Ripple | secp256k1 | Ed25519 | Broader compatibility |

### Performance Characteristics

```zig
// Performance comparison for key generation
const KeyPerfTest = struct {
    pub fn benchmarkKeyGeneration(key_type: KeyType, iterations: u32) !u64 {
        const start = std.time.milliTimestamp();

        for (0..iterations) |_| {
            var keypair = try crypto.KeyPair.generate(key_type, allocator);
            defer keypair.deinit();
        }

        return @intCast(std.time.milliTimestamp() - start);
    }
};

// Example results (approximate, hardware-dependent):
// Ed25519: ~0.1ms per keypair
// secp256k1: ~0.5ms per keypair
```

## Currency Conversion Utilities

### Decimal Precision Helper

```zig
pub const ProtocolConfig = struct {
    decimal_places: u8,
    symbol: []const u8,
    base_fee_micro: i64,

    pub fn getConfig(protocol: Protocol) ProtocolConfig {
        return switch (protocol) {
            .ghostchain => .{ .decimal_places = 6, .symbol = "GCC", .base_fee_micro = 1000 },
            .ethereum => .{ .decimal_places = 18, .symbol = "ETH", .base_fee_micro = 0 }, // Gas-based
            .stellar => .{ .decimal_places = 7, .symbol = "XLM", .base_fee_micro = 100 },
            .hedera => .{ .decimal_places = 8, .symbol = "HBAR", .base_fee_micro = 5000 },
            .ripple => .{ .decimal_places = 6, .symbol = "XRP", .base_fee_micro = 10 },
        };
    }
};
```

### Amount Conversion

```zig
pub fn formatAmount(micro_amount: i64, protocol: Protocol, allocator: Allocator) ![]const u8 {
    const config = ProtocolConfig.getConfig(protocol);
    const divisor = std.math.pow(i64, 10, config.decimal_places);
    const whole = @divFloor(micro_amount, divisor);
    const fractional = @mod(micro_amount, divisor);

    return try std.fmt.allocPrint(
        allocator,
        "{}.{:0>*} {}",
        .{ whole, config.decimal_places, fractional, config.symbol }
    );
}

pub fn parseAmount(amount_str: []const u8, protocol: Protocol) !i64 {
    // Parse user-friendly amount string to micro-units
    // Example: "1.5 GCC" -> 1500000
    // Implementation would handle decimal parsing
    _ = amount_str;
    _ = protocol;
    return 0; // Placeholder
}
```

## Network Integration

### Broadcasting Transactions

```zig
pub fn broadcastTransaction(tx: Transaction) ![]const u8 {
    return switch (tx.protocol) {
        .ghostchain => try broadcastGhostChain(tx),
        .ethereum => try broadcastEthereum(tx),
        .stellar => try broadcastStellar(tx),
        .hedera => try broadcastHedera(tx),
        .ripple => try broadcastRipple(tx),
    };
}

// Protocol-specific broadcast implementations
fn broadcastGhostChain(tx: Transaction) ![]const u8 {
    // Connect to GhostChain node
    // Submit transaction via RPC
    // Return transaction hash
    _ = tx;
    return "gc_tx_hash_placeholder";
}

fn broadcastEthereum(tx: Transaction) ![]const u8 {
    // Connect to Ethereum node (e.g., via Web3)
    // Submit transaction
    // Return transaction hash
    _ = tx;
    return "0x1234567890abcdef...";
}
```

### Network Configuration

```zig
pub const NetworkConfig = struct {
    name: []const u8,
    rpc_url: []const u8,
    chain_id: ?u64,
    explorer_url: []const u8,

    pub fn getMainnetConfig(protocol: Protocol) NetworkConfig {
        return switch (protocol) {
            .ghostchain => .{
                .name = "GhostChain Mainnet",
                .rpc_url = "https://rpc.ghostchain.network",
                .chain_id = 1,
                .explorer_url = "https://explorer.ghostchain.network",
            },
            .ethereum => .{
                .name = "Ethereum Mainnet",
                .rpc_url = "https://mainnet.infura.io/v3/YOUR_KEY",
                .chain_id = 1,
                .explorer_url = "https://etherscan.io",
            },
            .stellar => .{
                .name = "Stellar Mainnet",
                .rpc_url = "https://horizon.stellar.org",
                .chain_id = null,
                .explorer_url = "https://stellarexpert.io",
            },
            .hedera => .{
                .name = "Hedera Mainnet",
                .rpc_url = "https://mainnet-public.mirrornode.hedera.com",
                .chain_id = null,
                .explorer_url = "https://hashscan.io",
            },
            .ripple => .{
                .name = "XRPL Mainnet",
                .rpc_url = "https://s1.ripple.com:51234",
                .chain_id = null,
                .explorer_url = "https://livenet.xrpl.org",
            },
        };
    }
};
```

## Testing and Validation

### Address Validation

```zig
pub fn validateAddress(address: []const u8, protocol: Protocol) bool {
    return switch (protocol) {
        .ghostchain => validateGhostChainAddress(address),
        .ethereum => validateEthereumAddress(address),
        .stellar => validateStellarAddress(address),
        .hedera => validateHederaAddress(address),
        .ripple => validateRippleAddress(address),
    };
}

fn validateEthereumAddress(address: []const u8) bool {
    // Must start with 0x and be 42 characters total
    if (address.len != 42) return false;
    if (!std.mem.startsWith(u8, address, "0x")) return false;

    // Validate hex characters
    for (address[2..]) |char| {
        if (!std.ascii.isHex(char)) return false;
    }

    return true;
}

fn validateGhostChainAddress(address: []const u8) bool {
    // Must start with "gc1" or "gc_"
    return std.mem.startsWith(u8, address, "gc1") or
           std.mem.startsWith(u8, address, "gc_");
}
```

### Transaction Validation

```zig
pub fn validateTransaction(tx: *const Transaction) !void {
    // Basic validation
    if (tx.amount <= 0) return error.InvalidAmount;
    if (tx.from.len == 0 or tx.to.len == 0) return error.InvalidAddress;

    // Protocol-specific validation
    switch (tx.protocol) {
        .ethereum => {
            if (tx.gas_limit == null or tx.gas_price == null) {
                return error.MissingGasParameters;
            }
        },
        else => {},
    }

    // Address format validation
    if (!validateAddress(tx.from, tx.protocol)) return error.InvalidFromAddress;
    if (!validateAddress(tx.to, tx.protocol)) return error.InvalidToAddress;
}
```

## Future Protocol Support

The architecture is designed to easily support additional protocols:

```zig
// Example: Adding Bitcoin support
pub const Bitcoin = struct {
    pub fn createTransaction(
        allocator: Allocator,
        from: []const u8,
        to: []const u8,
        amount: i64
    ) !Transaction {
        return Transaction.init(allocator, .bitcoin, from, to, amount, "BTC");
    }

    pub fn estimateFee(tx_size_bytes: u32, sat_per_byte: i64) i64 {
        return @intCast(tx_size_bytes * sat_per_byte);
    }
};

// Add to Protocol enum
pub const Protocol = enum {
    ghostchain,
    ethereum,
    stellar,
    hedera,
    ripple,
    bitcoin,  // New protocol
};
```