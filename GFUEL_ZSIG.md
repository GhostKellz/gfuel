# GFUEL Integration Guide: Migrating from Standalone Zsig to Zledger v0.5.0

This guide helps GFUEL update the existing zwallet codebase that previously used separate zledger and zsig dependencies to now use the integrated zsig functionality within zledger v0.5.0.

## 🔄 Migration Overview

**Before (zwallet with separate dependencies):**
```zig
// Old build.zig dependencies
.zledger = .{ .url = "...", .hash = "..." },
.zsig = .{ .url = "...", .hash = "..." },

// Old imports
const zledger = @import("zledger");
const zsig = @import("zsig");
```

**After (zwallet with integrated zledger v0.5.0):**
```zig
// New build.zig dependencies - only one!
.zledger = .{ .url = "https://github.com/ghostkellz/zledger", .hash = "..." },

// New imports - zsig is included in zledger
const zledger = @import("zledger");
// zsig functionality: zledger.zsig.*
```

## 📦 Step 1: Update build.zig.zon

**Remove old dependencies:**
```zig
// Remove these lines from build.zig.zon
.zsig = .{
    .url = "https://github.com/ghostkellz/zsig",
    .hash = "12345...",
},
```

**Update zledger to v0.5.0:**
```zig
.{
    .name = "zwallet",
    .version = "0.8.0",
    .dependencies = .{
        .zledger = .{
            .url = "https://github.com/ghostkellz/zledger",
            .hash = "12345...", // zig fetch will update this
        },
        // Keep other dependencies like zcrypto, etc.
    },
    .paths = .{""},
}
```

**Fetch the updated dependency:**
```bash
zig fetch --save https://github.com/ghostkellz/zledger
```

## 🔧 Step 2: Update build.zig

**Before:**
```zig
pub fn build(b: *std.Build) void {
    // ...
    const zledger = b.dependency("zledger", .{});
    const zsig = b.dependency("zsig", .{});

    exe.root_module.addImport("zledger", zledger.module("zledger"));
    exe.root_module.addImport("zsig", zsig.module("zsig"));
}
```

**After:**
```zig
pub fn build(b: *std.Build) void {
    // ...
    const zledger = b.dependency("zledger", .{});

    // Only need zledger - zsig is included!
    exe.root_module.addImport("zledger", zledger.module("zledger"));
    // Remove zsig import line
}
```

## 🔄 Step 3: Update Source Code Imports

**Replace all zsig imports:**

```zig
// OLD - Remove these lines
const zsig = @import("zsig");

// NEW - Use zledger with integrated zsig
const zledger = @import("zledger");
// Access zsig via: zledger.zsig.* or direct exports like zledger.generateKeypair
```

## 🔐 Step 4: Update Cryptographic Code

### Key Generation

**Before:**
```zig
const keypair = try zsig.generateKeypair(allocator);
const signature = try zsig.signMessage(message, keypair);
const is_valid = zsig.verifySignature(message, &signature.bytes, &keypair.publicKey());
```

**After:**
```zig
// Option 1: Use direct exports (recommended)
const keypair = try zledger.generateKeypair(allocator);
const signature = try zledger.signMessage(message, keypair);
const is_valid = zledger.verifySignature(message, &signature.bytes, &keypair.publicKey());

// Option 2: Use explicit zsig module
const keypair = try zledger.zsig.generateKeypair(allocator);
const signature = try zledger.zsig.signMessage(message, keypair);
const is_valid = zledger.zsig.verifySignature(message, &signature.bytes, &keypair.publicKey());
```

### Wallet Key Management

**Before:**
```zig
// zwallet/src/crypto.zig
const zsig = @import("zsig");

pub const WalletKeypair = struct {
    inner: zsig.Keypair,

    pub fn generate(allocator: std.mem.Allocator) !WalletKeypair {
        return WalletKeypair{
            .inner = try zsig.generateKeypair(allocator),
        };
    }

    pub fn signTransaction(self: WalletKeypair, tx_data: []const u8) !zsig.Signature {
        return try zsig.signMessage(tx_data, self.inner);
    }
};
```

**After:**
```zig
// zwallet/src/crypto.zig
const zledger = @import("zledger");

pub const WalletKeypair = struct {
    inner: zledger.Keypair,

    pub fn generate(allocator: std.mem.Allocator) !WalletKeypair {
        return WalletKeypair{
            .inner = try zledger.generateKeypair(allocator),
        };
    }

    pub fn signTransaction(self: WalletKeypair, tx_data: []const u8) !zledger.Signature {
        return try zledger.signMessage(tx_data, self.inner);
    }
};
```

### Transaction Signing in Zwallet

**Before:**
```zig
// zwallet/src/transaction.zig
const zsig = @import("zsig");
const zledger = @import("zledger");

pub fn processWalletTransaction(wallet: *Wallet, to_address: []const u8, amount: i64) !void {
    // Create transaction
    const tx = zledger.Transaction{ /* ... */ };

    // Sign with zsig
    const tx_json = try std.json.stringifyAlloc(wallet.allocator, tx, .{});
    defer wallet.allocator.free(tx_json);

    const signature = try zsig.signMessage(tx_json, wallet.keypair);

    // Verify
    if (!zsig.verifySignature(tx_json, &signature.bytes, &wallet.keypair.publicKey())) {
        return error.InvalidSignature;
    }

    // Process...
}
```

**After:**
```zig
// zwallet/src/transaction.zig
const zledger = @import("zledger");

pub fn processWalletTransaction(wallet: *Wallet, to_address: []const u8, amount: i64) !void {
    // Create transaction
    const tx = zledger.Transaction{ /* ... */ };

    // Sign with integrated zsig (via zledger)
    const tx_json = try std.json.stringifyAlloc(wallet.allocator, tx, .{});
    defer wallet.allocator.free(tx_json);

    const signature = try zledger.signMessage(tx_json, wallet.keypair);

    // Verify
    if (!zledger.verifySignature(tx_json, &signature.bytes, &wallet.keypair.publicKey())) {
        return error.InvalidSignature;
    }

    // Process...
}
```

## 💼 Step 5: Update Wallet-Specific Features

### HD Wallet Implementation

**Before:**
```zig
// zwallet/src/hd_wallet.zig
const zsig = @import("zsig");

pub const HDWallet = struct {
    master_key: zsig.Keypair,

    pub fn deriveChild(self: HDWallet, index: u32, allocator: std.mem.Allocator) !zsig.Keypair {
        // Derivation logic using zsig
        const seed = self.computeChildSeed(index);
        return zsig.keypairFromSeed(seed);
    }
};
```

**After:**
```zig
// zwallet/src/hd_wallet.zig
const zledger = @import("zledger");

pub const HDWallet = struct {
    master_key: zledger.Keypair,

    pub fn deriveChild(self: HDWallet, index: u32, allocator: std.mem.Allocator) !zledger.Keypair {
        // Derivation logic using integrated zsig
        const seed = self.computeChildSeed(index);
        return zledger.zsig.keypairFromSeed(seed);
    }
};
```

### Batch Transaction Signing

**Before:**
```zig
// zwallet/src/batch.zig
const zsig = @import("zsig");

pub fn signTransactionBatch(transactions: []const []const u8, keypair: zsig.Keypair, allocator: std.mem.Allocator) ![]zsig.Signature {
    return try zsig.signBatch(allocator, transactions, keypair);
}
```

**After:**
```zig
// zwallet/src/batch.zig
const zledger = @import("zledger");

pub fn signTransactionBatch(transactions: []const []const u8, keypair: zledger.Keypair, allocator: std.mem.Allocator) ![]zledger.Signature {
    return try zledger.zsig.signBatch(allocator, transactions, keypair);
}
```

## 🗂️ Step 6: Update Wallet Data Structures

### Wallet Configuration

**Before:**
```zig
// zwallet/src/wallet.zig
const zsig = @import("zsig");
const zledger = @import("zledger");

pub const Wallet = struct {
    name: []const u8,
    keypair: zsig.Keypair,
    ledger: zledger.Ledger,
    // ...
};
```

**After:**
```zig
// zwallet/src/wallet.zig
const zledger = @import("zledger");

pub const Wallet = struct {
    name: []const u8,
    keypair: zledger.Keypair,  // Now using zledger.Keypair
    ledger: zledger.Ledger,
    // ...
};
```

### Key Storage Format

**Before:**
```zig
pub fn saveWallet(wallet: Wallet, path: []const u8, allocator: std.mem.Allocator) !void {
    const key_bundle = try wallet.keypair.exportBundle(allocator);
    defer allocator.free(key_bundle);

    const wallet_data = WalletData{
        .name = wallet.name,
        .key_bundle = key_bundle,
    };

    // Save to file...
}
```

**After:**
```zig
// Same code works! The API is compatible
pub fn saveWallet(wallet: Wallet, path: []const u8, allocator: std.mem.Allocator) !void {
    const key_bundle = try wallet.keypair.exportBundle(allocator);
    defer allocator.free(key_bundle);

    const wallet_data = WalletData{
        .name = wallet.name,
        .key_bundle = key_bundle,
    };

    // Save to file...
}
```

## 🧪 Step 7: Update Tests

**Before:**
```zig
// zwallet/tests/crypto_test.zig
const zsig = @import("zsig");
const std = @import("std");

test "wallet key generation" {
    const allocator = std.testing.allocator;
    const keypair = try zsig.generateKeypair(allocator);

    // Test signing
    const message = "test transaction";
    const signature = try zsig.signMessage(message, keypair);

    // Verify
    try std.testing.expect(zsig.verifySignature(message, &signature.bytes, &keypair.publicKey()));
}
```

**After:**
```zig
// zwallet/tests/crypto_test.zig
const zledger = @import("zledger");
const std = @import("std");

test "wallet key generation" {
    const allocator = std.testing.allocator;
    const keypair = try zledger.generateKeypair(allocator);

    // Test signing
    const message = "test transaction";
    const signature = try zledger.signMessage(message, keypair);

    // Verify
    try std.testing.expect(zledger.verifySignature(message, &signature.bytes, &keypair.publicKey()));
}
```

## 🚀 Step 8: Leverage New v0.5.0 Features

### Enhanced Ledger Integration

```zig
// zwallet/src/enhanced_wallet.zig
const zledger = @import("zledger");

pub const EnhancedWallet = struct {
    keypair: zledger.Keypair,
    ledger: zledger.Ledger,

    pub fn createSignedTransaction(self: *EnhancedWallet, to: []const u8, amount: i64) ![]const u8 {
        // Create transaction
        const tx = zledger.Transaction{
            .id = try generateTxId(),
            .from_account = self.getAddress(),
            .to_account = to,
            .amount = amount,
            .currency = "USD",
            .timestamp = std.time.timestamp(),
            .memo = null,
        };

        // Add to ledger (automatic double-entry)
        try self.ledger.addTransaction(tx);

        // Sign transaction for external verification
        const tx_json = try std.json.stringifyAlloc(self.allocator, tx, .{});
        defer self.allocator.free(tx_json);

        const signature = try zledger.signMessage(tx_json, self.keypair);

        // Return signed transaction data
        return try createSignedTxBundle(tx, signature, self.allocator);
    }

    pub fn verifyExternalTransaction(tx_data: []const u8, signature: zledger.Signature, sender_pubkey: [32]u8) bool {
        return zledger.verifySignature(tx_data, &signature.bytes, &sender_pubkey);
    }
};
```

### Multi-Signature Wallet Support

```zig
// zwallet/src/multisig.zig
const zledger = @import("zledger");

pub const MultiSigWallet = struct {
    required_signatures: u8,
    signers: []zledger.Keypair,
    ledger: zledger.Ledger,

    pub fn signTransaction(self: MultiSigWallet, tx_data: []const u8, allocator: std.mem.Allocator) ![]zledger.Signature {
        var signatures = std.ArrayList(zledger.Signature).init(allocator);
        defer signatures.deinit();

        // Sign with all available keys
        for (self.signers) |signer| {
            const sig = try zledger.signMessage(tx_data, signer);
            try signatures.append(sig);
        }

        return signatures.toOwnedSlice();
    }

    pub fn verifyMultiSig(tx_data: []const u8, signatures: []zledger.Signature, public_keys: [][32]u8, required: u8) bool {
        var valid_count: u8 = 0;

        for (signatures, public_keys) |sig, pubkey| {
            if (zledger.verifySignature(tx_data, &sig.bytes, &pubkey)) {
                valid_count += 1;
            }
        }

        return valid_count >= required;
    }
};
```

## ⚠️ Migration Checklist

- [ ] **Remove zsig dependency** from `build.zig.zon`
- [ ] **Update zledger** to v0.5.0 in `build.zig.zon`
- [ ] **Update build.zig** to remove zsig import
- [ ] **Replace all zsig imports** with zledger in source files
- [ ] **Update function calls** to use `zledger.signMessage`, `zledger.generateKeypair`, etc.
- [ ] **Update type declarations** to use `zledger.Keypair`, `zledger.Signature`
- [ ] **Update tests** to use new import structure
- [ ] **Verify compilation** with `zig build`
- [ ] **Run tests** to ensure compatibility: `zig build test`
- [ ] **Test wallet functionality** with new integrated crypto

## 🔍 Common Issues and Solutions

### Issue: "no module named 'zsig' available"

**Problem:** Still importing zsig directly
```zig
const zsig = @import("zsig"); // ❌ Will fail
```

**Solution:** Use zledger import
```zig
const zledger = @import("zledger"); // ✅ Correct
// Use: zledger.zsig.* or zledger.generateKeypair
```

### Issue: Type mismatch errors

**Problem:** Mixed old and new types
```zig
const old_keypair: zsig.Keypair = ...;  // ❌ Old type
const new_sig = try zledger.signMessage(..., old_keypair); // ❌ Type mismatch
```

**Solution:** Consistent type usage
```zig
const keypair: zledger.Keypair = try zledger.generateKeypair(allocator); // ✅ Consistent
const signature = try zledger.signMessage(..., keypair); // ✅ Works
```

## 📊 Benefits of Migration

1. **Reduced Dependencies** - One package instead of two
2. **Better Integration** - Ledger and crypto work seamlessly
3. **Simplified Build** - Less configuration needed
4. **Enhanced Security** - Integrated audit trails with signatures
5. **Future-Proof** - Active development continues in zledger
6. **Performance** - Optimized batch operations

## 🚀 Post-Migration Opportunities

After migrating, consider leveraging these new v0.5.0 features:

1. **Integrated Audit Trails** - Automatic transaction signing
2. **Batch Operations** - Efficient multi-transaction processing
3. **Enhanced CLI** - Built-in keygen, sign, verify commands
4. **Better Asset Support** - Multi-currency with crypto signing
5. **WebAssembly Ready** - Deploy wallet to browser environments

## 📞 Support

If you encounter issues during migration:

1. Check the [API documentation](./docs/api/)
2. Review [integration examples](./docs/examples/)
3. Test with the [basic usage example](./docs/examples/getting-started/basic-usage.md)
4. Open an issue on GitHub for additional support

The migration should be straightforward as the APIs remain largely compatible, with zsig now accessible through the zledger namespace.