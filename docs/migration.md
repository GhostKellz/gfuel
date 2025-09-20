# Migration Guide: From zwallet to GFuel

This guide documents the migration from zwallet to GFuel, including the integration of zledger v0.5.0 with integrated zsig functionality.

## Overview

GFuel is the evolution of zwallet with significant improvements:

- **Rebranding**: Complete transition from "zwallet" to "GFuel"
- **zledger v0.5.0**: Integrated zsig functionality eliminates separate zsig dependency
- **Enhanced Privacy**: Improved Shroud integration
- **Better Architecture**: Cleaner separation of concerns
- **Updated APIs**: More intuitive and consistent interfaces

## Breaking Changes

### 1. Project Name and Imports

**Before (zwallet):**
```zig
const zwallet = @import("zwallet");
```

**After (GFuel):**
```zig
const gfuel = @import("gfuel");
```

### 2. Cryptographic API Changes

#### KeyPair Structure

**Before (zwallet with separate zsig):**
```zig
const zsig = @import("zsig");

pub const KeyPair = struct {
    public_key: [32]u8,
    private_key: [32]u8,
    key_type: KeyType,

    pub fn sign(self: *const KeyPair, message: []const u8) ![]u8 {
        return zsig.sign(message, self.private_key);
    }
};
```

**After (GFuel with integrated zledger):**
```zig
const zledger = @import("zledger");

pub const KeyPair = struct {
    inner: zledger.Keypair,
    key_type: KeyType,

    pub fn sign(self: *const KeyPair, message: []const u8, allocator: Allocator) !zledger.Signature {
        return try zledger.signMessage(message, self.inner);
    }

    pub fn publicKey(self: *const KeyPair) [32]u8 {
        return self.inner.publicKey();
    }
};
```

#### Key Generation

**Before:**
```zig
var keypair = try KeyPair.generate(.ed25519);
const pub_key = keypair.public_key;
```

**After:**
```zig
var keypair = try KeyPair.generate(.ed25519, allocator);
defer keypair.deinit();
const pub_key = keypair.publicKey();
```

### 3. Wallet API Changes

#### Wallet Creation

**Before:**
```zig
var wallet = try zwallet.createWallet(allocator, "passphrase", .hybrid);
```

**After:**
```zig
var wallet = try gfuel.wallet.Wallet.create(allocator, "passphrase", .hybrid, null);
```

#### Account Creation

**Before:**
```zig
const account = try wallet.createAccount(.ethereum, .secp256k1);
```

**After:**
```zig
try wallet.createAccount(.ethereum, .secp256k1, "Account Name");
```

### 4. Transaction API Changes

#### Transaction Creation

**Before:**
```zig
var tx = try zwallet.Transaction.create(allocator, .ethereum, from, to, amount);
```

**After:**
```zig
var tx = try gfuel.transaction.ProtocolFactory.createTransaction(
    allocator, .ethereum, from, to, amount
);
defer tx.deinit(allocator);
```

#### Transaction Signing

**Before:**
```zig
try tx.sign(private_key);
```

**After:**
```zig
try tx.sign(allocator, private_key);
```

### 5. FFI Changes

#### Function Names

**Before (zwallet):**
```c
zwallet_init()
zwallet_create_wallet()
zwallet_destroy()
```

**After (GFuel):**
```c
gfuel_init()
gfuel_create_wallet()
gfuel_destroy()
```

#### Structure Names

**Before:**
```c
typedef struct {
    void* wallet_ptr;
    bool is_valid;
} ZWalletContext;
```

**After:**
```c
typedef struct {
    void* wallet_ptr;
    void* allocator_ptr;
    bool is_valid;
} GFuelContext;
```

## Migration Steps

### Step 1: Update Dependencies

#### build.zig.zon

**Remove:**
```zig
.dependencies = .{
    .zsig = .{
        .url = "https://github.com/ghostkellz/zsig/archive/main.tar.gz",
        .hash = "...",
    },
    .zledger = .{
        .url = "https://github.com/ghostkellz/zledger/archive/v0.4.0.tar.gz",
        .hash = "...",
    },
},
```

**Add:**
```zig
.dependencies = .{
    .zledger = .{
        .url = "https://github.com/ghostkellz/zledger/archive/v0.5.0.tar.gz",
        .hash = "1220f01c1b3c8c4b95b8a9b9c123456789abcdef...",
    },
    .shroud = .{
        .url = "https://github.com/ghostkellz/shroud/archive/v1.2.4.tar.gz",
        .hash = "1220a1b2c3d4e5f6789012345678901234567890...",
    },
},
```

#### build.zig

**Before:**
```zig
const zsig = b.dependency("zsig", .{});
const zledger = b.dependency("zledger", .{});

exe.root_module.addImport("zsig", zsig.module("zsig"));
exe.root_module.addImport("zledger", zledger.module("zledger"));
```

**After:**
```zig
const zledger = b.dependency("zledger", .{});
const shroud = b.dependency("shroud", .{});

exe.root_module.addImport("zledger", zledger.module("zledger"));
exe.root_module.addImport("shroud", shroud.module("shroud"));
```

### Step 2: Update Imports

#### Source Files

Find and replace across all `.zig` files:

```bash
# Update imports
sed -i 's/@import("zwallet")/@import("gfuel")/g' src/**/*.zig
sed -i 's/@import("zsig")//g' src/**/*.zig  # Remove zsig imports
sed -i 's/const zsig = @import("zsig");//g' src/**/*.zig

# Update references
sed -i 's/zwallet\./gfuel\./g' src/**/*.zig
```

### Step 3: Update Crypto Code

#### Migrate KeyPair Usage

**Before:**
```zig
const zsig = @import("zsig");

pub fn signMessage(message: []const u8, private_key: [32]u8) ![]u8 {
    return try zsig.sign(message, private_key);
}

pub fn verifyMessage(message: []const u8, signature: []const u8, public_key: [32]u8) bool {
    return zsig.verify(message, signature, public_key);
}
```

**After:**
```zig
const zledger = @import("zledger");

pub fn signMessage(message: []const u8, keypair: zledger.Keypair) !zledger.Signature {
    return try zledger.signMessage(message, keypair);
}

pub fn verifyMessage(message: []const u8, signature: *const zledger.Signature, public_key: *const [32]u8) bool {
    return zledger.verifySignature(message, &signature.bytes, public_key);
}
```

### Step 4: Update Wallet Code

#### Account Management

**Before:**
```zig
pub fn createAccount(self: *Wallet, protocol: Protocol, key_type: KeyType) !Account {
    var keypair = try crypto.KeyPair.generate(key_type);

    return Account{
        .address = try generateAddress(&keypair.public_key, protocol),
        .protocol = protocol,
        .keypair = keypair,
    };
}
```

**After:**
```zig
pub fn createAccount(self: *Wallet, protocol: Protocol, key_type: KeyType, name: ?[]const u8) !void {
    var keypair = try crypto.KeyPair.generate(key_type, self.allocator);

    const pub_key = keypair.publicKey();
    const address = try generateAddress(self.allocator, &pub_key, protocol);

    const account = Account{
        .address = address,
        .protocol = protocol,
        .key_type = key_type,
        .keypair = keypair,
        .name = if (name) |n| try self.allocator.dupe(u8, n) else null,
        // ... other fields
    };

    try self.accounts.append(self.allocator, account);
}
```

### Step 5: Update FFI Code

#### Function Signatures

**Before:**
```zig
export fn zwallet_create_wallet(
    ctx: *ZWalletContext,
    passphrase: [*:0]const u8,
    passphrase_len: u32,
) c_int {
    // Implementation
}
```

**After:**
```zig
export fn gfuel_create_wallet(
    ctx: *GFuelContext,
    passphrase: [*:0]const u8,
    passphrase_len: u32,
    wallet_name: [*:0]const u8,
    wallet_name_len: u32,
    device_bound: bool,
) c_int {
    // Implementation
}
```

### Step 6: Update Documentation and Examples

#### README Updates

**Before:**
```markdown
# ZWallet - Secure Wallet for Zig

ZWallet provides secure cryptocurrency wallet functionality...
```

**After:**
```markdown
# GFuel - Secure, Programmable Wallet for Zig

GFuel provides secure cryptocurrency wallet functionality...
```

#### Example Code

Update all example files:

```bash
# Update example files
find examples/ -name "*.zig" -exec sed -i 's/zwallet/gfuel/g' {} \;
find examples/ -name "*.zig" -exec sed -i 's/ZWallet/GFuel/g' {} \;
```

## Automated Migration Script

Create a migration script to automate the process:

```bash
#!/bin/bash
# migrate_to_gfuel.sh

set -e

echo "🚀 Starting migration from zwallet to GFuel..."

# 1. Update build files
echo "📦 Updating build configuration..."
sed -i 's/zwallet/gfuel/g' build.zig
sed -i 's/zwallet/gfuel/g' build.zig.zon

# Remove zsig dependency from build.zig.zon
sed -i '/zsig.*{/,/},/d' build.zig.zon

# 2. Update source files
echo "🔧 Updating source files..."
find src/ -name "*.zig" -exec sed -i 's/@import("zwallet")/@import("gfuel")/g' {} \;
find src/ -name "*.zig" -exec sed -i 's/@import("zsig")//g' {} \;
find src/ -name "*.zig" -exec sed -i '/const zsig = @import("zsig");/d' {} \;
find src/ -name "*.zig" -exec sed -i 's/zwallet\./gfuel\./g' {} \;

# 3. Update FFI exports
echo "🔌 Updating FFI exports..."
find src/ -name "*.zig" -exec sed -i 's/zwallet_/gfuel_/g' {} \;
find src/ -name "*.zig" -exec sed -i 's/ZWallet/GFuel/g' {} \;

# 4. Update examples
echo "📖 Updating examples..."
find examples/ -name "*.zig" -exec sed -i 's/zwallet/gfuel/g' {} \;
find examples/ -name "*.zig" -exec sed -i 's/ZWallet/GFuel/g' {} \;

# 5. Update documentation
echo "📚 Updating documentation..."
find . -name "*.md" -exec sed -i 's/zwallet/gfuel/g' {} \;
find . -name "*.md" -exec sed -i 's/ZWallet/GFuel/g' {} \;

# 6. Test build
echo "🔨 Testing build..."
zig build

echo "✅ Migration completed successfully!"
echo "⚠️  Please manually review:"
echo "   - Crypto API usage (KeyPair methods)"
echo "   - Transaction signing (added allocator parameter)"
echo "   - Error handling (updated error types)"
echo "   - FFI integration (updated function signatures)"
```

## Testing Migration

### Verification Checklist

- [ ] **Build succeeds** with `zig build`
- [ ] **Tests pass** with `zig build test`
- [ ] **Examples run** without errors
- [ ] **FFI functions export** correctly
- [ ] **Documentation updated** consistently
- [ ] **No zsig references** remain in code
- [ ] **zledger v0.5.0** is being used

### Test Script

```bash
#!/bin/bash
# test_migration.sh

echo "🧪 Testing GFuel migration..."

# Test build
if zig build; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Test examples
if ./zig-out/bin/gfuel_example; then
    echo "✅ Basic example works"
else
    echo "❌ Basic example failed"
    exit 1
fi

if ./zig-out/bin/gfuel_shroud_cli; then
    echo "✅ Shroud example works"
else
    echo "❌ Shroud example failed"
    exit 1
fi

# Test CLI help
if ./zig-out/bin/gfuel help >/dev/null; then
    echo "✅ CLI help works"
else
    echo "❌ CLI help failed"
    exit 1
fi

echo "✅ All migration tests passed!"
```

## Troubleshooting

### Common Issues

#### 1. Build Errors

**Error:** `error: no member named 'public_key' in struct`
**Solution:** Update to use `keypair.publicKey()` method

**Error:** `error: expected 2 argument(s), found 1`
**Solution:** Add allocator parameter to function calls

#### 2. Import Errors

**Error:** `error: unable to find 'zsig'`
**Solution:** Remove all zsig imports and references

**Error:** `error: unable to find 'zwallet'`
**Solution:** Update imports to use `gfuel`

#### 3. Runtime Errors

**Error:** Memory leaks in examples
**Solution:** Ensure `defer deinit()` calls are present

**Error:** Signature verification fails
**Solution:** Update to use zledger signature types

### Getting Help

If you encounter issues during migration:

1. **Check the build logs** for specific error messages
2. **Review the examples** for correct usage patterns
3. **Consult the API documentation** for updated function signatures
4. **Test incrementally** by migrating one module at a time

## Benefits After Migration

### Performance Improvements

- **Faster key generation** with optimized zledger
- **Better memory management** with integrated allocators
- **Reduced binary size** without separate zsig dependency

### New Features

- **Enhanced privacy** with improved Shroud integration
- **Better audit trails** with zledger v0.5.0
- **More protocols** supported out of the box
- **Improved FFI** with better error handling

### Developer Experience

- **Cleaner APIs** with consistent naming
- **Better documentation** with comprehensive examples
- **Improved testing** with integrated test suite
- **Modern Zig practices** with current language features

This migration guide ensures a smooth transition from zwallet to GFuel while taking advantage of all the new features and improvements.