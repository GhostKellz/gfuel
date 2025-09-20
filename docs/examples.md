# Examples Documentation

This document provides comprehensive examples for using GFuel in various scenarios, from basic wallet operations to advanced privacy features.

## Basic Examples

### Simple Wallet Creation and Usage

```zig
const std = @import("std");
const gfuel = @import("gfuel");

pub fn basicWalletExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new wallet
    var wallet = try gfuel.wallet.Wallet.create(
        allocator,
        "secure_passphrase_123",
        .hybrid,
        null
    );
    defer wallet.deinit();

    std.debug.print("✅ Wallet created successfully!\n", .{});

    // Create accounts for different protocols
    try wallet.createAccount(.ghostchain, .ed25519, "Main GCC Account");
    try wallet.createAccount(.ethereum, .secp256k1, "ETH Trading Account");
    try wallet.createAccount(.stellar, .ed25519, "XLM Savings Account");

    std.debug.print("📁 Created {} accounts\n", .{wallet.accounts.items.len});

    // List all accounts
    for (wallet.accounts.items, 0..) |account, i| {
        std.debug.print("  Account {}: {} - {s}\n", .{
            i + 1,
            account.protocol,
            account.address
        });
    }
}
```

### Transaction Creation and Signing

```zig
pub fn transactionExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a GhostChain transaction
    var gc_tx = try gfuel.transaction.GhostChain.createTransaction(
        allocator,
        "gc1sender123456789abcdef",
        "gc1recipient987654321fedcba",
        1000000 // 1 GCC in micro-units
    );
    defer gc_tx.deinit(allocator);

    std.debug.print("💰 Transaction created:\n", .{});
    std.debug.print("  From: {s}\n", .{gc_tx.from});
    std.debug.print("  To: {s}\n", .{gc_tx.to});
    std.debug.print("  Amount: {} micro-units\n", .{gc_tx.amount});

    // Sign the transaction
    const private_key = "test_private_key_32_bytes_exactly!";
    try gc_tx.sign(allocator, private_key);

    if (gc_tx.signature) |sig| {
        std.debug.print("✅ Transaction signed: {}\n", .{std.fmt.fmtSliceHexLower(sig[0..8])});
    }

    // Estimate fee
    const fee = gfuel.transaction.GhostChain.estimateFee(gc_tx.amount);
    std.debug.print("💸 Estimated fee: {} micro-units\n", .{fee});
}
```

## Multi-Protocol Examples

### Cross-Protocol Wallet Management

```zig
pub fn multiProtocolExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var wallet = try gfuel.wallet.Wallet.create(
        allocator,
        "multi_protocol_passphrase",
        .hybrid,
        null
    );
    defer wallet.deinit();

    // Protocol configurations
    const protocols = [_]gfuel.wallet.Protocol{ .ghostchain, .ethereum, .stellar, .hedera };
    const key_types = [_]gfuel.wallet.KeyType{ .ed25519, .secp256k1, .ed25519, .ed25519 };
    const names = [_][]const u8{ "GhostChain Main", "Ethereum Trading", "Stellar Savings", "Hedera Operations" };

    // Create accounts for each protocol
    for (protocols, key_types, names) |protocol, key_type, name| {
        try wallet.createAccount(protocol, key_type, name);
        std.debug.print("✅ Created {} account: {s}\n", .{ protocol, name });
    }

    // Create transactions for each protocol
    const amounts = [_]i64{ 1000000, 1000000000000000000, 10000000, 100000000 };
    const to_addresses = [_][]const u8{
        "gc1recipient123...",
        "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
        "GBXXIIPRN6ZXJJYJ7LJM7HW5C36MM2GGDLDKPIHVK3Q7GSLMXXQFVVCO",
        "0.0.789012"
    };

    for (protocols, amounts, to_addresses) |protocol, amount, to_addr| {
        const from_addr = wallet.accounts.items[@intFromEnum(protocol)].address;

        var tx = try gfuel.transaction.ProtocolFactory.createTransaction(
            allocator,
            protocol,
            from_addr,
            to_addr,
            amount
        );
        defer tx.deinit(allocator);

        const fee = gfuel.transaction.ProtocolFactory.estimateFee(
            protocol,
            amount,
            if (protocol == .ethereum) @as(?u64, 21000) else null,
            if (protocol == .ethereum) @as(?i64, 20000000000) else null
        );

        std.debug.print("🔄 {}: {} -> {} (fee: {})\n", .{ protocol, amount, to_addr[0..12], fee });
    }
}
```

## Privacy and Shroud Examples

### Privacy-Focused Wallet with Shroud

```zig
const shroud = @import("shroud");
const zledger = @import("zledger");

pub fn privacyWalletExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🛡️ Creating privacy-focused wallet...\n", .{});

    // Create wallet with privacy features
    var wallet = try gfuel.wallet.Wallet.create(
        allocator,
        "privacy_passphrase_secure",
        .privacy_focused,
        null
    );
    defer wallet.deinit();

    // Verify privacy components are initialized
    if (wallet.shroud_guardian) |guardian| {
        std.debug.print("✅ Shroud guardian active\n", .{});
        _ = guardian;
    }

    if (wallet.audit_ledger) |ledger| {
        std.debug.print("✅ Audit ledger active\n", .{});
        _ = ledger;
    }

    // Create ephemeral identity
    var ephemeral_identity = shroud.identity.Identity.init(
        allocator,
        "ephemeral_session_id",
        .{ .bytes = [_]u8{0x42} ** 32 }
    );
    defer ephemeral_identity.deinit();

    std.debug.print("🔐 Ephemeral identity created: {s}\n", .{ephemeral_identity.id});

    // Set up access control
    if (wallet.shroud_guardian) |*guardian| {
        try guardian.addRole("privacy_user", &[_]shroud.guardian.Permission{ .read, .write });

        const has_access = guardian.validateRole("privacy_user");
        std.debug.print("🔑 Access validation: {}\n", .{has_access});
    }

    // Create privacy transaction
    try wallet.createAccount(.ethereum, .secp256k1, "Privacy ETH Account");

    var private_tx = try gfuel.transaction.Ethereum.createPrivateTransaction(
        allocator,
        "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
        "0x123456789abcdef123456789abcdef123456789a",
        500000000000000000, // 0.5 ETH
        &ephemeral_identity
    );
    defer private_tx.deinit(allocator);

    std.debug.print("🔒 Private transaction created\n", .{});

    if (private_tx.metadata) |metadata| {
        std.debug.print("📋 Privacy metadata: {s}\n", .{metadata[0..@min(50, metadata.len)]});
    }

    std.debug.print("✅ Privacy wallet example completed\n", .{});
}
```

### Audit Trail with zledger

```zig
pub fn auditTrailExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("📊 Audit trail example starting...\n", .{});

    // Create audit ledger
    var audit_ledger = zledger.journal.Journal.init(allocator, null);
    defer audit_ledger.deinit();

    // Create transaction with audit trail
    var tx = try gfuel.transaction.GhostChain.createTransactionWithAudit(
        allocator,
        "gc1sender123456789abcdef",
        "gc1recipient987654321fedcba",
        2000000, // 2 GCC
        &audit_ledger
    );
    defer tx.deinit(allocator);

    std.debug.print("💰 Transaction with audit created\n", .{});

    if (tx.ledger_entry_id) |entry_id| {
        std.debug.print("📋 Audit entry ID: {s}\n", .{entry_id});
    }

    // Add more audit entries
    const additional_txs = [_]struct { from: []const u8, to: []const u8, amount: i64 }{
        .{ .from = "gc1alice123...", .to = "gc1bob456...", .amount = 500000 },
        .{ .from = "gc1bob456...", .to = "gc1charlie789...", .amount = 750000 },
        .{ .from = "gc1charlie789...", .to = "gc1alice123...", .amount = 250000 },
    };

    for (additional_txs) |tx_data| {
        const ledger_tx = try zledger.tx.Transaction.init(
            allocator,
            tx_data.amount,
            "GCC",
            tx_data.from,
            tx_data.to,
            "Audit trail test transaction"
        );
        try audit_ledger.append(ledger_tx);
    }

    std.debug.print("📈 Added {} audit entries\n", .{audit_ledger.entries.items.len});

    // Verify audit trail integrity
    const integrity_verified = try audit_ledger.verifyIntegrity();
    std.debug.print("🔍 Audit integrity verified: {}\n", .{integrity_verified});

    if (integrity_verified) {
        std.debug.print("✅ All audit entries are valid\n", .{});
        std.debug.print("📊 Total audit entries: {}\n", .{audit_ledger.entries.items.len});
    }
}
```

## Advanced Cryptography Examples

### Key Generation and Signing

```zig
pub fn cryptographyExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🔐 Cryptography example starting...\n", .{});

    // Generate different key types
    const key_types = [_]gfuel.crypto.KeyType{ .ed25519, .secp256k1, .curve25519 };

    for (key_types) |key_type| {
        std.debug.print("\n🔑 Testing {} keys...\n", .{key_type});

        // Generate keypair
        var keypair = try gfuel.crypto.KeyPair.generate(key_type, allocator);
        defer keypair.deinit();

        // Get public key
        const public_key = keypair.publicKey();
        std.debug.print("  Public key: {}\n", .{std.fmt.fmtSliceHexLower(public_key[0..8])});

        // Sign a message
        const message = "Hello, GFuel cryptography!";
        const signature = try keypair.sign(message, allocator);
        std.debug.print("  Signature: {}\n", .{std.fmt.fmtSliceHexLower(signature.bytes[0..8])});

        // Verify signature
        const is_valid = keypair.verify(message, &signature);
        std.debug.print("  Verification: {}\n", .{if (is_valid) "✅ Valid" else "❌ Invalid"});

        // Test with wrong message
        const wrong_message = "Wrong message";
        const wrong_verify = keypair.verify(wrong_message, &signature);
        std.debug.print("  Wrong message verification: {}\n", .{if (wrong_verify) "❌ Should be invalid" else "✅ Correctly invalid"});
    }

    // Deterministic key generation from seed
    std.debug.print("\n🌱 Deterministic key generation...\n", .{});

    var seed: [32]u8 = undefined;
    @memcpy(&seed, "this_is_a_test_seed_32_bytes!");

    var keypair1 = try gfuel.crypto.KeyPair.fromSeed(seed, .ed25519, allocator);
    defer keypair1.deinit();

    var keypair2 = try gfuel.crypto.KeyPair.fromSeed(seed, .ed25519, allocator);
    defer keypair2.deinit();

    const pub1 = keypair1.publicKey();
    const pub2 = keypair2.publicKey();

    const keys_match = std.mem.eql(u8, &pub1, &pub2);
    std.debug.print("  Same seed produces same keys: {}\n", .{if (keys_match) "✅ Yes" else "❌ No"});
}
```

## FFI Integration Examples

### C Integration Example

Create a C wrapper for GFuel:

```c
// gfuel_wrapper.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "gfuel.h" // Generated from Zig FFI

typedef struct {
    GFuelContext context;
    int is_initialized;
} GFuelWrapper;

GFuelWrapper* gfuel_wrapper_init(void) {
    GFuelWrapper* wrapper = malloc(sizeof(GFuelWrapper));
    if (!wrapper) return NULL;

    wrapper->context = gfuel_init();
    wrapper->is_initialized = wrapper->context.is_valid;

    return wrapper;
}

int gfuel_wrapper_create_wallet(GFuelWrapper* wrapper, const char* passphrase, const char* name) {
    if (!wrapper || !wrapper->is_initialized) {
        return FFI_ERROR_INVALID_PARAM;
    }

    return gfuel_create_wallet(
        &wrapper->context,
        passphrase,
        strlen(passphrase),
        name,
        name ? strlen(name) : 0,
        false // Not device-bound
    );
}

int gfuel_wrapper_create_account(GFuelWrapper* wrapper, uint32_t protocol, uint32_t key_type, WalletAccount* account) {
    if (!wrapper || !wrapper->is_initialized) {
        return FFI_ERROR_INVALID_PARAM;
    }

    return gfuel_create_account(&wrapper->context, protocol, key_type, account);
}

void gfuel_wrapper_destroy(GFuelWrapper* wrapper) {
    if (wrapper) {
        if (wrapper->is_initialized) {
            gfuel_destroy(&wrapper->context);
        }
        free(wrapper);
    }
}

// Example usage
int main() {
    printf("🚀 GFuel C Integration Example\n");

    // Initialize wrapper
    GFuelWrapper* wallet = gfuel_wrapper_init();
    if (!wallet) {
        fprintf(stderr, "❌ Failed to initialize GFuel\n");
        return 1;
    }

    // Create wallet
    int result = gfuel_wrapper_create_wallet(wallet, "c_integration_passphrase", "C Test Wallet");
    if (result != FFI_SUCCESS) {
        fprintf(stderr, "❌ Failed to create wallet: %d\n", result);
        gfuel_wrapper_destroy(wallet);
        return 1;
    }

    printf("✅ Wallet created successfully\n");

    // Create GhostChain account
    WalletAccount gc_account;
    result = gfuel_wrapper_create_account(wallet, 0, 0, &gc_account); // GhostChain, Ed25519
    if (result == FFI_SUCCESS) {
        printf("✅ GhostChain account created: %.*s\n", gc_account.address_len, gc_account.address);
        printf("   Protocol: %u, Key type: %u\n", gc_account.protocol, gc_account.key_type);
    }

    // Create Ethereum account
    WalletAccount eth_account;
    result = gfuel_wrapper_create_account(wallet, 1, 1, &eth_account); // Ethereum, secp256k1
    if (result == FFI_SUCCESS) {
        printf("✅ Ethereum account created: %.*s\n", eth_account.address_len, eth_account.address);
    }

    // Clean up
    gfuel_wrapper_destroy(wallet);
    printf("🧹 Cleanup completed\n");

    return 0;
}
```

### Python Integration Example

Using ctypes to interface with GFuel:

```python
# gfuel_python.py
import ctypes
import os
from ctypes import Structure, c_void_p, c_uint32, c_bool, c_char_p, c_uint8, c_int64

# Load GFuel library
lib_path = "./zig-out/lib/libgfuel.so"  # Linux
# lib_path = "./zig-out/lib/libgfuel.dylib"  # macOS
# lib_path = "./zig-out/lib/gfuel.dll"  # Windows

gfuel = ctypes.CDLL(lib_path)

# Define structures
class GFuelContext(Structure):
    _fields_ = [
        ("wallet_ptr", c_void_p),
        ("allocator_ptr", c_void_p),
        ("is_valid", c_bool)
    ]

class WalletAccount(Structure):
    _fields_ = [
        ("address", c_uint8 * 64),
        ("address_len", c_uint32),
        ("public_key", c_uint8 * 32),
        ("qid", c_uint8 * 16),
        ("protocol", c_uint32),
        ("key_type", c_uint32)
    ]

# Define function signatures
gfuel.gfuel_init.restype = GFuelContext
gfuel.gfuel_destroy.argtypes = [ctypes.POINTER(GFuelContext)]
gfuel.gfuel_create_wallet.argtypes = [
    ctypes.POINTER(GFuelContext),
    c_char_p, c_uint32,
    c_char_p, c_uint32,
    c_bool
]
gfuel.gfuel_create_wallet.restype = ctypes.c_int

gfuel.gfuel_create_account.argtypes = [
    ctypes.POINTER(GFuelContext),
    c_uint32, c_uint32,
    ctypes.POINTER(WalletAccount)
]
gfuel.gfuel_create_account.restype = ctypes.c_int

class GFuelWallet:
    def __init__(self):
        self.context = gfuel.gfuel_init()
        if not self.context.is_valid:
            raise Exception("Failed to initialize GFuel context")

    def create_wallet(self, passphrase, name=None):
        passphrase_bytes = passphrase.encode('utf-8')
        name_bytes = name.encode('utf-8') if name else None

        result = gfuel.gfuel_create_wallet(
            ctypes.byref(self.context),
            passphrase_bytes, len(passphrase_bytes),
            name_bytes, len(name_bytes) if name_bytes else 0,
            False
        )

        if result != 0:
            raise Exception(f"Failed to create wallet: {result}")

    def create_account(self, protocol, key_type):
        account = WalletAccount()
        result = gfuel.gfuel_create_account(
            ctypes.byref(self.context),
            protocol, key_type,
            ctypes.byref(account)
        )

        if result != 0:
            raise Exception(f"Failed to create account: {result}")

        return {
            'address': bytes(account.address[:account.address_len]).decode('utf-8'),
            'protocol': account.protocol,
            'key_type': account.key_type,
            'public_key': bytes(account.public_key)
        }

    def __del__(self):
        if hasattr(self, 'context'):
            gfuel.gfuel_destroy(ctypes.byref(self.context))

# Example usage
def main():
    print("🐍 GFuel Python Integration Example")

    try:
        # Create wallet
        wallet = GFuelWallet()
        wallet.create_wallet("python_integration_passphrase", "Python Test Wallet")
        print("✅ Wallet created successfully")

        # Create accounts
        protocols = [
            (0, "GhostChain"),
            (1, "Ethereum"),
            (2, "Stellar"),
            (3, "Hedera")
        ]

        for protocol_id, protocol_name in protocols:
            key_type = 0 if protocol_id != 1 else 1  # Ed25519 for most, secp256k1 for Ethereum

            try:
                account = wallet.create_account(protocol_id, key_type)
                print(f"✅ {protocol_name} account: {account['address']}")
            except Exception as e:
                print(f"❌ Failed to create {protocol_name} account: {e}")

        print("🧹 Cleanup completed")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
```

## CLI Integration Examples

### Shell Scripts for Automation

```bash
#!/bin/bash
# gfuel_automation.sh - Automated wallet operations

set -e

WALLET_NAME="automated_wallet"
PASSPHRASE="automation_secure_passphrase"

echo "🚀 Starting GFuel automation example"

# Check if wallet exists
if ! gfuel load --name "$WALLET_NAME" 2>/dev/null; then
    echo "📁 Creating new wallet..."
    gfuel generate --type ed25519 --name "$WALLET_NAME"

    echo "🔧 Creating accounts for all protocols..."
    gfuel account create --protocol ghostchain --type ed25519 --name "GC Automated"
    gfuel account create --protocol ethereum --type secp256k1 --name "ETH Automated"
    gfuel account create --protocol stellar --type ed25519 --name "XLM Automated"
else
    echo "✅ Wallet loaded successfully"
fi

# Check balances
echo "💰 Checking balances..."
gfuel balance --all --json > balances.json
cat balances.json | jq '.[] | "\(.protocol): \(.balance) \(.token)"'

# Create test transactions (dry run)
echo "🔄 Testing transactions..."
RECIPIENTS=(
    "gc1test123456789abcdef"
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8"
    "GBXXIIPRN6ZXJJYJ7LJM7HW5C36MM2GGDLDKPIHVK3Q7GSLMXXQFVVCO"
)

TOKENS=("gcc" "eth" "xlm")
AMOUNTS=(100 0.01 10)

for i in "${!RECIPIENTS[@]}"; do
    echo "  Testing ${TOKENS[$i]} transaction..."
    gfuel send \
        --to "${RECIPIENTS[$i]}" \
        --amount "${AMOUNTS[$i]}" \
        --token "${TOKENS[$i]}" \
        --dry-run \
        --json
done

echo "✅ Automation example completed"
```

### Monitoring and Alerts

```bash
#!/bin/bash
# gfuel_monitor.sh - Balance monitoring with alerts

ALERT_THRESHOLD_GCC=1000
ALERT_THRESHOLD_ETH=0.1
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

send_alert() {
    local token=$1
    local balance=$2
    local threshold=$3

    local message="🚨 Low balance alert: $balance $token (threshold: $threshold)"
    echo "$message"

    # Send to Slack (optional)
    if [[ -n "$WEBHOOK_URL" ]]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$WEBHOOK_URL"
    fi
}

check_balance() {
    local token=$1
    local threshold=$2

    local balance_json=$(gfuel balance --token "$token" --json)
    local balance=$(echo "$balance_json" | jq -r '.balance_formatted' | cut -d' ' -f1)

    if (( $(echo "$balance < $threshold" | bc -l) )); then
        send_alert "$token" "$balance" "$threshold"
    else
        echo "✅ $token balance OK: $balance"
    fi
}

echo "📊 Starting balance monitoring..."

while true; do
    echo "$(date): Checking balances..."

    check_balance "gcc" "$ALERT_THRESHOLD_GCC"
    check_balance "eth" "$ALERT_THRESHOLD_ETH"

    sleep 300  # Check every 5 minutes
done
```

## Performance Testing Examples

### Benchmark Script

```zig
const std = @import("std");
const gfuel = @import("gfuel");

pub fn benchmarkExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("⚡ Performance benchmark starting...\n", .{});

    // Benchmark wallet creation
    const wallet_iterations = 10;
    const wallet_start = std.time.milliTimestamp();

    for (0..wallet_iterations) |i| {
        var wallet = try gfuel.wallet.Wallet.generate(allocator, .hybrid);
        defer wallet.deinit();

        try wallet.createAccount(.ghostchain, .ed25519, null);
        _ = i;
    }

    const wallet_duration = std.time.milliTimestamp() - wallet_start;
    std.debug.print("💳 Wallet creation: {}ms per wallet (avg over {} iterations)\n", .{
        @divFloor(wallet_duration, wallet_iterations),
        wallet_iterations
    });

    // Benchmark key generation
    const key_iterations = 100;
    const key_types = [_]gfuel.crypto.KeyType{ .ed25519, .secp256k1 };

    for (key_types) |key_type| {
        const key_start = std.time.milliTimestamp();

        for (0..key_iterations) |i| {
            var keypair = try gfuel.crypto.KeyPair.generate(key_type, allocator);
            defer keypair.deinit();
            _ = i;
        }

        const key_duration = std.time.milliTimestamp() - key_start;
        std.debug.print("🔑 {} key generation: {}ms per key (avg over {} iterations)\n", .{
            key_type,
            @divFloor(key_duration, key_iterations),
            key_iterations
        });
    }

    // Benchmark transaction signing
    const sign_iterations = 1000;
    var keypair = try gfuel.crypto.KeyPair.generate(.ed25519, allocator);
    defer keypair.deinit();

    const message = "Performance test message for signing benchmark";
    const sign_start = std.time.milliTimestamp();

    for (0..sign_iterations) |i| {
        const signature = try keypair.sign(message, allocator);
        _ = signature;
        _ = i;
    }

    const sign_duration = std.time.milliTimestamp() - sign_start;
    std.debug.print("✍️  Ed25519 signing: {}μs per signature (avg over {} iterations)\n", .{
        @divFloor(sign_duration * 1000, sign_iterations),
        sign_iterations
    });

    std.debug.print("✅ Performance benchmark completed\n", .{});
}
```

## Error Handling Examples

### Robust Error Handling

```zig
pub fn errorHandlingExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🛡️ Error handling example starting...\n", .{});

    // Example 1: Wallet creation with error handling
    const wallet_result = gfuel.wallet.Wallet.create(
        allocator,
        "weak", // Weak passphrase for demonstration
        .hybrid,
        null
    );

    var wallet = wallet_result catch |err| switch (err) {
        gfuel.wallet.WalletError.InvalidPassword => {
            std.debug.print("❌ Weak passphrase detected, using stronger one...\n", .{});
            try gfuel.wallet.Wallet.create(allocator, "much_stronger_passphrase_2024!", .hybrid, null);
        },
        gfuel.wallet.WalletError.InsufficientFunds => {
            std.debug.print("❌ Insufficient funds for operation\n", .{});
            return;
        },
        else => {
            std.debug.print("❌ Unexpected wallet error: {}\n", .{err});
            return err;
        },
    };
    defer wallet.deinit();

    std.debug.print("✅ Wallet created with strong passphrase\n", .{});

    // Example 2: Transaction creation with validation
    const invalid_tx_result = gfuel.transaction.Transaction.init(
        allocator,
        .ethereum,
        "invalid_address",
        "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
        1000000000000000000,
        "ETH"
    );

    invalid_tx_result catch |err| switch (err) {
        gfuel.wallet.WalletError.InvalidAddress => {
            std.debug.print("❌ Invalid address detected, using valid address...\n", .{});
        },
        else => {
            std.debug.print("❌ Transaction creation error: {}\n", .{err});
        },
    };

    // Create valid transaction
    var valid_tx = try gfuel.transaction.Transaction.init(
        allocator,
        .ethereum,
        "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
        "0x123456789abcdef123456789abcdef123456789a",
        1000000000000000000,
        "ETH"
    );
    defer valid_tx.deinit(allocator);

    std.debug.print("✅ Valid transaction created\n", .{});

    // Example 3: Key generation with retry logic
    const max_retries = 3;
    var retry_count: u32 = 0;

    const keypair = while (retry_count < max_retries) : (retry_count += 1) {
        const keypair_result = gfuel.crypto.KeyPair.generate(.ed25519, allocator);

        if (keypair_result) |kp| {
            // Validate key quality (simplified example)
            const pub_key = kp.publicKey();
            if (!std.mem.allEqual(u8, &pub_key, 0)) {
                break kp;
            } else {
                std.debug.print("⚠️  Generated weak key, retrying... (attempt {})\n", .{retry_count + 1});
                kp.deinit();
                continue;
            }
        } else |err| {
            std.debug.print("❌ Key generation failed (attempt {}): {}\n", .{ retry_count + 1, err });
            if (retry_count == max_retries - 1) {
                return err;
            }
        }
    } else {
        std.debug.print("❌ Failed to generate valid key after {} attempts\n", .{max_retries});
        return gfuel.crypto.CryptoError.KeyGenerationFailed;
    };
    defer keypair.deinit();

    std.debug.print("✅ Strong keypair generated after {} attempts\n", .{retry_count + 1});

    std.debug.print("✅ Error handling example completed successfully\n", .{});
}
```

These examples provide comprehensive coverage of GFuel's capabilities, from basic wallet operations to advanced privacy features, multi-protocol support, and integration with external systems. They demonstrate best practices for error handling, performance optimization, and real-world usage scenarios.