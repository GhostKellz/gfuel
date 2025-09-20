# Privacy Features Documentation

GFuel integrates with Shroud to provide comprehensive privacy and identity management features, enabling anonymous transactions, ephemeral identities, and access control.

## Overview

The privacy system in GFuel consists of:
- **Shroud Identity Management** - Ephemeral and persistent identities
- **Access Control Guardians** - Permission-based access control
- **Privacy Tokens** - Authentication and authorization tokens
- **Audit Trail Protection** - Privacy-preserving transaction logging
- **Anonymous Transactions** - Identity obfuscation for transactions

## Shroud Integration

### Identity Management

Shroud provides identity abstraction through the `shroud.identity.Identity` module:

```zig
const shroud = @import("shroud");

// Create ephemeral identity
var identity = shroud.identity.Identity.init(
    allocator,
    "user_session_id",
    .{ .bytes = random_32_bytes }
);
defer identity.deinit();
```

### Guardian Access Control

The Guardian system provides role-based access control:

```zig
var guardian = shroud.guardian.Guardian.init(allocator);
defer guardian.deinit();

// Add roles with specific permissions
try guardian.addRole("user", &[_]shroud.guardian.Permission{ .read, .write });
try guardian.addRole("admin", &[_]shroud.guardian.Permission{ .read, .write, .admin });

// Validate role permissions
const has_access = guardian.validateRole("user");
```

## Privacy-Focused Wallet Mode

### Enabling Privacy Mode

Create a wallet with privacy features enabled:

```zig
var wallet = try gfuel.wallet.Wallet.create(
    allocator,
    "secure_passphrase",
    .privacy_focused,  // Enable privacy mode
    null
);
defer wallet.deinit();

// Privacy components automatically initialized
if (wallet.shroud_guardian) |guardian| {
    std.log.info("Access control guardian active\n", .{});
}

if (wallet.audit_ledger) |ledger| {
    std.log.info("Privacy-preserving audit trail active\n", .{});
}
```

### Privacy Mode Features

When using `.privacy_focused` mode, the wallet automatically provides:

1. **Shroud Guardian** - Access control and permission management
2. **Audit Ledger** - Cryptographic transaction logging
3. **Identity Integration** - Seamless identity management
4. **Privacy Tokens** - Authentication and session management

## Identity Types

### Ephemeral Identities

Short-lived identities for single transactions or sessions:

```zig
// Create ephemeral identity for a transaction
var ephemeral_identity = shroud.identity.Identity.init(
    allocator,
    "tx_ephemeral_id",
    .{ .bytes = crypto_random_bytes }
);
defer ephemeral_identity.deinit();

// Use for privacy transaction
var private_tx = try gfuel.transaction.Ethereum.createPrivateTransaction(
    allocator,
    "0xfrom...",
    "0xto...",
    amount,
    &ephemeral_identity
);
defer private_tx.deinit(allocator);
```

### Persistent Identities

Long-term identities for ongoing operations:

```zig
// Create persistent identity
var persistent_identity = shroud.identity.Identity.init(
    allocator,
    "user_persistent_id",
    .{ .bytes = derived_key_material }
);
defer persistent_identity.deinit();

// Store identity reference in wallet account
account.shroud_identity = persistent_identity;
```

### Anonymous Identities

Completely anonymous identities with no linkable information:

```zig
// Generate random identity data
var random_bytes: [32]u8 = undefined;
std.crypto.random.bytes(&random_bytes);

var anonymous_identity = shroud.identity.Identity.init(
    allocator,
    "anonymous_session",
    .{ .bytes = random_bytes }
);
defer anonymous_identity.deinit();

std.log.info("Anonymous identity: {s}\n", .{anonymous_identity.id});
```

## Privacy Tokens

### Access Token Creation

Generate time-limited access tokens for operations:

```zig
// Create access token with 1-hour expiration
const access_token = try identity.createAccessToken("transaction_auth", 3600);

// Serialize token for transmission
const token_data = access_token.serialize();
std.log.info("Access token: {s}\n", .{token_data});
```

### Token Validation

Validate and use access tokens:

```zig
// Validate token before operation
if (try identity.validateAccessToken(token_data)) {
    std.log.info("Token valid, proceeding with operation\n", .{});
    // Perform authorized operation
} else {
    std.log.err("Invalid or expired token\n", .{});
    return error.TokenExpired;
}
```

## Private Transactions

### Ethereum Privacy Transactions

Create Ethereum transactions with privacy features:

```zig
var identity = shroud.identity.Identity.init(
    allocator,
    "eth_privacy_user",
    .{ .bytes = user_key_material }
);
defer identity.deinit();

var private_tx = try gfuel.transaction.Ethereum.createPrivateTransaction(
    allocator,
    "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
    "0x123456789abcdef123456789abcdef123456789a",
    1000000000000000000, // 1 ETH
    &identity
);
defer private_tx.deinit(allocator);

// Privacy token automatically attached
if (private_tx.metadata) |metadata| {
    std.log.info("Privacy metadata attached: {s}\n", .{metadata});
}
```

### GhostChain Audit Transactions

Create GhostChain transactions with audit trails:

```zig
var audit_ledger = zledger.journal.Journal.init(allocator, null);
defer audit_ledger.deinit();

var tx = try gfuel.transaction.GhostChain.createTransactionWithAudit(
    allocator,
    "gc1sender...",
    "gc1recipient...",
    1000000,
    &audit_ledger
);
defer tx.deinit(allocator);

// Verify audit trail integrity
const integrity_verified = try audit_ledger.verifyIntegrity();
std.log.info("Audit trail integrity: {}\n", .{integrity_verified});
```

## Access Control

### Role-Based Permissions

Set up role-based access control:

```zig
var guardian = shroud.guardian.Guardian.init(allocator);
defer guardian.deinit();

// Define permission sets
const user_permissions = [_]shroud.guardian.Permission{ .read, .write };
const admin_permissions = [_]shroud.guardian.Permission{ .read, .write, .admin };
const viewer_permissions = [_]shroud.guardian.Permission{ .read };

// Add roles
try guardian.addRole("user", &user_permissions);
try guardian.addRole("admin", &admin_permissions);
try guardian.addRole("viewer", &viewer_permissions);
```

### Permission Validation

Check permissions before operations:

```zig
// Validate user has required permissions
fn validateTransactionPermission(guardian: *shroud.guardian.Guardian, role: []const u8) bool {
    if (!guardian.validateRole(role)) {
        return false;
    }

    // Check specific permission for transaction
    return guardian.hasPermission(role, .write);
}

// Usage
if (validateTransactionPermission(&guardian, "user")) {
    // Proceed with transaction
    try createTransaction();
} else {
    std.log.err("Insufficient permissions for transaction\n", .{});
    return error.PermissionDenied;
}
```

## Audit Trail Privacy

### Privacy-Preserving Logging

Log transactions with privacy protection:

```zig
var privacy_ledger = zledger.journal.Journal.init(allocator, null);
defer privacy_ledger.deinit();

// Create privacy-preserving audit entry
const audit_tx = try zledger.tx.Transaction.init(
    allocator,
    amount,
    "GCC",
    "privacy_sender_hash",    // Hash instead of real address
    "privacy_recipient_hash", // Hash instead of real address
    "Privacy transaction with identity protection"
);

try privacy_ledger.append(audit_tx);
```

### Audit Trail Verification

Verify audit integrity without revealing sensitive data:

```zig
// Verify audit trail without exposing transaction details
const integrity_check = try privacy_ledger.verifyIntegrity();
if (integrity_check) {
    std.log.info("Privacy audit trail verified\n", .{});
    std.log.info("Total entries: {d}\n", .{privacy_ledger.entries.items.len});
} else {
    std.log.err("Audit trail integrity compromised\n", .{});
}
```

## Complete Privacy Example

### Full Privacy Transaction Flow

```zig
pub fn privacyTransactionExample(allocator: std.mem.Allocator) !void {
    // 1. Create privacy-focused wallet
    var wallet = try gfuel.wallet.Wallet.create(
        allocator,
        "privacy_passphrase",
        .privacy_focused,
        null
    );
    defer wallet.deinit();

    // 2. Create ephemeral identity for transaction
    var ephemeral_identity = shroud.identity.Identity.init(
        allocator,
        "ephemeral_tx_id",
        .{ .bytes = [_]u8{0x42} ** 32 }
    );
    defer ephemeral_identity.deinit();

    // 3. Set up access guardian
    if (wallet.shroud_guardian) |*guardian| {
        try guardian.addRole("privacy_user", &[_]shroud.guardian.Permission{ .read, .write });
    }

    // 4. Create privacy transaction
    var private_tx = try gfuel.transaction.Ethereum.createPrivateTransaction(
        allocator,
        "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8",
        "0x123456789abcdef123456789abcdef123456789a",
        1000000000000000000,
        &ephemeral_identity
    );
    defer private_tx.deinit(allocator);

    // 5. Generate access token
    const access_token = try ephemeral_identity.createAccessToken("tx_auth", 3600);

    // 6. Sign transaction with privacy protection
    try private_tx.sign(allocator, "private_key_32_bytes_exactly!");

    // 7. Log to privacy audit trail
    if (wallet.audit_ledger) |*ledger| {
        const privacy_audit_tx = try zledger.tx.Transaction.init(
            allocator,
            private_tx.amount,
            private_tx.currency,
            "hashed_sender",
            "hashed_recipient",
            "Privacy transaction with ephemeral identity"
        );
        try ledger.append(privacy_audit_tx);

        // Verify audit trail
        const verified = try ledger.verifyIntegrity();
        std.log.info("Privacy audit verified: {}\n", .{verified});
    }

    std.log.info("Privacy transaction completed successfully\n", .{});
}
```

## Privacy Best Practices

### Identity Management

1. **Use ephemeral identities** for single-use operations:
```zig
// Good: Ephemeral identity for one transaction
var tx_identity = shroud.identity.Identity.init(allocator, "temp_id", random_bytes);
defer tx_identity.deinit();
```

2. **Rotate persistent identities** regularly:
```zig
// Rotate identity every N transactions or time period
if (transaction_count % 100 == 0) {
    old_identity.deinit();
    new_identity = createNewIdentity();
}
```

3. **Clear identity data** when no longer needed:
```zig
// Identities are automatically cleared in deinit()
defer identity.deinit(); // Important!
```

### Access Control

1. **Use least privilege principle**:
```zig
// Give minimum required permissions
const user_perms = [_]shroud.guardian.Permission{ .read }; // Read-only
const tx_perms = [_]shroud.guardian.Permission{ .read, .write }; // Transact
```

2. **Validate permissions before operations**:
```zig
if (!guardian.hasPermission("user", .write)) {
    return error.InsufficientPermissions;
}
```

### Transaction Privacy

1. **Use privacy tokens for sensitive operations**:
```zig
const privacy_token = try identity.createAccessToken("sensitive_op", 300); // 5 min
// Use token for authentication
```

2. **Hash sensitive data in audit logs**:
```zig
const address_hash = hashAddress(real_address);
// Log hash instead of real address
```

3. **Use different identities for different protocols**:
```zig
var eth_identity = createIdentity("eth_operations");
var gc_identity = createIdentity("gc_operations");
// Keep protocol identities separate
```

## Security Considerations

### Identity Protection

- **Never log raw identity data**
- **Use secure random number generation** for identity creation
- **Clear identity memory** when done
- **Rotate identities** based on usage patterns

### Token Security

- **Use appropriate expiration times** for tokens
- **Validate token integrity** before use
- **Revoke tokens** when no longer needed
- **Store tokens securely** during transmission

### Audit Trail Security

- **Verify audit integrity** regularly
- **Use privacy-preserving hashes** in logs
- **Encrypt sensitive audit data**
- **Implement audit log rotation**

## Integration with External Systems

### Privacy-Preserving APIs

Expose privacy features through APIs:

```zig
pub const PrivacyAPI = struct {
    pub fn createAnonymousTransaction(
        protocol: Protocol,
        amount: i64,
        recipient_hash: []const u8
    ) !Transaction {
        var anon_identity = createEphemeralIdentity();
        defer anon_identity.deinit();

        return try createPrivateTransaction(protocol, amount, recipient_hash, &anon_identity);
    }

    pub fn validatePrivacyToken(token: []const u8) !bool {
        // Implement token validation
        return true; // Placeholder
    }
};
```

### Blockchain Privacy Integration

Integrate with privacy-focused blockchain features:

```zig
// Example: Ethereum privacy integration
pub fn createZKTransaction(
    allocator: Allocator,
    identity: *shroud.identity.Identity,
    proof_data: []const u8
) !Transaction {
    var tx = try Ethereum.createPrivateTransaction(
        allocator,
        "0x...", // From address
        "0x...", // To address
        amount,
        identity
    );

    // Attach zero-knowledge proof
    tx.metadata = try std.fmt.allocPrint(
        allocator,
        "zk_proof:{s}",
        .{std.fmt.fmtSliceHexLower(proof_data)}
    );

    return tx;
}
```

## Future Privacy Enhancements

The privacy system is designed for extensibility:

1. **Zero-Knowledge Proofs** - Integration with ZK-SNARKs/STARKs
2. **Ring Signatures** - Multi-signature privacy
3. **Stealth Addresses** - One-time addresses for enhanced privacy
4. **Mixing Services** - Transaction mixing for anonymity
5. **Privacy Coins Integration** - Support for Monero, Zcash-style privacy

```zig
// Future: ZK proof integration
pub fn createZKProof(secret: []const u8, public_inputs: []const u8) ![]const u8 {
    // Generate zero-knowledge proof
    return "zk_proof_placeholder";
}

// Future: Ring signature support
pub fn createRingSignature(
    keypairs: []const crypto.KeyPair,
    message: []const u8
) ![]const u8 {
    // Create ring signature for anonymity
    return "ring_sig_placeholder";
}
```