//! Cryptographic utilities and key management
//! Integrates with zledger v0.5.0 with integrated zsig

const std = @import("std");
const zledger = @import("zledger");
const Allocator = std.mem.Allocator;

pub const CryptoError = error{
    InvalidKey,
    InvalidSignature,
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
};

// Use zledger's integrated Keypair type for better compatibility
pub const KeyPair = struct {
    inner: zledger.Keypair,
    key_type: KeyType,

    pub fn deinit(self: *KeyPair) void {
        // The zledger.Keypair handles its own cleanup
        _ = self;
    }

    /// Generate new keypair using zledger's integrated zsig
    pub fn generate(key_type: KeyType, allocator: Allocator) !KeyPair {
        const inner_keypair = try zledger.generateKeypair(allocator);
        return KeyPair{
            .inner = inner_keypair,
            .key_type = key_type,
        };
    }

    /// Generate from seed using zledger's integrated zsig
    pub fn fromSeed(seed: [32]u8, key_type: KeyType, allocator: Allocator) !KeyPair {
        const inner_keypair = try zledger.keypairFromSeed(seed, allocator);
        return KeyPair{
            .inner = inner_keypair,
            .key_type = key_type,
        };
    }

    /// Sign message using zledger's integrated signing
    pub fn sign(self: *const KeyPair, message: []const u8, allocator: Allocator) !zledger.Signature {
        _ = allocator; // Not used by zledger.signMessage
        return try zledger.signMessage(message, self.inner);
    }

    /// Verify signature using zledger's integrated verification
    pub fn verify(self: *const KeyPair, message: []const u8, signature: *const zledger.Signature) bool {
        return zledger.verifySignature(message, &signature.bytes, &self.inner.publicKey());
    }

    /// Get public key bytes
    pub fn publicKey(self: *const KeyPair) [32]u8 {
        return self.inner.publicKey();
    }
};

pub const KeyType = enum {
    ed25519,
    secp256k1,
    curve25519,
};

/// Convenience function for creating a GFuel wallet keypair
pub fn createWalletKeypair(allocator: Allocator) !KeyPair {
    return KeyPair.generate(.ed25519, allocator);
}

/// Create a wallet keypair from seed using zledger
pub fn createWalletKeypairFromSeed(seed: [32]u8, allocator: Allocator) !KeyPair {
    return KeyPair.fromSeed(seed, .ed25519, allocator);
}

/// Generate mnemonic phrase using BIP-39
pub fn generateMnemonic(allocator: Allocator, entropy_bits: u16) ![]const u8 {
    _ = entropy_bits;
    // TODO: Use zledger v0.5.0 bip39 implementation
    return allocator.dupe(u8, "test mnemonic phrase for development");
}

/// Convert mnemonic to seed using BIP-39
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8, allocator: Allocator) ![64]u8 {
    _ = allocator;
    _ = mnemonic;
    _ = passphrase;
    // TODO: Use zledger v0.5.0 bip39 implementation
    return [_]u8{0} ** 64;
}

test "keypair generation" {
    var keypair = try KeyPair.generate(.ed25519, std.testing.allocator);
    defer keypair.deinit();

    try std.testing.expect(keypair.key_type == .ed25519);
}

test "signing and verification" {
    var keypair = try KeyPair.generate(.ed25519, std.testing.allocator);
    defer keypair.deinit();

    const message = "Hello, GFuel!";
    const signature = try keypair.sign(message, std.testing.allocator);

    try std.testing.expect(keypair.verify(message, &signature));
}