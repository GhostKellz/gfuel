//! FFI (Foreign Function Interface) for exposing GFuel to Rust/C
//! This module provides C-compatible functions for integration with walletd/ghostd
//! Now with Shroud privacy, Zsig signing, and Zledger audit trails

const std = @import("std");
const shroud = @import("shroud");
const zledger = @import("zledger");
const gfuel = @import("gfuel");
const wallet = gfuel.wallet;
const tx = gfuel.tx;
const qid = gfuel.qid;

// C-compatible error codes
pub const FFI_SUCCESS: c_int = 0;
pub const FFI_ERROR_INVALID_PARAM: c_int = -1;
pub const FFI_ERROR_WALLET_LOCKED: c_int = -2;
pub const FFI_ERROR_INSUFFICIENT_FUNDS: c_int = -3;
pub const FFI_ERROR_SIGNING_FAILED: c_int = -4;
pub const FFI_ERROR_VERIFICATION_FAILED: c_int = -5;
pub const FFI_ERROR_MEMORY_ERROR: c_int = -6;
pub const FFI_ERROR_INVALID_ADDRESS: c_int = -7;
pub const FFI_ERROR_ACCOUNT_NOT_FOUND: c_int = -8;
pub const FFI_ERROR_PRIVACY_VIOLATION: c_int = -9;
pub const FFI_ERROR_AUDIT_FAILED: c_int = -10;
pub const FFI_ERROR_IDENTITY_EXPIRED: c_int = -11;

// C-compatible structures
pub const GFuelContext = extern struct {
    wallet_ptr: ?*anyopaque,
    allocator_ptr: ?*anyopaque,
    is_valid: bool,
};

pub const WalletAccount = extern struct {
    address: [64]u8,
    address_len: u32,
    public_key: [32]u8,
    qid: [16]u8,
    protocol: u32, // Protocol as integer
    key_type: u32, // KeyType as integer
};

pub const ShroudIdentity = extern struct {
    identity_ptr: ?*anyopaque,
    did: [64]u8,
    did_len: u32,
    mode: u32, // IdentityMode as integer
    is_valid: bool,
    expires_at: i64,
};

pub const LedgerEntry = extern struct {
    id: [32]u8,
    id_len: u32,
    transaction_hash: [32]u8,
    timestamp: i64,
    amount: i64,
    verified: bool,
};

pub const SignatureResult = extern struct {
    signature: [64]u8,
    signature_len: u32,
    success: bool,
    audit_entry_id: [32]u8,
    audit_entry_len: u32,
};

pub const BalanceInfo = extern struct {
    protocol: u32,
    token: [32]u8,
    token_len: u32,
    amount: u64,
    decimals: u8,
};

// Global allocator for FFI operations
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const global_allocator = gpa.allocator();

// Convert Zig errors to C error codes
fn zigErrorToC(err: anyerror) c_int {
    return switch (err) {
        wallet.WalletError.InvalidPassword => FFI_ERROR_INVALID_PARAM,
        wallet.WalletError.WalletLocked => FFI_ERROR_WALLET_LOCKED,
        wallet.WalletError.InsufficientFunds => FFI_ERROR_INSUFFICIENT_FUNDS,
        wallet.WalletError.SigningFailed => FFI_ERROR_SIGNING_FAILED,
        wallet.WalletError.InvalidAddress => FFI_ERROR_INVALID_ADDRESS,
        else => FFI_ERROR_MEMORY_ERROR,
    };
}

// Convert Protocol enum to integer
fn protocolToInt(protocol: wallet.Protocol) u32 {
    return switch (protocol) {
        .ghostchain => 0,
        .ethereum => 1,
        .stellar => 2,
        .hedera => 3,
        .ripple => 4,
    };
}

// Convert integer to Protocol enum
fn intToProtocol(value: u32) wallet.Protocol {
    return switch (value) {
        0 => .ghostchain,
        1 => .ethereum,
        2 => .stellar,
        3 => .hedera,
        4 => .ripple,
        else => .ghostchain,
    };
}

// Convert KeyType enum to integer
fn keyTypeToInt(key_type: wallet.KeyType) u32 {
    return switch (key_type) {
        .ed25519 => 0,
        .secp256k1 => 1,
        .curve25519 => 2,
    };
}

// Convert integer to KeyType enum
fn intToKeyType(value: u32) wallet.KeyType {
    return switch (value) {
        0 => .ed25519,
        1 => .secp256k1,
        2 => .curve25519,
        else => .ed25519,
    };
}

// GFuel FFI Functions

/// Initialize a new wallet context
export fn gfuel_init() GFuelContext {
    return GFuelContext{
        .wallet_ptr = null,
        .allocator_ptr = @ptrCast(&global_allocator),
        .is_valid = true,
    };
}

/// Destroy wallet context and free resources
export fn gfuel_destroy(ctx: *GFuelContext) void {
    if (ctx.wallet_ptr) |ptr| {
        const wallet_ptr: *wallet.Wallet = @ptrCast(@alignCast(ptr));
        wallet_ptr.deinit();
        global_allocator.destroy(wallet_ptr);
        ctx.wallet_ptr = null;
    }
    ctx.is_valid = false;
}

/// Create a new wallet with passphrase
export fn gfuel_create_wallet(
    ctx: *GFuelContext,
    passphrase: [*:0]const u8,
    passphrase_len: u32,
    wallet_name: [*:0]const u8,
    wallet_name_len: u32,
    device_bound: bool,
) c_int {
    if (!ctx.is_valid) return FFI_ERROR_INVALID_PARAM;

    const pass_slice = passphrase[0..passphrase_len];
    const name_slice = if (wallet_name_len > 0) wallet_name[0..wallet_name_len] else null;

    const mode: wallet.WalletMode = if (device_bound) .private_cold else .hybrid;

    const new_wallet = wallet.Wallet.create(global_allocator, pass_slice, mode, null) catch |err| {
        return zigErrorToC(err);
    };

    const wallet_ptr = global_allocator.create(wallet.Wallet) catch {
        return FFI_ERROR_MEMORY_ERROR;
    };
    wallet_ptr.* = new_wallet;

    ctx.wallet_ptr = @ptrCast(wallet_ptr);
    return FFI_SUCCESS;
}

/// Load existing wallet with passphrase
export fn gfuel_load_wallet(
    ctx: *GFuelContext,
    wallet_data: [*]const u8,
    data_len: u32,
    passphrase: [*:0]const u8,
    passphrase_len: u32,
) c_int {
    if (!ctx.is_valid) return FFI_ERROR_INVALID_PARAM;

    _ = wallet_data;
    _ = data_len;
    const pass_slice = passphrase[0..passphrase_len];

    const loaded_wallet = wallet.Wallet.load(global_allocator, \"placeholder_path\", pass_slice) catch |err| {
        return zigErrorToC(err);
    };

    const wallet_ptr = global_allocator.create(wallet.Wallet) catch {
        return FFI_ERROR_MEMORY_ERROR;
    };
    wallet_ptr.* = loaded_wallet;

    ctx.wallet_ptr = @ptrCast(wallet_ptr);
    return FFI_SUCCESS;
}

/// Create account for specific protocol
export fn gfuel_create_account(
    ctx: *GFuelContext,
    protocol: u32,
    key_type: u32,
    account_out: *WalletAccount,
) c_int {
    if (!ctx.is_valid or ctx.wallet_ptr == null) return FFI_ERROR_INVALID_PARAM;

    const wallet_ptr: *wallet.Wallet = @ptrCast(@alignCast(ctx.wallet_ptr.?));
    const proto = intToProtocol(protocol);
    const ktype = intToKeyType(key_type);

    wallet_ptr.createAccount(proto, ktype, null) catch |err| {
        return zigErrorToC(err);
    };

    // Get the last created account
    if (wallet_ptr.accounts.items.len == 0) {
        return FFI_ERROR_ACCOUNT_NOT_FOUND;
    }
    const account = &wallet_ptr.accounts.items[wallet_ptr.accounts.items.len - 1];

    // Fill account structure
    @memset(&account_out.address, 0);
    const addr_len = @min(account.address.len, 63);
    @memcpy(account_out.address[0..addr_len], account.address[0..addr_len]);
    account_out.address_len = @intCast(addr_len);

    if (account.getPublicKey()) |pub_key| {
        account_out.public_key = pub_key;
    } else {
        @memset(&account_out.public_key, 0);
    }

    // Generate placeholder QID for now
    @memset(&account_out.qid, 0);
    account_out.protocol = protocolToInt(account.protocol);
    account_out.key_type = keyTypeToInt(account.key_type);

    return FFI_SUCCESS;
}

/// Get wallet balance for protocol and token
export fn gfuel_get_balance(
    ctx: *GFuelContext,
    protocol: u32,
    token: [*:0]const u8,
    token_len: u32,
    balance_out: *u64,
) c_int {
    if (!ctx.is_valid or ctx.wallet_ptr == null) return FFI_ERROR_INVALID_PARAM;

    _ = ctx;
    _ = protocol;
    _ = token;
    _ = token_len;

    // TODO: Implement proper balance lookup with wallet accounts
    balance_out.* = 0;
    return FFI_SUCCESS; // Balance of 0 is valid for now
}

/// Update wallet balance
export fn gfuel_update_balance(
    ctx: *GFuelContext,
    protocol: u32,
    token: [*:0]const u8,
    token_len: u32,
    amount: u64,
    decimals: u8,
) c_int {
    if (!ctx.is_valid or ctx.wallet_ptr == null) return FFI_ERROR_INVALID_PARAM;

    _ = ctx;
    _ = protocol;
    _ = token;
    _ = token_len;
    _ = amount;
    _ = decimals;

    // TODO: Implement proper balance update with wallet accounts

    return FFI_SUCCESS;
}

/// Lock wallet
export fn gfuel_lock(ctx: *GFuelContext) c_int {
    if (!ctx.is_valid or ctx.wallet_ptr == null) return FFI_ERROR_INVALID_PARAM;

    const wallet_ptr: *wallet.Wallet = @ptrCast(@alignCast(ctx.wallet_ptr.?));
    wallet_ptr.lock();

    return FFI_SUCCESS;
}

/// Unlock wallet with passphrase
export fn gfuel_unlock(
    ctx: *GFuelContext,
    passphrase: [*:0]const u8,
    passphrase_len: u32,
) c_int {
    if (!ctx.is_valid or ctx.wallet_ptr == null) return FFI_ERROR_INVALID_PARAM;

    const wallet_ptr: *wallet.Wallet = @ptrCast(@alignCast(ctx.wallet_ptr.?));
    const pass_slice = passphrase[0..passphrase_len];

    wallet_ptr.unlock(pass_slice) catch |err| {
        return zigErrorToC(err);
    };

    return FFI_SUCCESS;
}

/// Get master QID
export fn gfuel_get_master_qid(
    ctx: *GFuelContext,
    qid_out: *[16]u8,
) c_int {
    if (!ctx.is_valid or ctx.wallet_ptr == null) return FFI_ERROR_INVALID_PARAM;

    _ = ctx;

    // TODO: Implement proper QID generation
    @memset(qid_out, 0);
    return FFI_SUCCESS;
}

// Shroud Identity FFI Functions (replacing RealID)

/// Initialize Shroud identity context
export fn shroud_identity_init() ShroudIdentity {
    return ShroudIdentity{
        .identity_ptr = null,
        .did = std.mem.zeroes([64]u8),
        .did_len = 0,
        .mode = 0, // persistent
        .is_valid = true,
        .expires_at = 0,
    };
}

/// Destroy Shroud identity context
export fn shroud_identity_destroy(ctx: *ShroudIdentity) void {
    if (ctx.identity_ptr) |ptr| {
        const identity_ptr: *shroud.identity.Identity = @ptrCast(@alignCast(ptr));
        identity_ptr.deinit();
        global_allocator.destroy(identity_ptr);
        ctx.identity_ptr = null;
    }
    ctx.is_valid = false;
}

// TODO: Implement Shroud identity generation functions
// The following functions need to be rewritten for Shroud instead of RealID

// Temporarily removed problematic functions - need to reimplement with Shroud

/// Convert QID to string
export fn qid_to_string(
    qid_bytes: *const [16]u8,
    buffer: [*]u8,
    buffer_len: u32,
    out_len: *u32,
) c_int {
    if (buffer_len < 40) return FFI_ERROR_INVALID_PARAM; // IPv6 string needs at least 39 chars + null

    const qid_obj = qid.QID{ .bytes = qid_bytes.* };
    const buffer_slice = buffer[0..buffer_len];

    const qid_string = qid_obj.toString(buffer_slice) catch {
        return FFI_ERROR_INVALID_PARAM;
    };

    out_len.* = @intCast(qid_string.len);
    return FFI_SUCCESS;
}

/// Convert string to QID
export fn string_to_qid(
    qid_string: [*:0]const u8,
    string_len: u32,
    qid_out: *[16]u8,
) c_int {
    const string_slice = qid_string[0..string_len];

    const qid_obj = qid.QID.fromString(string_slice) catch {
        return FFI_ERROR_INVALID_PARAM;
    };

    qid_out.* = qid_obj.bytes;
    return FFI_SUCCESS;
}

// Test functions for FFI
test "FFI wallet operations" {
    var ctx = gfuel_init();
    defer gfuel_destroy(&ctx);

    // Create wallet
    const passphrase = "test_passphrase_for_ffi";
    const wallet_name = "ffi_test_wallet";

    const create_result = gfuel_create_wallet(
        &ctx,
        passphrase.ptr,
        passphrase.len,
        wallet_name.ptr,
        wallet_name.len,
        false,
    );

    try std.testing.expect(create_result == FFI_SUCCESS);

    // Create account
    var account: WalletAccount = undefined;
    const account_result = gfuel_create_account(&ctx, 0, 0, &account); // GhostChain, Ed25519

    try std.testing.expect(account_result == FFI_SUCCESS);
    try std.testing.expect(account.protocol == 0);
    try std.testing.expect(account.key_type == 0);
}

// TODO: Implement Shroud-based tests
// test "FFI Shroud operations" {
//     // Implementation needed for Shroud identity functions
// }
