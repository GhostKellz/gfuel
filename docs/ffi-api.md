# FFI (Foreign Function Interface) API Documentation

GFuel provides a comprehensive C-compatible FFI layer for integration with external applications, particularly for use with ghostd/walletd and other systems written in Rust, C, or other languages.

## Overview

The FFI module (`src/core/ffi.zig`) exports C-compatible functions that allow external applications to:
- Create and manage wallets
- Perform cryptographic operations
- Handle transactions
- Manage Shroud identities
- Access audit trails

## Error Codes

### FFI Error Constants

```c
#define FFI_SUCCESS                 0
#define FFI_ERROR_INVALID_PARAM    -1
#define FFI_ERROR_WALLET_LOCKED    -2
#define FFI_ERROR_INSUFFICIENT_FUNDS -3
#define FFI_ERROR_SIGNING_FAILED   -4
#define FFI_ERROR_VERIFICATION_FAILED -5
#define FFI_ERROR_MEMORY_ERROR     -6
#define FFI_ERROR_INVALID_ADDRESS  -7
#define FFI_ERROR_ACCOUNT_NOT_FOUND -8
#define FFI_ERROR_PRIVACY_VIOLATION -9
#define FFI_ERROR_AUDIT_FAILED     -10
#define FFI_ERROR_IDENTITY_EXPIRED -11
```

## Core Structures

### GFuelContext

Main context structure for wallet operations:

```c
typedef struct {
    void* wallet_ptr;      // Opaque wallet pointer
    void* allocator_ptr;   // Opaque allocator pointer
    bool is_valid;         // Context validity flag
} GFuelContext;
```

### WalletAccount

Account information structure:

```c
typedef struct {
    uint8_t address[64];     // Account address
    uint32_t address_len;    // Address length
    uint8_t public_key[32];  // Public key bytes
    uint8_t qid[16];         // Quantum Identity (QID)
    uint32_t protocol;       // Protocol enum as integer
    uint32_t key_type;       // Key type enum as integer
} WalletAccount;
```

### ShroudIdentity

Shroud privacy identity structure:

```c
typedef struct {
    void* identity_ptr;      // Opaque identity pointer
    uint8_t did[64];         // Decentralized identifier
    uint32_t did_len;        // DID length
    uint32_t mode;           // Identity mode
    bool is_valid;           // Identity validity
    int64_t expires_at;      // Expiration timestamp
} ShroudIdentity;
```

### SignatureResult

Cryptographic signature result:

```c
typedef struct {
    uint8_t signature[64];        // Signature bytes
    uint32_t signature_len;       // Signature length
    bool success;                 // Operation success flag
    uint8_t audit_entry_id[32];   // Audit trail entry ID
    uint32_t audit_entry_len;     // Audit entry ID length
} SignatureResult;
```

### LedgerEntry

Audit trail entry structure:

```c
typedef struct {
    uint8_t id[32];              // Entry ID
    uint32_t id_len;             // ID length
    uint8_t transaction_hash[32]; // Transaction hash
    int64_t timestamp;           // Unix timestamp
    int64_t amount;              // Transaction amount
    bool verified;               // Verification status
} LedgerEntry;
```

## Core Wallet Functions

### Context Management

#### `gfuel_init()`

Initializes a new GFuel context.

```c
GFuelContext gfuel_init(void);
```

**Example (C):**
```c
GFuelContext ctx = gfuel_init();
if (!ctx.is_valid) {
    fprintf(stderr, "Failed to initialize GFuel context\n");
    return -1;
}
```

#### `gfuel_destroy()`

Destroys a GFuel context and frees resources.

```c
void gfuel_destroy(GFuelContext* ctx);
```

**Example (C):**
```c
gfuel_destroy(&ctx);
```

### Wallet Creation

#### `gfuel_create_wallet()`

Creates a new wallet with a passphrase.

```c
int gfuel_create_wallet(
    GFuelContext* ctx,
    const char* passphrase,
    uint32_t passphrase_len,
    const char* wallet_name,
    uint32_t wallet_name_len,
    bool device_bound
);
```

**Parameters:**
- `ctx`: GFuel context
- `passphrase`: Wallet passphrase (null-terminated)
- `passphrase_len`: Length of passphrase
- `wallet_name`: Optional wallet name (null-terminated)
- `wallet_name_len`: Length of wallet name
- `device_bound`: Whether wallet is device-bound

**Returns:** `FFI_SUCCESS` on success, error code on failure

**Example (C):**
```c
const char* passphrase = "secure_wallet_passphrase";
const char* wallet_name = "my_wallet";

int result = gfuel_create_wallet(
    &ctx,
    passphrase,
    strlen(passphrase),
    wallet_name,
    strlen(wallet_name),
    false  // Not device-bound
);

if (result != FFI_SUCCESS) {
    fprintf(stderr, "Failed to create wallet: %d\n", result);
}
```

#### `gfuel_load_wallet()`

Loads an existing wallet from data.

```c
int gfuel_load_wallet(
    GFuelContext* ctx,
    const uint8_t* wallet_data,
    uint32_t data_len,
    const char* passphrase,
    uint32_t passphrase_len
);
```

**Example (C):**
```c
// Load wallet from file data
FILE* file = fopen("wallet.keystore", "rb");
// ... read file data ...

int result = gfuel_load_wallet(
    &ctx,
    wallet_data,
    data_len,
    passphrase,
    strlen(passphrase)
);
```

### Account Management

#### `gfuel_create_account()`

Creates a new account for a specific protocol.

```c
int gfuel_create_account(
    GFuelContext* ctx,
    uint32_t protocol,      // 0=ghostchain, 1=ethereum, 2=stellar, 3=hedera, 4=ripple
    uint32_t key_type,      // 0=ed25519, 1=secp256k1, 2=curve25519
    WalletAccount* account_out
);
```

**Example (C):**
```c
WalletAccount account;
int result = gfuel_create_account(
    &ctx,
    0,  // GhostChain
    0,  // Ed25519
    &account
);

if (result == FFI_SUCCESS) {
    printf("Account created: %.*s\n", account.address_len, account.address);
    printf("Protocol: %u, Key type: %u\n", account.protocol, account.key_type);
}
```

### Balance Management

#### `gfuel_get_balance()`

Gets the balance for a protocol and token.

```c
int gfuel_get_balance(
    GFuelContext* ctx,
    uint32_t protocol,
    const char* token,
    uint32_t token_len,
    uint64_t* balance_out
);
```

**Example (C):**
```c
uint64_t balance;
const char* token = "GCC";

int result = gfuel_get_balance(
    &ctx,
    0,  // GhostChain
    token,
    strlen(token),
    &balance
);

if (result == FFI_SUCCESS) {
    printf("Balance: %llu micro-units\n", balance);
}
```

#### `gfuel_update_balance()`

Updates the balance for a protocol and token.

```c
int gfuel_update_balance(
    GFuelContext* ctx,
    uint32_t protocol,
    const char* token,
    uint32_t token_len,
    uint64_t amount,
    uint8_t decimals
);
```

### Security Operations

#### `gfuel_lock()`

Locks the wallet and clears sensitive data.

```c
int gfuel_lock(GFuelContext* ctx);
```

**Example (C):**
```c
int result = gfuel_lock(&ctx);
if (result == FFI_SUCCESS) {
    printf("Wallet locked successfully\n");
}
```

#### `gfuel_unlock()`

Unlocks the wallet with a passphrase.

```c
int gfuel_unlock(
    GFuelContext* ctx,
    const char* passphrase,
    uint32_t passphrase_len
);
```

**Example (C):**
```c
const char* passphrase = "secure_wallet_passphrase";
int result = gfuel_unlock(&ctx, passphrase, strlen(passphrase));
if (result == FFI_SUCCESS) {
    printf("Wallet unlocked successfully\n");
}
```

### QID (Quantum Identity) Functions

#### `gfuel_get_master_qid()`

Gets the master QID for the wallet.

```c
int gfuel_get_master_qid(
    GFuelContext* ctx,
    uint8_t qid_out[16]
);
```

**Example (C):**
```c
uint8_t master_qid[16];
int result = gfuel_get_master_qid(&ctx, master_qid);
if (result == FFI_SUCCESS) {
    printf("Master QID: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", master_qid[i]);
    }
    printf("\n");
}
```

#### `qid_to_string()`

Converts QID bytes to string representation.

```c
int qid_to_string(
    const uint8_t qid_bytes[16],
    char* buffer,
    uint32_t buffer_len,
    uint32_t* out_len
);
```

**Example (C):**
```c
uint8_t qid[16] = {0x01, 0x02, 0x03, ...};
char qid_string[64];
uint32_t string_len;

int result = qid_to_string(qid, qid_string, sizeof(qid_string), &string_len);
if (result == FFI_SUCCESS) {
    printf("QID string: %.*s\n", string_len, qid_string);
}
```

#### `string_to_qid()`

Converts string representation to QID bytes.

```c
int string_to_qid(
    const char* qid_string,
    uint32_t string_len,
    uint8_t qid_out[16]
);
```

## Shroud Privacy Functions

### Identity Management

#### `shroud_identity_init()`

Initializes a new Shroud identity context.

```c
ShroudIdentity shroud_identity_init(void);
```

**Example (C):**
```c
ShroudIdentity identity = shroud_identity_init();
if (!identity.is_valid) {
    fprintf(stderr, "Failed to initialize Shroud identity\n");
}
```

#### `shroud_identity_destroy()`

Destroys a Shroud identity context.

```c
void shroud_identity_destroy(ShroudIdentity* identity);
```

**Example (C):**
```c
shroud_identity_destroy(&identity);
```

## Protocol Integration

### Protocol Enum Mapping

The FFI uses integer constants for protocol identification:

```c
#define PROTOCOL_GHOSTCHAIN  0
#define PROTOCOL_ETHEREUM    1
#define PROTOCOL_STELLAR     2
#define PROTOCOL_HEDERA      3
#define PROTOCOL_RIPPLE      4
```

### Key Type Enum Mapping

```c
#define KEYTYPE_ED25519      0
#define KEYTYPE_SECP256K1    1
#define KEYTYPE_CURVE25519   2
```

## Usage Examples

### Complete Wallet Operations (C)

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// GFuel FFI declarations
// (Include generated header file)

int main() {
    // Initialize context
    GFuelContext ctx = gfuel_init();
    if (!ctx.is_valid) {
        fprintf(stderr, "Failed to initialize GFuel\n");
        return 1;
    }

    // Create wallet
    const char* passphrase = "my_secure_passphrase";
    const char* wallet_name = "test_wallet";

    int result = gfuel_create_wallet(
        &ctx,
        passphrase, strlen(passphrase),
        wallet_name, strlen(wallet_name),
        false
    );

    if (result != FFI_SUCCESS) {
        fprintf(stderr, "Failed to create wallet: %d\n", result);
        gfuel_destroy(&ctx);
        return 1;
    }

    printf("Wallet created successfully\n");

    // Create GhostChain account
    WalletAccount gc_account;
    result = gfuel_create_account(&ctx, PROTOCOL_GHOSTCHAIN, KEYTYPE_ED25519, &gc_account);
    if (result == FFI_SUCCESS) {
        printf("GhostChain account: %.*s\n", gc_account.address_len, gc_account.address);
    }

    // Create Ethereum account
    WalletAccount eth_account;
    result = gfuel_create_account(&ctx, PROTOCOL_ETHEREUM, KEYTYPE_SECP256K1, &eth_account);
    if (result == FFI_SUCCESS) {
        printf("Ethereum account: %.*s\n", eth_account.address_len, eth_account.address);
    }

    // Get balance
    uint64_t balance;
    const char* token = "GCC";
    result = gfuel_get_balance(&ctx, PROTOCOL_GHOSTCHAIN, token, strlen(token), &balance);
    if (result == FFI_SUCCESS) {
        printf("GCC Balance: %llu\n", balance);
    }

    // Lock wallet
    gfuel_lock(&ctx);
    printf("Wallet locked\n");

    // Unlock wallet
    result = gfuel_unlock(&ctx, passphrase, strlen(passphrase));
    if (result == FFI_SUCCESS) {
        printf("Wallet unlocked\n");
    }

    // Clean up
    gfuel_destroy(&ctx);
    return 0;
}
```

### Rust Integration Example

```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// FFI bindings
#[repr(C)]
pub struct GFuelContext {
    wallet_ptr: *mut c_void,
    allocator_ptr: *mut c_void,
    is_valid: bool,
}

#[repr(C)]
pub struct WalletAccount {
    address: [u8; 64],
    address_len: u32,
    public_key: [u8; 32],
    qid: [u8; 16],
    protocol: u32,
    key_type: u32,
}

extern "C" {
    fn gfuel_init() -> GFuelContext;
    fn gfuel_destroy(ctx: *mut GFuelContext);
    fn gfuel_create_wallet(
        ctx: *mut GFuelContext,
        passphrase: *const c_char,
        passphrase_len: u32,
        wallet_name: *const c_char,
        wallet_name_len: u32,
        device_bound: bool,
    ) -> c_int;
    fn gfuel_create_account(
        ctx: *mut GFuelContext,
        protocol: u32,
        key_type: u32,
        account_out: *mut WalletAccount,
    ) -> c_int;
}

// Rust wrapper
pub struct GFuelWallet {
    context: GFuelContext,
}

impl GFuelWallet {
    pub fn new() -> Result<Self, i32> {
        let context = unsafe { gfuel_init() };
        if !context.is_valid {
            return Err(-1);
        }
        Ok(GFuelWallet { context })
    }

    pub fn create_wallet(&mut self, passphrase: &str, name: &str) -> Result<(), i32> {
        let c_passphrase = CString::new(passphrase).unwrap();
        let c_name = CString::new(name).unwrap();

        let result = unsafe {
            gfuel_create_wallet(
                &mut self.context,
                c_passphrase.as_ptr(),
                passphrase.len() as u32,
                c_name.as_ptr(),
                name.len() as u32,
                false,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }

    pub fn create_account(&mut self, protocol: u32, key_type: u32) -> Result<WalletAccount, i32> {
        let mut account = WalletAccount {
            address: [0; 64],
            address_len: 0,
            public_key: [0; 32],
            qid: [0; 16],
            protocol: 0,
            key_type: 0,
        };

        let result = unsafe {
            gfuel_create_account(&mut self.context, protocol, key_type, &mut account)
        };

        if result == 0 {
            Ok(account)
        } else {
            Err(result)
        }
    }
}

impl Drop for GFuelWallet {
    fn drop(&mut self) {
        unsafe {
            gfuel_destroy(&mut self.context);
        }
    }
}

// Usage example
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = GFuelWallet::new()?;

    wallet.create_wallet("secure_passphrase", "rust_wallet")?;
    println!("Wallet created successfully");

    let account = wallet.create_account(0, 0)?; // GhostChain, Ed25519
    let address = String::from_utf8_lossy(&account.address[..account.address_len as usize]);
    println!("Account created: {}", address);

    Ok(())
}
```

## Build Integration

### C Header Generation

Generate C headers from Zig FFI exports:

```bash
# Generate header file
zig build-lib src/core/ffi.zig -dynamic -femit-h=gfuel.h

# Use in C project
gcc -o example example.c -lgfuel -L./zig-out/lib
```

### CMake Integration

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(gfuel_integration)

# Find GFuel library
find_library(GFUEL_LIB gfuel PATHS ./zig-out/lib)
if(NOT GFUEL_LIB)
    message(FATAL_ERROR "GFuel library not found")
endif()

# Include headers
include_directories(.)

# Create executable
add_executable(gfuel_example example.c)
target_link_libraries(gfuel_example ${GFUEL_LIB})
```

### Rust Bindgen Integration

```toml
# Cargo.toml
[build-dependencies]
bindgen = "0.69"

[dependencies]
libc = "0.2"
```

```rust
// build.rs
use bindgen::Builder;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-search=./zig-out/lib");
    println!("cargo:rustc-link-lib=gfuel");

    let bindings = Builder::default()
        .header("gfuel.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
```

## Error Handling Best Practices

### Check Return Values

Always check FFI function return values:

```c
int result = gfuel_create_wallet(&ctx, passphrase, passphrase_len, name, name_len, false);
switch (result) {
    case FFI_SUCCESS:
        printf("Wallet created successfully\n");
        break;
    case FFI_ERROR_INVALID_PARAM:
        fprintf(stderr, "Invalid parameters provided\n");
        break;
    case FFI_ERROR_MEMORY_ERROR:
        fprintf(stderr, "Memory allocation failed\n");
        break;
    default:
        fprintf(stderr, "Unknown error: %d\n", result);
        break;
}
```

### Resource Management

Always clean up resources:

```c
// Initialize
GFuelContext ctx = gfuel_init();
ShroudIdentity identity = shroud_identity_init();

// ... use resources ...

// Always clean up
shroud_identity_destroy(&identity);
gfuel_destroy(&ctx);
```

## Thread Safety

The FFI layer is **not thread-safe**. If using from multiple threads:

1. **Use separate contexts** per thread
2. **Implement external synchronization** if sharing contexts
3. **Avoid concurrent operations** on the same wallet

## Memory Management

The FFI layer handles internal memory management, but:

1. **Initialize contexts** before use
2. **Destroy contexts** when done
3. **Don't access pointers** after destruction
4. **Check validity flags** before operations

## Performance Considerations

- **Reuse contexts** when possible
- **Batch operations** to reduce FFI overhead
- **Cache frequently accessed data** on the caller side
- **Use appropriate buffer sizes** for string operations