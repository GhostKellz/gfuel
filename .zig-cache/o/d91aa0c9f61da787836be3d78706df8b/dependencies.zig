pub const packages = struct {
    pub const @"shroud-1.2.4-z7C8mXYWBQDnbScUT0wV5HI44ceuV9BYHelv9F-82sqJ" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/shroud-1.2.4-z7C8mXYWBQDnbScUT0wV5HI44ceuV9BYHelv9F-82sqJ";
        pub const build_zig = @import("shroud-1.2.4-z7C8mXYWBQDnbScUT0wV5HI44ceuV9BYHelv9F-82sqJ");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" },
        };
    };
    pub const @"zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl";
        pub const build_zig = @import("zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" },
        };
    };
    pub const @"zledger-0.4.0-gtTGiD06BABnyQi0FQoom66gEOlxxk1c0k-dtd0n2x6P" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zledger-0.4.0-gtTGiD06BABnyQi0FQoom66gEOlxxk1c0k-dtd0n2x6P";
        pub const build_zig = @import("zledger-0.4.0-gtTGiD06BABnyQi0FQoom66gEOlxxk1c0k-dtd0n2x6P");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zcrypto", "zcrypto-0.8.6-rgQAI9g9DQDTxLJBz5QS6eF5rDIYloue7jV5YZysZCYl" },
        };
    };
    pub const @"zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_";
        pub const build_zig = @import("zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zsync", "zsync-0.5.4-KAuheV0SHQBxubuzXagj1oq5B2KE4VhMWTAAAaInwB2_" },
    .{ "zledger", "zledger-0.4.0-gtTGiD06BABnyQi0FQoom66gEOlxxk1c0k-dtd0n2x6P" },
    .{ "shroud", "shroud-1.2.4-z7C8mXYWBQDnbScUT0wV5HI44ceuV9BYHelv9F-82sqJ" },
};
