pub const packages = struct {
    pub const @"N-V-__8AAAOIwgCuuT3IhPlAW6erD8SspcE7iVKY4nbJWLV6" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AADKo3ADb6qHynR1iiBhHFQcaoAE0qpLZuh3GtoT2" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AAFoXkgBrHnNjViSdp84aL1ciwtWKZdYHK7dSSppd" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AAGKbngAmNuaBMSXq_WgmQi6N8WVWVKp0moFSTvoJ" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AAHpvrAAEcEurDCWYQt6jTJSozCfLDwkGTptKEyJ7" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AAJKMngA8y82sENkRg-JF100BtRa7GQxoBIfU3c3_" = struct {
        pub const available = false;
    };
    pub const @"N-V-__8AANrukAA2AHP6xuzchs_iwsyg1UYhIFhpUR6R0x7K" = struct {
        pub const available = true;
        pub const build_root = "/Users/jea/.cache/zig/p/N-V-__8AANrukAA2AHP6xuzchs_iwsyg1UYhIFhpUR6R0x7K";
        pub const deps: []const struct { []const u8, []const u8 } = &.{};
    };
    pub const @"protobuf-3.0.0-0e82atQRKQAeWaBvhs4mtvWwJ6oZ42Deivtk1rZLUKx3" = struct {
        pub const build_root = "/Users/jea/.cache/zig/p/protobuf-3.0.0-0e82atQRKQAeWaBvhs4mtvWwJ6oZ42Deivtk1rZLUKx3";
        pub const build_zig = @import("protobuf-3.0.0-0e82atQRKQAeWaBvhs4mtvWwJ6oZ42Deivtk1rZLUKx3");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "protoc-linux-64", "N-V-__8AAAOIwgCuuT3IhPlAW6erD8SspcE7iVKY4nbJWLV6" },
            .{ "protoc-linux-x86_64", "N-V-__8AAGKbngAmNuaBMSXq_WgmQi6N8WVWVKp0moFSTvoJ" },
            .{ "protoc-linux-x86_32", "N-V-__8AAHpvrAAEcEurDCWYQt6jTJSozCfLDwkGTptKEyJ7" },
            .{ "protoc-linux-aarch_64", "N-V-__8AAJKMngA8y82sENkRg-JF100BtRa7GQxoBIfU3c3_" },
            .{ "protoc-osx-aarch_64", "N-V-__8AANrukAA2AHP6xuzchs_iwsyg1UYhIFhpUR6R0x7K" },
            .{ "protoc-osx-x86_64", "N-V-__8AAFoXkgBrHnNjViSdp84aL1ciwtWKZdYHK7dSSppd" },
            .{ "protoc-win64", "N-V-__8AAAOIwgCuuT3IhPlAW6erD8SspcE7iVKY4nbJWLV6" },
            .{ "protoc-linux-s390", "N-V-__8AADKo3ADb6qHynR1iiBhHFQcaoAE0qpLZuh3GtoT2" },
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "protobuf", "protobuf-3.0.0-0e82atQRKQAeWaBvhs4mtvWwJ6oZ42Deivtk1rZLUKx3" },
};
