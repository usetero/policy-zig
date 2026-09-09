//! Shared compile-time and runtime capacity contract.

const std = @import("std");

/// Every bounded policy subsystem derives its storage from this value.
pub const Capacity = struct {
    max_connections: u16,
    worker_count: u16,
    max_policy_images: u8 = 3,
    max_policies: u16,
    max_fields: u16,
    max_matchers: u32,
    max_actions: u32,
    max_image_bytes: u32,
    max_record_bytes: u32,
    max_context_bytes: u32,
    max_group_bytes: u32,
    journal_events_per_worker: u32,
    extension_queue_bytes: u32,

    pub const ValidationError = error{
        ZeroCapacity,
        UnsupportedImageSlotCount,
        PolicyIndexOverflow,
        FieldIndexOverflow,
        ImageTooSmall,
    };

    /// Reject internally inconsistent layouts before any storage is carved.
    pub fn validate(self: Capacity) ValidationError!void {
        if (self.max_connections == 0 or
            self.worker_count == 0 or
            self.max_policies == 0 or
            self.max_fields == 0 or
            self.max_image_bytes == 0 or
            self.max_record_bytes == 0 or
            self.max_context_bytes == 0 or
            self.max_group_bytes == 0 or
            self.journal_events_per_worker == 0)
        {
            return error.ZeroCapacity;
        }
        if (self.max_policy_images != 3) return error.UnsupportedImageSlotCount;
        if (self.max_policies == std.math.maxInt(u16)) return error.PolicyIndexOverflow;
        if (self.max_fields == std.math.maxInt(u16)) return error.FieldIndexOverflow;
        if (self.max_image_bytes < 128) return error.ImageTooSmall;
    }
};

test "capacity rejects inconsistent configurations" {
    const valid: Capacity = .{
        .max_connections = 4,
        .worker_count = 2,
        .max_policies = 256,
        .max_fields = 64,
        .max_matchers = 1024,
        .max_actions = 512,
        .max_image_bytes = 1024 * 1024,
        .max_record_bytes = 64 * 1024,
        .max_context_bytes = 4096,
        .max_group_bytes = 1024,
        .journal_events_per_worker = 1024,
        .extension_queue_bytes = 64 * 1024,
    };
    try valid.validate();

    var invalid = valid;
    invalid.max_policy_images = 2;
    try std.testing.expectError(error.UnsupportedImageSlotCount, invalid.validate());
}
