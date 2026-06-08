const proto = @import("proto");
const types = @import("types.zig");

const Policy = proto.policy.Policy;

/// Re-export TransformResult for use by providers
pub const TransformResult = types.TransformResult;

/// Update notification sent by providers to subscribers
pub const PolicyUpdate = struct {
    policies: []const Policy,
    /// ID of the provider that sent this update
    provider_id: []const u8,
};

/// Callback signature for policy updates
/// Context is provider-specific state, onUpdate is called when policies change
pub const PolicyCallback = struct {
    context: *anyopaque,
    onUpdate: *const fn (context: *anyopaque, update: PolicyUpdate) anyerror!void,

    pub fn call(self: PolicyCallback, update: PolicyUpdate) !void {
        try self.onUpdate(self.context, update);
    }
};
