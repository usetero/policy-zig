//! Link probe used to enforce the production evaluator instruction-page budget.

const std = @import("std");
const runtime = @import("policy_runtime");

pub fn main() void {
    std.mem.doNotOptimizeAway(&runtime.evaluate);
}
