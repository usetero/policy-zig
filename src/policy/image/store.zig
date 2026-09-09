//! Three-slot image publication with exact worker epoch announcements.

const std = @import("std");
const capacity_mod = @import("policy_capacity");
const image_mod = @import("policy_image");

pub const Capacity = capacity_mod.Capacity;
pub const PolicyImage = image_mod.PolicyImage;

pub const EpochSlot = struct {
    value: std.atomic.Value(u64) = .init(0),
};

pub const ImageSlot = struct {
    storage: []u8,
    image_len: u32 = 0,
    epoch: u64 = 0,
};

pub const BuildSlot = struct {
    index: u8,
    storage: []u8,
};

pub const StoreError = error{
    InvalidCapacity,
    SlotCountMismatch,
    WorkerCountMismatch,
    SlotTooSmall,
    NoReusableSlot,
    InvalidSlot,
    CorruptImage,
    ImageTooLarge,
    WorkerOutOfRange,
    EpochOverflow,
};

/// Publication is a single release-store of `{epoch, slot}`. Mutable slot
/// metadata is control-plane-only and must be serialized by the host compiler.
pub const ImageStore = struct {
    capacity: Capacity,
    slots: []ImageSlot,
    worker_epochs: []EpochSlot,
    published: std.atomic.Value(u64) = .init(0),
    next_epoch: u64 = 1,

    pub fn init(capacity: Capacity, slots: []ImageSlot, worker_epochs: []EpochSlot) StoreError!ImageStore {
        capacity.validate() catch return error.InvalidCapacity;
        if (slots.len != capacity.max_policy_images) return error.SlotCountMismatch;
        if (worker_epochs.len != capacity.worker_count) return error.WorkerCountMismatch;
        for (slots) |slot| {
            if (slot.storage.len < capacity.max_image_bytes) return error.SlotTooSmall;
        }
        for (worker_epochs) |*slot| slot.value.store(0, .monotonic);
        return .{
            .capacity = capacity,
            .slots = slots,
            .worker_epochs = worker_epochs,
        };
    }

    /// Returns an inactive destination only when no worker announces the
    /// epoch that most recently occupied it.
    pub fn beginBuild(self: *ImageStore) StoreError!BuildSlot {
        const active_index = unpackIndex(self.published.load(.acquire));
        for (self.slots, 0..) |slot, index| {
            if (active_index != null and active_index.? == index) continue;
            if (slot.epoch != 0 and self.isAnnounced(slot.epoch)) continue;
            return .{
                .index = @intCast(index),
                .storage = self.slots[index].storage[0..self.capacity.max_image_bytes],
            };
        }
        return error.NoReusableSlot;
    }

    /// Validate and atomically expose a completely written inactive image.
    pub fn publish(self: *ImageStore, slot_index: u8, image_len: usize) StoreError!u64 {
        if (slot_index >= self.slots.len) return error.InvalidSlot;
        const active_index = unpackIndex(self.published.load(.acquire));
        if (active_index != null and active_index.? == slot_index) return error.InvalidSlot;
        const slot = &self.slots[slot_index];
        if (slot.epoch != 0 and self.isAnnounced(slot.epoch)) return error.NoReusableSlot;
        if (image_len > self.capacity.max_image_bytes or image_len > slot.storage.len) return error.ImageTooLarge;
        _ = image_mod.PolicyImage.open(slot.storage[0..image_len]) catch return error.CorruptImage;
        if (self.next_epoch == std.math.maxInt(u56)) return error.EpochOverflow;
        const epoch = self.next_epoch;
        self.next_epoch += 1;
        slot.image_len = @intCast(image_len);
        slot.epoch = epoch;
        self.published.store(pack(epoch, slot_index), .release);
        return epoch;
    }

    pub fn acquire(self: *ImageStore, worker_id: u16) StoreError!?ImageLease {
        if (worker_id >= self.worker_epochs.len) return error.WorkerOutOfRange;
        const announcement = &self.worker_epochs[worker_id];
        while (true) {
            const before = self.published.load(.acquire);
            const index = unpackIndex(before) orelse {
                announcement.value.store(0, .release);
                return null;
            };
            const epoch = unpackEpoch(before);
            announcement.value.store(epoch, .release);
            if (self.published.load(.acquire) != before) continue;
            const slot = &self.slots[index];
            const policy_image = image_mod.PolicyImage.open(slot.storage[0..slot.image_len]) catch {
                announcement.value.store(0, .release);
                return error.CorruptImage;
            };
            return .{
                .image = policy_image,
                .epoch = epoch,
                .announcement = announcement,
            };
        }
    }

    pub fn activeEpoch(self: *const ImageStore) u64 {
        return unpackEpoch(self.published.load(.acquire));
    }

    fn isAnnounced(self: *const ImageStore, epoch: u64) bool {
        for (self.worker_epochs) |*slot| {
            if (slot.value.load(.acquire) == epoch) return true;
        }
        return false;
    }
};

pub const ImageLease = struct {
    image: PolicyImage,
    epoch: u64,
    announcement: *EpochSlot,

    /// Clear only at a safe request or record boundary.
    pub fn release(self: *ImageLease) void {
        self.announcement.value.store(0, .release);
        self.* = undefined;
    }
};

pub const PolicyRegistry = ImageStore;
pub const PolicySnapshot = PolicyImage;

fn pack(epoch: u64, index: u8) u64 {
    std.debug.assert(epoch <= std.math.maxInt(u56));
    return (epoch << 8) | (@as(u64, index) + 1);
}

fn unpackEpoch(value: u64) u64 {
    return value >> 8;
}

fn unpackIndex(value: u64) ?u8 {
    const encoded: u8 = @truncate(value);
    return if (encoded == 0) null else encoded - 1;
}

test "announced retired image cannot be reused" {
    const compiler_mod = @import("policy_compiler");
    const capacity: Capacity = .{
        .max_connections = 2,
        .worker_count = 1,
        .max_policies = 4,
        .max_fields = 4,
        .max_matchers = 4,
        .max_actions = 4,
        .max_image_bytes = 1024,
        .max_record_bytes = 1024,
        .max_context_bytes = 256,
        .max_group_bytes = 128,
        .journal_events_per_worker = 8,
        .extension_queue_bytes = 128,
    };
    var bytes: [3][1024]u8 = undefined;
    var slots = [_]ImageSlot{
        .{ .storage = &bytes[0] },
        .{ .storage = &bytes[1] },
        .{ .storage = &bytes[2] },
    };
    var epochs = [_]EpochSlot{.{}};
    var store = try ImageStore.init(capacity, &slots, &epochs);
    var workspace: [512]u8 = undefined;

    const field: compiler_mod.FieldSpec = .{ .signal = .log, .value_kind = .string, .selector_id = 1, .name = "body" };
    const matchers = [_]compiler_mod.MatcherSpec{.{ .field = field, .opcode = .exists }};
    const policies = [_]compiler_mod.PolicySpec{.{ .id = "p", .verdict = .keep, .matchers = &matchers }};

    const first_build = try store.beginBuild();
    var compiler = try compiler_mod.Compiler.init(capacity, &workspace, first_build.storage);
    const first = try compiler.compile(.{ .policies = &policies, .seed = 1 });
    const first_epoch = try store.publish(first_build.index, first.len);
    var lease = (try store.acquire(0)).?;
    try std.testing.expectEqual(first_epoch, lease.epoch);

    const second_build = try store.beginBuild();
    compiler = try compiler_mod.Compiler.init(capacity, &workspace, second_build.storage);
    const second = try compiler.compile(.{ .policies = &policies, .seed = 2 });
    _ = try store.publish(second_build.index, second.len);

    for (3..103) |seed| {
        const churn_build = try store.beginBuild();
        try std.testing.expect(churn_build.index != first_build.index);
        compiler = try compiler_mod.Compiler.init(capacity, &workspace, churn_build.storage);
        const churned = try compiler.compile(.{ .policies = &policies, .seed = seed });
        _ = try store.publish(churn_build.index, churned.len);
    }
    lease.release();
    const reusable = try store.beginBuild();
    try std.testing.expectEqual(first_build.index, reusable.index);
}
