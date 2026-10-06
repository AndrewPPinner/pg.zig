const std = @import("std");
const Pool = @import("pool.zig").Pool;
const Result = @import("result.zig").Result;

pub const MockPool = struct {
    //Could do a custom hasher and do tuple key of sql and values (too much work)
    query_return_dict: std.StringHashMap(!Result),
    exec_return_dict: std.StringHashMap(!i64),

    pub fn init(alloc: std.mem.Allocator) @This() {
        return .{
            .query_return_dict = std.StringHashMap(!Result).init(alloc),
            .exec_return_dict = std.StringHashMap(!i64).init(alloc),
        };
    }

    pub fn deinit(self: *MockPool) void {
        self.query_return_dict.deinit();
        self.exec_return_dict.deinit();
    }

    pub fn addQueryReturn(self: *MockPool, sql: []const u8, value: anytype) void {
        self.query_return_dict.put(sql, value);
    }
    pub fn addExecReturn(self: *MockPool, sql: []const u8, value: anytype) void {
        self.exec_return_dict.put(sql, value);
    }

    pub fn query(self: *MockPool, sql: []const u8, _: anytype) !*Result {
        const result = self.exec_return_dict.get(sql);
        return try result;
    }

    pub fn exec(self: *MockPool, sql: []const u8, _: anytype) !?i64 {
        const result = self.exec_return_dict.get(sql);
        return try result;
    }
};
