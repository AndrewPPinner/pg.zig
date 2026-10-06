const std = @import("std");
const Pool = @import("pool.zig").Pool;
const Result = @import("result.zig").Result;

pub const MockPool = struct {
    //Could do a custom hasher and do tuple key of sql and values (too much work)
    query_return_dict: std.StringHashMap(anyerror!Result),
    exec_return_dict: std.StringHashMap(anyerror!?i64),
    query_call_count: u32,
    exec_call_count: u32,

    pub fn init(alloc: std.mem.Allocator) @This() {
        return .{
            .query_return_dict = std.StringHashMap(anyerror!Result).init(alloc),
            .exec_return_dict = std.StringHashMap(anyerror!?i64).init(alloc),
            .query_call_count = 0,
            .exec_call_count = 0,
        };
    }

    pub fn deinit(self: *MockPool) void {
        self.query_return_dict.deinit();
        self.exec_return_dict.deinit();
    }

    pub fn addQueryReturn(self: *MockPool, sql: []const u8, value: anyerror!Result) !void {
        try self.query_return_dict.put(sql, value);
    }
    pub fn addExecReturn(self: *MockPool, sql: []const u8, value: anyerror!?i64) !void {
        try self.exec_return_dict.put(sql, value);
    }

    pub fn query(self: *MockPool, sql: []const u8, _: anytype) !*Result {
        self.query_call_count += 1;
        const result = self.exec_return_dict.get(sql);
        return result;
    }

    pub fn exec(self: *MockPool, sql: []const u8, _: anytype) !?i64 {
        self.exec_call_count += 1;
        const result = self.exec_return_dict.get(sql);
        return result.?;
    }
};
