const std = @import("std");
const builtin = @import("builtin");
const lib = @import("lib.zig");

const openssl = lib.openssl;

const posix = std.posix;

const Conn = lib.Conn;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const DEFAULT_HOST = "127.0.0.1";

pub const Stream = if (lib.has_openssl) TLSStream else PlainStream;

const TLSStream = struct {
    valid: bool,
    ssl: ?*openssl.SSL,
    stream_bio: ?*StreamBio,
    stream: Io.net.Stream,
    io: Io,

    pub fn connect(io: Io, allocator: Allocator, opts: Conn.Opts, ctx_: ?*openssl.SSL_CTX) !Stream {
        const plain = try PlainStream.connect(io, allocator, opts, null);
        errdefer plain.close();

        const stream = plain.stream;

        var ssl: ?*openssl.SSL = null;
        var stream_bio: ?*StreamBio = null;
        if (ctx_) |ctx| {
            // PostgreSQL TLS starts off as a plain connection which we upgrade
            try writeStream(stream, io, &.{ 0, 0, 0, 8, 4, 210, 22, 47 });
            var buf = [1]u8{0};
            _ = try readStream(stream, io, &buf);
            if (buf[0] != 'S') {
                return error.SSLNotSupportedByServer;
            }

            ssl = openssl.SSL_new(ctx) orelse return error.SSLNewFailed;
            errdefer openssl.SSL_free(ssl);

            if (opts.host) |host| {
                if (isHostName(host)) {
                    // don't send this for an ip address
                    var owned = false;
                    const h = opts._hostz orelse blk: {
                        owned = true;
                        break :blk try allocator.dupeZ(u8, host);
                    };

                    defer if (owned) {
                        allocator.free(h);
                    };

                    if (openssl.SSL_set_tlsext_host_name(ssl, h.ptr) != 1) {
                        return error.SSLHostNameFailed;
                    }
                }
                switch (opts.tls) {
                    .verify_full => openssl.SSL_set_verify(ssl, openssl.SSL_VERIFY_PEER, null),
                    else => {},
                }
            }

            stream_bio = try StreamBio.init(stream, io, allocator);
            errdefer stream_bio.?.deinit();

            openssl.SSL_set_bio(ssl, stream_bio.?.bio, stream_bio.?.bio);

            {
                const ret = openssl.SSL_connect(ssl);
                if (ret != 1) {
                    const err = openssl.SSL_get_error(ssl, ret);
                    const err2 = windows.std_windows.GetLastError();
                    std.log.debug("{} {}", .{ err, err2 });
                    const verification_code = openssl.SSL_get_verify_result(ssl);
                    if (comptime lib._stderr_tls) {
                        lib.printSSLError();
                    }
                    if (verification_code != openssl.X509_V_OK) {
                        if (comptime lib._stderr_tls) {
                            std.debug.print("ssl verification error: {s}\n", .{openssl.X509_verify_cert_error_string(verification_code)});
                        }
                        return error.SSLCertificationVerificationError;
                    }
                    return error.SSLConnectFailed;
                }
            }
        }

        return .{
            .ssl = ssl,
            .valid = true,
            .stream = stream,
            .io = io,
            .stream_bio = stream_bio,
        };
    }

    pub fn close(self: *Stream) void {
        if (self.ssl) |ssl| {
            if (self.valid) {
                _ = openssl.SSL_shutdown(ssl);
                self.valid = false;
            }
            openssl.SSL_free(ssl);

            if (self.stream_bio) |sb| sb.deinit();
        }
        self.stream.close(self.io);
    }

    pub fn shutdown(self: *const Stream, how: Io.net.ShutdownHow) !void {
        return self.stream.shutdown(self.io, how);
    }

    pub fn writeAll(self: *Stream, data: []const u8) !void {
        if (self.ssl) |ssl| {
            const result = openssl.SSL_write(ssl, data.ptr, @intCast(data.len));
            if (result <= 0) {
                self.valid = false;
                return error.SSLWriteFailed;
            }
            return;
        }
        return writeStream(self.stream, self.io, data);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.ssl) |ssl| {
            var read_len: usize = undefined;
            const result = openssl.SSL_read_ex(ssl, buf.ptr, @intCast(buf.len), &read_len);
            if (result <= 0) {
                self.valid = false;
                return error.SSLReadFailed;
            }
            return read_len;
        }

        return readStream(self.stream, self.io, buf);
    }
};

const PlainStream = struct {
    io: Io,
    stream: Io.net.Stream,

    pub fn connect(io: Io, _: Allocator, opts: Conn.Opts, _: anytype) !PlainStream {
        const host = opts.host orelse DEFAULT_HOST;
        const is_unix = host.len > 0 and host[0] == '/';

        const stream = try blk: {
            if (is_unix) {
                if (comptime Io.net.has_unix_sockets == false or std.posix.AF == void) {
                    return error.UnixPathNotSupported;
                }
                const addr: Io.net.UnixAddress = try .init(host);
                break :blk addr.connect(io);
            }
            const port = opts.port orelse 5432;
            const hostname: Io.net.HostName = try .init(host);
            break :blk hostname.connect(io, port, .{ .mode = .stream });
        };
        errdefer stream.close(io);

        if (is_unix == false) {
            try setKeepalive(stream.socket.handle, opts);
        }

        return .{
            .io = io,
            .stream = stream,
        };
    }

    pub fn close(self: *const PlainStream) void {
        self.stream.close(self.io);
    }

    pub fn shutdown(self: *const PlainStream, how: Io.net.ShutdownHow) !void {
        return self.stream.shutdown(self.io, how);
    }

    pub fn writeAll(self: *const PlainStream, data: []const u8) !void {
        return writeStream(self.stream, self.io, data);
    }

    pub fn read(self: *const PlainStream, buf: []u8) !usize {
        return readStream(self.stream, self.io, buf);
    }
};

const StreamBio = struct {
    allocator: Allocator,
    bio: *openssl.BIO,
    method: *openssl.BIO_METHOD,
    stream: Io.net.Stream,
    io: Io,

    fn read(bio: ?*openssl.BIO, buffer: [*c]u8, len: usize, read_count: [*c]usize) callconv(.c) c_int {
        const ctx: *StreamBio = @ptrCast(
            @alignCast(openssl.BIO_get_data(bio)),
        );

        const dst = buffer[0..len];

        const n = readStream(ctx.stream, ctx.io, dst) catch {
            read_count.* = 0;
            return 0;
        };

        read_count.* = n;
        return 1;
    }

    fn write(bio: ?*openssl.BIO, buffer: [*c]const u8, len: usize, written: [*c]usize) callconv(.c) c_int {
        const ctx: *StreamBio = @ptrCast(
            @alignCast(openssl.BIO_get_data(bio)),
        );

        const src = buffer[0..len];

        writeStream(ctx.stream, ctx.io, src) catch {
            written.* = 0;
            return 0;
        };

        written.* = len;
        return 1;
    }

    fn ctrl(bio: ?*openssl.BIO, cmd: c_int, num: c_long, ptr: ?*anyopaque) callconv(.c) c_long {
        _ = bio;
        _ = num;
        _ = ptr;

        return switch (cmd) {
            openssl.BIO_CTRL_FLUSH => 1,
            else => 0,
        };
    }

    fn configure_bio_method() !*openssl.BIO_METHOD {
        const new_bio_method = openssl.BIO_meth_new(openssl.BIO_TYPE_SOURCE_SINK, "zig io.net stream") orelse {
            return error.BioMethodCreateFailed;
        };

        if (openssl.BIO_meth_set_read_ex(new_bio_method, StreamBio.read) != 1) {
            return error.BioMethodReadFailed;
        }

        if (openssl.BIO_meth_set_write_ex(new_bio_method, StreamBio.write) != 1) {
            return error.BioMethodWriteFailed;
        }

        if (openssl.BIO_meth_set_ctrl(new_bio_method, StreamBio.ctrl) != 1) {
            return error.BioMethodCtrlFailed;
        }

        return new_bio_method;
    }

    fn create_bio(method: *openssl.BIO_METHOD) !*openssl.BIO {
        const bio = openssl.BIO_new(method) orelse
            return error.BioCreateFailed;

        return bio;
    }

    pub fn init(stream: Io.net.Stream, io: Io, alloc: Allocator) !*StreamBio {
        const method = try configure_bio_method();
        errdefer openssl.BIO_meth_free(method);

        const bio = try create_bio(method);
        errdefer _ = openssl.BIO_free(bio);

        const self = try alloc.create(StreamBio);
        errdefer alloc.destroy(self);
        self.* = .{ .stream = stream, .io = io, .bio = bio, .allocator = alloc, .method = method };
        openssl.BIO_set_data(self.bio, @ptrCast(self));
        openssl.BIO_set_init(self.bio, 1);

        return self;
    }

    // Does not free bio since BIOs assigned to SSL via SSL_set_bio are automatically freed when SSL_free is called
    pub fn deinit(self: *StreamBio) void {
        openssl.BIO_meth_free(self.method);
        self.allocator.destroy(self);
    }
};

const TCP = switch (builtin.os.tag) {
    // Zig doesn't expose these /shrug
    .freebsd, .dragonfly => struct {
        pub const KEEPIDLE = 256;
        pub const KEEPINTVL = 512;
        pub const KEEPCNT = 1024;
    },
    .netbsd => struct {
        pub const KEEPIDLE = 3;
        pub const KEEPINTVL = 5;
        pub const KEEPCNT = 6;
    },
    .illumos => struct {
        pub const KEEPIDLE = 0x22;
        pub const KEEPCNT = 0x23;
        pub const KEEPINTVL = 0x24;
    },
    else => if (posix.TCP == void) struct {} else posix.TCP,
};

fn setKeepalive(handle: posix.socket_t, opts: Conn.Opts) !void {
    if (opts.keepalive == false) {
        return;
    }
    const on: c_int = 1;
    try setsockopt(handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&on));

    const level = posix.IPPROTO.TCP;

    if (opts.keepalive_idle) |idle| {
        const optname: ?u32 = comptime if (@hasDecl(TCP, "KEEPIDLE"))
            TCP.KEEPIDLE
        else if (@hasDecl(TCP, "KEEPALIVE"))
            TCP.KEEPALIVE
        else
            null;
        if (optname) |name| {
            const v: c_int = @intCast(idle);
            setsockopt(handle, level, name, std.mem.asBytes(&v)) catch {};
        }
    }

    if (opts.keepalive_interval) |intvl| {
        if (comptime @hasDecl(TCP, "KEEPINTVL")) {
            const v: c_int = @intCast(intvl);
            setsockopt(handle, level, TCP.KEEPINTVL, std.mem.asBytes(&v)) catch {};
        }
    }

    if (opts.keepalive_count) |cnt| {
        if (comptime @hasDecl(TCP, "KEEPCNT")) {
            const v: c_int = @intCast(cnt);
            setsockopt(handle, level, TCP.KEEPCNT, std.mem.asBytes(&v)) catch {};
        }
    }
}

fn setsockopt(fd: posix.socket_t, level: i32, optname: u32, opt: []const u8) !void {
    if (@import("builtin").os.tag != .windows) {
        return posix.setsockopt(fd, level, optname, opt);
    }

    const SO = posix.SO;
    const SOL = posix.SOL;
    const timeval = posix.timeval;

    var ms_buf: u32 = 0;
    var opt_ptr: [*]const u8 = opt.ptr;
    var opt_len: i32 = @intCast(opt.len);
    if (level == SOL.SOCKET and (optname == SO.RCVTIMEO or optname == SO.SNDTIMEO) and opt.len == @sizeOf(timeval)) {
        const tv: *const timeval = @ptrCast(@alignCast(opt.ptr));
        const total_ms = @as(i64, tv.sec) * 1000 + @divTrunc(@as(i64, tv.usec), 1000);
        ms_buf = if (total_ms < 0) 0 else @intCast(@min(total_ms, std.math.maxInt(u32)));
        opt_ptr = @ptrCast(&ms_buf);
        opt_len = @sizeOf(u32);
    }

    const in: []const u8 = @ptrCast(&std.os.windows.AFD.SOCKOPT_INFO{
        .mode = .set,
        .level = level,
        .optname = optname,
        .optval = opt_ptr,
        .optlen = @intCast(opt_len),
    });

    var iosb: std.os.windows.IO_STATUS_BLOCK = undefined;
    switch (std.os.windows.ntdll.NtDeviceIoControlFile(
        fd,
        null, // event
        null, // APC routine
        null, // APC context
        &iosb,
        std.os.windows.IOCTL.AFD.SOCKOPT,
        if (in.len > 0) in.ptr else null,
        @intCast(in.len),
        null,
        0,
    )) {
        .SUCCESS => return,
        .CANCELLED => return error.Canceled,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return std.os.windows.unexpectedStatus(status),
    }
}

fn readStream(stream: Io.net.Stream, io: Io, buf: []u8) !usize {
    var vecs: [1][]u8 = .{buf};
    var reader = stream.reader(io, &.{});
    const r = &reader.interface;
    return r.readVec(&vecs) catch |err| switch (err) {
        error.ReadFailed => return reader.err orelse err,
        else => return err,
    };
}

fn writeStream(stream: Io.net.Stream, io: Io, data: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &buf);
    const w = &writer.interface;
    w.writeAll(data) catch |err| switch (err) {
        error.WriteFailed => return writer.err orelse err,
    };
    w.flush() catch |err| switch (err) {
        error.WriteFailed => return writer.err orelse err,
    };
}

// Sends a best-effort Terminate ('X') message, shielded from cancellation so
// teardown can't be interrupted.
pub fn sendTerminate(stream: *Stream, io: Io) void {
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);
    stream.writeAll(&.{ 'X', 0, 0, 0, 4 }) catch {};
}

fn isHostName(host: []const u8) bool {
    if (std.mem.findScalar(u8, host, ':') != null) {
        // IPv6
        return false;
    }
    return std.mem.findNone(u8, host, "0123456789.") != null;
}

const windows = @import("windows.zig");
