#pragma author Glenn Hartmann
#pragma description BTRFS Send Stream format - see https://btrfs.readthedocs.io/en/latest/dev/dev-send-stream.html. Currently only supports version 1.

#pragma magic [ 62 74 72 66 73 2D 73 74 72 65 61 6D ] @ 0x0

#pragma endian little

import std.hash;
import std.io;
import std.mem;
import std.sys;
import type.guid;
import type.magic;
import type.time;

// See https://btrfs.readthedocs.io/en/latest/dev/dev-send-stream.html#stream-version-1.
enum CommandType : u16 {
    BTRFS_SEND_C_UNSPEC         = 0,
    BTRFS_SEND_C_SUBVOL         = 1,
    BTRFS_SEND_C_SNAPSHOT       = 2,
    BTRFS_SEND_C_MKFILE         = 3,
    BTRFS_SEND_C_MKDIR          = 4,
    BTRFS_SEND_C_MKNOD          = 5,
    BTRFS_SEND_C_MKFIFO         = 6,
    BTRFS_SEND_C_MKSOCK         = 7,
    BTRFS_SEND_C_SYMLINK        = 8,
    BTRFS_SEND_C_RENAME         = 9,
    BTRFS_SEND_C_LINK           = 10,
    BTRFS_SEND_C_UNLINK         = 11,
    BTRFS_SEND_C_RMDIR          = 12,
    BTRFS_SEND_C_SET_XATTR      = 13,
    BTRFS_SEND_C_REMOVE_XATTR   = 14,
    BTRFS_SEND_C_WRITE          = 15,
    BTRFS_SEND_C_CLONE          = 16,
    BTRFS_SEND_C_TRUNCATE       = 17,
    BTRFS_SEND_C_CHMOD          = 18,
    BTRFS_SEND_C_CHOWN          = 19,
    BTRFS_SEND_C_UTIMES         = 20,
    BTRFS_SEND_C_END            = 21,
    BTRFS_SEND_C_UPDATE_EXTENT  = 22,
};

// See https://btrfs.readthedocs.io/en/latest/dev/dev-send-stream.html#attributes-tlv-types.
enum AttributeType : u16 {
    BTRFS_SEND_A_UNSPEC          = 0,
    BTRFS_SEND_A_UUID            = 1,
    BTRFS_SEND_A_CTRANSID        = 2,
    BTRFS_SEND_A_INO             = 3,
    BTRFS_SEND_A_SIZE            = 4,
    BTRFS_SEND_A_MODE            = 5,
    BTRFS_SEND_A_UID             = 6,
    BTRFS_SEND_A_GID             = 7,
    BTRFS_SEND_A_RDEV            = 8,
    BTRFS_SEND_A_CTIME           = 9,
    BTRFS_SEND_A_MTIME           = 10,
    BTRFS_SEND_A_ATIME           = 11,
    BTRFS_SEND_A_OTIME           = 12,
    BTRFS_SEND_A_XATTR_NAME      = 13,
    BTRFS_SEND_A_XATTR_DATA      = 14,
    BTRFS_SEND_A_PATH            = 15,
    BTRFS_SEND_A_PATH_TO         = 16,
    BTRFS_SEND_A_PATH_LINK       = 17,
    BTRFS_SEND_A_FILE_OFFSET     = 18,
    BTRFS_SEND_A_DATA            = 19,
    BTRFS_SEND_A_CLONE_UUID      = 20,
    BTRFS_SEND_A_CLONE_CTRANSID  = 21,
    BTRFS_SEND_A_CLONE_PATH      = 22,
    BTRFS_SEND_A_CLONE_OFFSET    = 23,
    BTRFS_SEND_A_CLONE_LEN       = 24,
};

struct TimeSpec {
    u64 seconds;
    u32 nanoseconds;
} [[format("format_time_spec")]];

// Formats the "seconds" part of the TimeSpec as a time64_t.
fn format_time_spec(TimeSpec ts) {
    return type::impl::format_time_t(ts.seconds);
};

struct Attribute {
    AttributeType type;
    u16 length;

    u64 pre_data_pos = $;
    match (type) {
        (AttributeType::BTRFS_SEND_A_UNSPEC):          std::error("got unspecified attribute type");
        (AttributeType::BTRFS_SEND_A_UUID):            type::GUID uuid;
        (AttributeType::BTRFS_SEND_A_CLONE_UUID):      type::GUID clone_uuid;
        (AttributeType::BTRFS_SEND_A_CTRANSID):        u64 ctransid;
        (AttributeType::BTRFS_SEND_A_INO):             u64 ino;
        (AttributeType::BTRFS_SEND_A_SIZE):            u64 size;
        (AttributeType::BTRFS_SEND_A_MODE):            u64 mode;
        (AttributeType::BTRFS_SEND_A_UID):             u64 uid;
        (AttributeType::BTRFS_SEND_A_GID):             u64 gid;
        (AttributeType::BTRFS_SEND_A_RDEV):            u64 rdev;
        (AttributeType::BTRFS_SEND_A_CTIME):           TimeSpec ctime;
        (AttributeType::BTRFS_SEND_A_MTIME):           TimeSpec mtime;
        (AttributeType::BTRFS_SEND_A_ATIME):           TimeSpec atime;
        (AttributeType::BTRFS_SEND_A_OTIME):           TimeSpec otime;
        (AttributeType::BTRFS_SEND_A_XATTR_NAME):      char xattr_name[length];
        (AttributeType::BTRFS_SEND_A_XATTR_DATA):      u8 xattr_data[length];
        (AttributeType::BTRFS_SEND_A_PATH):            char path[length];
        (AttributeType::BTRFS_SEND_A_PATH_TO):         char path_to[length];
        (AttributeType::BTRFS_SEND_A_PATH_LINK):       char path_link[length];
        (AttributeType::BTRFS_SEND_A_FILE_OFFSET):     u64 file_offset;
        (AttributeType::BTRFS_SEND_A_DATA):            u8 data[length];
        (AttributeType::BTRFS_SEND_A_CLONE_CTRANSID):  u64 clone_ctransid;
        (AttributeType::BTRFS_SEND_A_CLONE_PATH):      char clone_path[length];
        (AttributeType::BTRFS_SEND_A_CLONE_OFFSET):    u64 clone_offset;
        (AttributeType::BTRFS_SEND_A_CLONE_LEN):       u64 clone_len;
        (_):                                           std::error(std::format("unknown attribute type: {}", type));
    }
    std::assert($ - pre_data_pos == length,
        std::format("bad attribute length: expected {}, got {}", length, $ - pre_data_pos));
};

// Length-defined array of |Attribute|s. As the name suggests, |ByteLength| is the array length in
// bytes, not in elements.
struct Attributes<auto ByteLength> {
    Attribute attributes[while(!std::mem::reached(addressof(this) + ByteLength))] [[inline]];
};

// The actual command structure. This is intended to be embedded inside a |Command| and
// [[inline]]d, so the user will never see the type name.
struct CommandInternal {
    u32 byte_length;
    CommandType type;
    u32 checksum; // CRC32C with initial seed 0
    Attributes<byte_length> attributes;
};

// Wrapper structure around a CommandInternal to verify the checksum.
struct Command {
    CommandInternal command [[inline]];

    std::mem::Section mySection = std::mem::create_section("checksum buffer");
    std::mem::set_section_size(mySection, sizeof(command));
    std::mem::copy_value_to_section(command, mySection, 0x0);

    // The checksum needs to be computed on the entire |command|, but with its |checksum| member
    // zeroed out, so we have to copy the data into a Section and modify it.
    CommandInternal section_command @ 0x0 in mySection;
    std::assert(sizeof(command) == sizeof(section_command),
        std::format("|section_command| is the wrong size: expected {}, got {}",
            sizeof(command), sizeof(section_command)));
    section_command.checksum = 0;

    // For some reason, running the crc32 on |section_command| directly always gets the wrong value.
    u8 data[sizeof(command)] @ 0x0 in mySection;
    u32 crc32c = std::hash::crc32(data, 0 /* init */, 0x1EDC6F41 /* poly */,
        0 /* xorout */, true /* reflect_in */, true /* reflect_out */);
    std::assert(crc32c == command.checksum,
        std::format("bad command checksum: expected {}, got {}", command.checksum, crc32c));

    std::mem::delete_section(mySection);
};

struct SendStream {
    type::Magic<"btrfs-stream"> magic;
    padding[1];
    u32 version;
    std::assert(version == 1,
        std::format("Only version 1 is currently supported (got version {})", version));
    Command commands[while(!std::mem::eof())];
};

SendStream send_stream @ 0x0;
std::assert(std::mem::eof(), "Parsing did not consume whole file.");
