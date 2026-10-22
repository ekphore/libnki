// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "internal.h"
#include "libnki/nki.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>
#include <zlib.h>

namespace libnki {
using namespace detail::patch;

namespace detail::patch {

std::size_t fastlz_decompress(
        std::span<const std::byte> input, std::span<std::byte> output) {
    if (input.empty())
        return 0;
    const auto level = (std::to_integer<unsigned>(input[0]) >> 5U) + 1U;
    if (level != 1 && level != 2)
        return 0;
    std::size_t ip = 1;
    std::size_t op = 0;
    unsigned ctrl = std::to_integer<unsigned>(input[0]) & 31U;
    constexpr std::size_t kMaxDistance = 8191;

    for (;;) {
        if (ctrl >= 32) {
            // both FastLZ levels share the biased length and extension sentinel
            std::size_t len = (ctrl >> 5U) - 1U;
            std::size_t ofs = (ctrl & 31U) << 8U;
            if (len == 6) {
                if (level == 1) {
                    if (ip >= input.size())
                        return 0;
                    len += std::to_integer<unsigned>(input[ip++]);
                } else {
                    unsigned code;
                    do {
                        if (ip >= input.size())
                            return 0;
                        code = std::to_integer<unsigned>(input[ip++]);
                        len += code;
                    } while (code == 255);
                }
            }
            if (ip >= input.size())
                return 0;
            const auto code = std::to_integer<unsigned>(input[ip++]);
            std::size_t distance = ofs + code + 1U;
            if (level == 2 && code == 255 && ofs == (31U << 8U)) {
                if (ip + 2 > input.size())
                    return 0;
                const auto far = (std::to_integer<unsigned>(input[ip]) << 8U) |
                                 std::to_integer<unsigned>(input[ip + 1]);
                ip += 2;
                // level 2's far reference starts one byte before op-far-0x1fff,
                // so its effective base distance is 0x2000
                distance = far + kMaxDistance + 1U;
            }
            len += 3;
            if (distance == 0 || distance > op || len > output.size() - op)
                return 0;
            auto ref = op - distance;
            for (std::size_t i = 0; i < len; ++i)
                output[op++] = output[ref++];
        } else {
            const auto len = static_cast<std::size_t>(ctrl) + 1U;
            if (len > input.size() - ip || len > output.size() - op)
                return 0;
            std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(ip), len,
                    output.begin() + static_cast<std::ptrdiff_t>(op));
            ip += len;
            op += len;
        }
        if (ip >= input.size())
            break;
        ctrl = std::to_integer<unsigned>(input[ip++]);
    }
    return op;
}

std::uint16_t legacy_decimal_to_packed_bcd(std::uint16_t value) {
    const auto thousands = static_cast<std::uint16_t>(value / 1000U);
    value = static_cast<std::uint16_t>(value - thousands * 1000U);
    const auto hundreds = static_cast<std::uint16_t>(value / 100U);
    value = static_cast<std::uint16_t>(value - hundreds * 100U);
    const auto tens = static_cast<std::uint16_t>(value / 10U);
    const auto ones = static_cast<std::uint16_t>(value - tens * 10U);
    return static_cast<std::uint16_t>(
            (thousands << 12U) | (hundreds << 8U) | (tens << 4U) | ones);
}

bool legacy_patch_magic(std::uint32_t value) {
    switch (value) {
        case 0xa4d6e55aU:
        case 0xab85ef01U:
        case 0xb36ee55eU:
        case 0x10874353U:
        case 0x74b5a69bU:
        case 0x7fa89012U:
            return true;
        default:
            return false;
    }
}

} // namespace detail::patch

std::array<std::byte, 16> calculate_k42_header_md5(
        std::span<const std::byte> normalized_header) {
    if (normalized_header.size() != K42PatchHeader::serialized_size) {
        throw std::invalid_argument(
                "BPatchHeaderV42 must be exactly 222 bytes");
    }
    auto header = std::vector<std::byte>(
            normalized_header.begin(), normalized_header.end());
    std::fill(header.begin() + 0xa2, header.begin() + 0xb2, std::byte{ 0 });
    static constexpr std::array<unsigned char, 2> prefix{ 0x09, 0xe2 };
    std::array<std::byte, 16> digest{};
    unsigned digest_size = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        throw std::runtime_error("cannot allocate MD5 context");
    const auto ok =
            EVP_DigestInit_ex(context, EVP_md5(), nullptr) == 1 &&
            EVP_DigestUpdate(context, prefix.data(), prefix.size()) == 1 &&
            EVP_DigestUpdate(context, header.data(), header.size()) == 1 &&
            EVP_DigestFinal_ex(context,
                    reinterpret_cast<unsigned char *>(digest.data()),
                    &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || digest_size != digest.size()) {
        throw std::runtime_error("BPatchHeaderV42 MD5 calculation failed");
    }
    return digest;
}

std::uint32_t kontakt_crc32(std::span<const std::byte> bytes) noexcept {
    std::uint32_t crc = 0xffffffffU;
    for (const auto byte : bytes) {
        crc ^= std::to_integer<std::uint8_t>(byte);
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1U) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

K42PatchData parse_k42_patch_data(std::span<const std::byte> bytes,
        std::optional<std::uint32_t> current_app_version,
        std::span<const std::byte> encryption_key) {
    if (bytes.size() < K42PatchHeader::serialized_size) {
        throw std::runtime_error("truncated BPatchHeaderV42");
    }
    K42PatchData out;
    std::copy_n(bytes.begin(), K42PatchHeader::serialized_size,
            out.header.normalized_bytes.begin());
    auto header = std::span<std::byte>(out.header.normalized_bytes);
    const auto native_magic = u32le(header, 0);
    const auto swapped_magic = byteswap32(native_magic);
    const auto is_v42_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    if (!is_v42_magic(native_magic) && !is_v42_magic(swapped_magic)) {
        throw std::runtime_error("unsupported BPatchHeaderV42 magic");
    }
    out.header.byte_swapped = !is_v42_magic(native_magic);
    if (out.header.byte_swapped) {
        auto swap16_at = [&](std::size_t offset) {
            std::swap(header[offset], header[offset + 1]);
        };
        auto swap32_at = [&](std::size_t offset) {
            std::swap(header[offset], header[offset + 3]);
            std::swap(header[offset + 1], header[offset + 2]);
        };
        for (const auto offset : { 0U, 4U, 10U, 16U, 20U, 24U, 36U, 40U, 44U,
                     50U, 54U, 0x9eU, 0xb2U, 0xb6U, 0xbaU }) {
            swap32_at(offset);
        }
        for (const auto offset :
                { 8U, 14U, 28U, 30U, 32U, 34U, 0x9aU, 0x9cU }) {
            swap16_at(offset);
        }
    }
    out.header.magic = u32le(header, 0);
    out.header.compressed_size = u32le(header, 4);
    out.header.revision = u16le(header, 8);
    out.header.artifact_kind = u16le(header, 0x0e);
    out.header.signature = u32le(header, 10);
    out.header.required_app_version = u32le(header, 0x2e);
    out.header.legacy_otp_word = u16le(header, 0x9a);
    out.header.library_word = u16le(header, 0x9c);
    out.header.flags = u32le(header, 0x9e);
    if ((out.header.flags & 0x10U) == 0) {
        if ((out.header.flags & 0x20U) != 0) {
            out.header.library_id = out.header.library_word;
        } else {
            const auto word =
                    static_cast<std::uint32_t>(out.header.library_word);
            const auto thousands = (out.header.library_word >> 3U) / 125U;
            auto remainder = word - thousands * 1000U;
            const auto hundreds = (remainder >> 2U) / 25U;
            remainder -= hundreds * 100U;
            const auto tens = remainder / 10U;
            out.header.library_id =
                    (thousands << 12U) | ((hundreds * 5243U >> 9U) & 0xff00U) |
                    ((tens * 205U >> 7U) & 0xf0U) | (remainder - tens * 10U);
        }
    }
    out.header.product_snpid = snpid_from_product_id(out.header.library_id);
    std::copy_n(header.begin() + 0xa2, out.header.md5.size(),
            out.header.md5.begin());
    out.header.payload_crc32 = u32le(header, 0xb6);
    out.header.uncompressed_size = u32le(header, 0xba);
    if (out.header.signature != 0xea37631aU) {
        throw std::runtime_error("BPatchHeaderV42 signature mismatch");
    }
    if (calculate_k42_header_md5(header) != out.header.md5) {
        throw std::runtime_error("BPatchHeaderV42 MD5 mismatch");
    }
    if (current_app_version &&
            *current_app_version < out.header.required_app_version) {
        throw std::runtime_error(
                "BPatchHeaderV42 requires a newer application version");
    }
    if (out.header.compressed_size == 0) {
        throw std::runtime_error(
                "BPatchHeaderV42 has an empty compressed payload");
    }
    const auto payload_offset = K42PatchHeader::serialized_size;
    if (out.header.compressed_size > bytes.size() - payload_offset) {
        throw std::runtime_error("truncated K42 compressed payload");
    }
    const auto stored_payload =
            bytes.subspan(payload_offset, out.header.compressed_size);
    if (kontakt_crc32(stored_payload) != out.header.payload_crc32) {
        throw std::runtime_error("K42 compressed payload CRC32 mismatch");
    }
    std::vector<std::byte> decrypted_payload;
    std::span<const std::byte> compressed = stored_payload;
    if (out.header.legacy_otp_encrypted()) {
        if (encryption_key.size() != (1U << 16)) {
            throw std::invalid_argument(
                    "K42 encrypted payload requires a 65536-byte product key");
        }
        const auto first_word = u16le(encryption_key, 0);
        const auto swapped_first_word = static_cast<std::uint16_t>(
                (first_word >> 8U) | (first_word << 8U));
        if (out.header.legacy_otp_word != swapped_first_word) {
            throw std::runtime_error("K42 product key marker mismatch");
        }
        decrypted_payload.assign(stored_payload.begin(), stored_payload.end());
        apply_encryption_item_xor(decrypted_payload, encryption_key);
        compressed = decrypted_payload;
    }
    out.decompressed.resize(out.header.uncompressed_size);
    const auto produced = fastlz_decompress(compressed, out.decompressed);
    if (produced != out.decompressed.size()) {
        throw std::runtime_error("K42 FastLZ output size mismatch (produced " +
                                 std::to_string(produced) + ", expected " +
                                 std::to_string(out.decompressed.size()) + ")");
    }
    out.chunks = scan_chunk_sequence(out.decompressed);
    return out;
}

std::string snpid_from_product_id(std::uint32_t product_id) {
    static constexpr char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (product_id < 0x1000U) {
        std::string out(3, '0');
        for (std::size_t i = 0; i < 3; ++i) {
            out[2 - i] = digits[(product_id >> (i * 4U)) & 0xfU];
        }
        return out;
    }
    auto value = product_id - 0xff0U;
    std::string out;
    do {
        out.push_back(digits[value % 36U]);
        value /= 36U;
    } while (value != 0);
    while (out.size() < 3)
        out.push_back('0');
    std::reverse(out.begin(), out.end());
    return out;
}

std::uint32_t k42_product_id(std::span<const std::byte> bytes) {
    if (bytes.size() < K42PatchHeader::serialized_size) {
        throw std::runtime_error("truncated BPatchHeaderV42");
    }
    const auto raw_magic = u32le(bytes, 0);
    const auto valid_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    const bool swapped =
            !valid_magic(raw_magic) && valid_magic(byteswap32(raw_magic));
    if (!valid_magic(raw_magic) && !swapped) {
        throw std::runtime_error("unsupported BPatchHeaderV42 magic");
    }
    auto word = u16le(bytes, 0x9c);
    auto flags = u32le(bytes, 0x9e);
    if (swapped) {
        word = static_cast<std::uint16_t>((word >> 8U) | (word << 8U));
        flags = byteswap32(flags);
    }
    if ((flags & 0x10U) != 0)
        return 0;
    if ((flags & 0x20U) != 0)
        return word;
    const auto thousands = (word >> 3U) / 125U;
    auto remainder = static_cast<std::uint32_t>(word) - thousands * 1000U;
    const auto hundreds = (remainder >> 2U) / 25U;
    remainder -= hundreds * 100U;
    const auto tens = remainder / 10U;
    return (thousands << 12U) | ((hundreds * 5243U >> 9U) & 0xff00U) |
           ((tens * 205U >> 7U) & 0xf0U) | (remainder - tens * 10U);
}

bool k42_legacy_otp_encrypted(std::span<const std::byte> bytes) {
    if (bytes.size() < K42PatchHeader::serialized_size) {
        throw std::runtime_error("truncated BPatchHeaderV42");
    }
    const auto raw_magic = u32le(bytes, 0);
    const auto valid_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    const bool swapped =
            !valid_magic(raw_magic) && valid_magic(byteswap32(raw_magic));
    if (!valid_magic(raw_magic) && !swapped) {
        throw std::runtime_error("unsupported BPatchHeaderV42 magic");
    }
    auto flags = u32le(bytes, 0x9e);
    if (swapped)
        flags = byteswap32(flags);
    return (flags & 4U) != 0;
}

struct K2MonolithResolution {
    K2MonolithInfo info;
    std::size_t patch_offset{};
};

std::optional<K2MonolithResolution> resolve_k2_monolith(
        std::span<const std::byte> bytes) {
    constexpr auto root_offset = K2PatchHeader::serialized_size;
    if (bytes.size() < root_offset + K2MonolithTable::table_header_size)
        return std::nullopt;

    const auto endian_u16 = [&](std::size_t offset, bool swapped) {
        auto value = u16le(bytes, offset);
        return swapped ? static_cast<std::uint16_t>(
                                 (value >> 8U) | (value << 8U))
                       : value;
    };
    const auto endian_u32 = [&](std::size_t offset, bool swapped) {
        const auto value = u32le(bytes, offset);
        return swapped ? byteswap32(value) : value;
    };
    const auto table_magic_at = [&](std::size_t offset) {
        if (offset > bytes.size() - 4)
            return false;
        const auto magic = u32le(bytes, offset);
        return magic == K2MonolithTable::table_magic ||
               byteswap32(magic) == K2MonolithTable::table_magic;
    };
    if (!table_magic_at(root_offset))
        return std::nullopt;

    K2MonolithResolution resolution;
    std::vector<std::pair<std::size_t, std::size_t>> patch_candidates;
    std::vector<std::size_t> pending{ root_offset };
    std::vector<std::size_t> visited;
    while (!pending.empty()) {
        const auto table_offset = pending.back();
        pending.pop_back();
        if (std::find(visited.begin(), visited.end(), table_offset) !=
                visited.end()) {
            continue;
        }
        visited.push_back(table_offset);
        if (visited.size() > 4096 ||
                table_offset >
                        bytes.size() - K2MonolithTable::table_header_size ||
                !table_magic_at(table_offset)) {
            throw std::runtime_error("invalid K2 monolith table link");
        }

        K2MonolithTable table;
        table.offset = static_cast<std::uint32_t>(table_offset);
        table.byte_swapped =
                u32le(bytes, table_offset) != K2MonolithTable::table_magic;
        table.version = endian_u16(table_offset + 4, table.byte_swapped);
        if (table.version >= 0x0112U) {
            throw std::runtime_error("unsupported K2 monolith table version");
        }
        table.writer_argument =
                endian_u32(table_offset + 0x06, table.byte_swapped);
        table.transform_mode =
                endian_u32(table_offset + 0x0a, table.byte_swapped);
        table.entry_count = endian_u32(table_offset + 0x0e, table.byte_swapped);
        table.table_identifier =
                endian_u32(table_offset + 0x12, table.byte_swapped);
        if (table.entry_count > (1U << 20)) {
            throw std::runtime_error("invalid K2 monolith entry count");
        }
        auto cursor = table_offset + K2MonolithTable::table_header_size;
        table.entries.reserve(table.entry_count);
        for (std::uint32_t index = 0; index < table.entry_count; ++index) {
            K2MonolithEntry entry;
            if (table.version == 0x0100U) {
                constexpr std::size_t fixed_size = 0x87;
                if (cursor > bytes.size() ||
                        fixed_size > bytes.size() - cursor) {
                    throw std::runtime_error(
                            "truncated fixed K2 monolith entry");
                }
                entry.serialized_size = fixed_size;
                entry.stored_offset =
                        endian_u32(cursor + 0x81, table.byte_swapped);
                entry.type = endian_u16(cursor + 0x85, table.byte_swapped);
                std::size_t name_size = 0;
                while (name_size < 0x81 &&
                        bytes[cursor + name_size] != std::byte{ 0 }) {
                    entry.name.push_back(static_cast<char16_t>(
                            std::to_integer<unsigned char>(
                                    bytes[cursor + name_size])));
                    ++name_size;
                }
                if (name_size == 0x81) {
                    throw std::runtime_error(
                            "unterminated fixed K2 monolith entry name");
                }
                cursor += fixed_size;
            } else {
                if (cursor > bytes.size() || 8 > bytes.size() - cursor) {
                    throw std::runtime_error(
                            "truncated K2 monolith entry prefix");
                }
                entry.serialized_size = endian_u16(cursor, table.byte_swapped);
                if (entry.serialized_size < 10 ||
                        (entry.serialized_size & 1U) != 0 ||
                        entry.serialized_size > bytes.size() - cursor) {
                    throw std::runtime_error("invalid K2 monolith entry size");
                }
                entry.stored_offset =
                        endian_u32(cursor + 2, table.byte_swapped);
                entry.type = endian_u16(cursor + 6, table.byte_swapped);
                bool terminated = false;
                for (std::size_t name_offset = 8;
                        name_offset + 1 < entry.serialized_size;
                        name_offset += 2) {
                    const auto character = endian_u16(
                            cursor + name_offset, table.byte_swapped);
                    if (character == 0) {
                        terminated = true;
                        break;
                    }
                    entry.name.push_back(static_cast<char16_t>(character));
                }
                if (!terminated) {
                    throw std::runtime_error(
                            "unterminated K2 monolith entry name");
                }
                cursor += entry.serialized_size;
            }
            entry.resolved_offset = entry.type == 2U
                                            ? entry.stored_offset ^ 0x1f4e0c8dU
                                            : entry.stored_offset;
            table.entries.push_back(std::move(entry));
        }

        const auto table_index = resolution.info.tables.size();
        resolution.info.tables.push_back(std::move(table));
        const auto &stored_table = resolution.info.tables.back();
        for (std::size_t entry_index = 0;
                entry_index < stored_table.entries.size(); ++entry_index) {
            const auto &entry = stored_table.entries[entry_index];
            if (entry.type == 1U) {
                pending.push_back(entry.resolved_offset);
            } else {
                patch_candidates.emplace_back(table_index, entry_index);
            }
        }
    }

    std::optional<std::pair<std::size_t, std::size_t>> selected;
    bool selected_swapped = false;
    for (const auto candidate : patch_candidates) {
        const auto &entry = resolution.info.tables[candidate.first]
                                    .entries[candidate.second];
        const auto offset = static_cast<std::size_t>(entry.resolved_offset);
        if (offset > bytes.size() - K2MonolithInfo::patch_link_size)
            continue;
        const auto raw_magic = u32le(bytes, offset);
        const bool swapped = raw_magic != K2MonolithInfo::patch_link_magic;
        if (raw_magic != K2MonolithInfo::patch_link_magic &&
                byteswap32(raw_magic) != K2MonolithInfo::patch_link_magic)
            continue;
        const auto version = endian_u16(offset + 4, swapped);
        if (version >= 0x0112U)
            continue;
        const auto patch_offset = offset + K2MonolithInfo::patch_link_size;
        if (patch_offset > bytes.size() - K2PatchHeader::serialized_size)
            continue;
        const auto patch_magic = u32le(bytes, patch_offset);
        const bool valid_patch_magic = patch_magic == 0xab85ef01U ||
                                       patch_magic == 0x10874353U ||
                                       patch_magic == 0x7fa89012U ||
                                       byteswap32(patch_magic) == 0xab85ef01U ||
                                       byteswap32(patch_magic) == 0x10874353U ||
                                       byteswap32(patch_magic) == 0x7fa89012U;
        if (!valid_patch_magic)
            continue;
        if (selected) {
            throw std::runtime_error("ambiguous K2 monolith patch entries");
        }
        selected = candidate;
        selected_swapped = swapped;
        resolution.patch_offset = patch_offset;
    }
    if (!selected)
        throw std::runtime_error("K2 monolith contains no patch entry");

    resolution.info.selected_table_index = selected->first;
    resolution.info.selected_entry_index = selected->second;
    const auto &entry =
            resolution.info.tables[selected->first].entries[selected->second];
    const auto link_offset = static_cast<std::size_t>(entry.resolved_offset);
    resolution.info.patch_link_version =
            endian_u16(link_offset + 4, selected_swapped);
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(link_offset),
            K2MonolithInfo::patch_link_size,
            resolution.info.patch_link_bytes.begin());
    resolution.info.embedded_patch_offset =
            static_cast<std::uint32_t>(resolution.patch_offset);
    return resolution;
}

K2PatchData parse_k2_patch_data(std::span<const std::byte> bytes,
        std::optional<std::uint32_t> current_app_version,
        std::span<const std::byte> encryption_key) {
    if (const auto monolith = resolve_k2_monolith(bytes)) {
        auto out = parse_k2_patch_data(bytes.subspan(monolith->patch_offset),
                current_app_version, encryption_key);
        out.monolith = monolith->info;
        return out;
    }
    if (bytes.size() < K2PatchHeader::serialized_size) {
        throw std::runtime_error("truncated BPatchHeaderV2");
    }
    K2PatchData out;
    std::copy_n(bytes.begin(), K2PatchHeader::serialized_size,
            out.header.normalized_bytes.begin());
    auto header = std::span<std::byte>(out.header.normalized_bytes);
    const auto valid_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    const auto raw_magic = u32le(header, 0);
    if (!valid_magic(raw_magic) && !valid_magic(byteswap32(raw_magic))) {
        throw std::runtime_error("unsupported BPatchHeaderV2 magic");
    }
    out.header.byte_swapped = !valid_magic(raw_magic);
    if (out.header.byte_swapped) {
        auto swap16_at = [&](std::size_t offset) {
            std::swap(header[offset], header[offset + 1]);
        };
        auto swap32_at = [&](std::size_t offset) {
            std::swap(header[offset], header[offset + 3]);
            std::swap(header[offset + 1], header[offset + 2]);
        };
        for (const auto offset : { 0U, 4U, 10U, 16U, 20U, 24U, 38U, 42U, 46U,
                     50U, 54U, 0x9eU, 0xa2U, 0xa6U }) {
            swap32_at(offset);
        }
        for (const auto offset :
                { 8U, 14U, 28U, 30U, 32U, 34U, 36U, 0x9aU, 0x9cU }) {
            swap16_at(offset);
        }
    }
    out.header.magic = u32le(header, 0);
    out.header.embedded_stream_size = u32le(header, 4);
    out.header.compressed_size = static_cast<std::uint32_t>(
            bytes.size() - K2PatchHeader::serialized_size);
    out.header.generation_revision = u16le(header, 8);
    out.header.preset_kind = u16le(header, 0x0e);
    out.header.signature = u32le(header, 0x0a);
    out.header.creator_version = u32le(header, 0x10);
    out.header.required_app_version = u32le(header, 0x2e);
    out.header.legacy_otp_word = u16le(header, 0x9a);
    out.header.library_word = u16le(header, 0x9c);
    out.header.flags = u32le(header, 0x9e);
    out.header.checksum = u32le(header, 0xa2);
    if (out.header.signature != 0x3e012a72U) {
        throw std::runtime_error("BPatchHeaderV2 signature mismatch");
    }
    if (out.header.creator_version < 0x0109091dU) {
        throw std::runtime_error("BPatchHeaderV2 creator version is too old");
    }
    if (out.header.creator_version > 0x0201090bU &&
            calculate_k2_header_checksum(header) != out.header.checksum) {
        throw std::runtime_error("BPatchHeaderV2 checksum mismatch");
    }
    if (current_app_version &&
            *current_app_version < out.header.required_app_version) {
        throw std::runtime_error(
                "BPatchHeaderV2 requires a newer application version");
    }
    if ((out.header.flags & 0x10U) == 0) {
        const auto word = static_cast<std::uint32_t>(out.header.library_word);
        const auto thousands = (out.header.library_word >> 3U) / 125U;
        auto remainder = word - thousands * 1000U;
        const auto hundreds = (remainder >> 2U) / 25U;
        remainder -= hundreds * 100U;
        const auto tens = remainder / 10U;
        out.header.library_id =
                (thousands << 12U) | ((hundreds * 5243U >> 9U) & 0xff00U) |
                ((tens * 205U >> 7U) & 0xf0U) | (remainder - tens * 10U);
    }
    out.header.product_snpid = snpid_from_product_id(out.header.library_id);
    if (bytes.size() == K2PatchHeader::serialized_size) {
        throw std::runtime_error("truncated or empty K2 compressed payload");
    }
    const auto stored = bytes.subspan(K2PatchHeader::serialized_size);
    std::vector<std::byte> transformed;
    std::span<const std::byte> compressed = stored;
    if (out.header.legacy_otp_encrypted()) {
        if (encryption_key.size() != (1U << 16)) {
            throw std::invalid_argument(
                    "K2 encrypted payload requires a 65536-byte product key");
        }
        const auto first_word = u16le(encryption_key, 0);
        const auto marker = static_cast<std::uint16_t>(
                (first_word >> 8U) | (first_word << 8U));
        if (out.header.legacy_otp_word != marker) {
            throw std::runtime_error("K2 product key marker mismatch");
        }
        transformed.assign(stored.begin(), stored.end());
        apply_encryption_item_xor(transformed, encryption_key);
        compressed = transformed;
    }

    z_stream stream{};
    stream.next_in = reinterpret_cast<Bytef *>(
            const_cast<std::byte *>(compressed.data()));
    stream.avail_in = static_cast<uInt>(compressed.size());
    if (inflateInit(&stream) != Z_OK) {
        throw std::runtime_error("cannot initialize K2 zlib stream");
    }
    std::array<std::byte, 65536> block{};
    int status = Z_OK;
    while (status == Z_OK) {
        stream.next_out = reinterpret_cast<Bytef *>(block.data());
        stream.avail_out = static_cast<uInt>(block.size());
        status = inflate(&stream, Z_NO_FLUSH);
        const auto produced = block.size() - stream.avail_out;
        out.decompressed.insert(out.decompressed.end(), block.begin(),
                block.begin() + static_cast<std::ptrdiff_t>(produced));
    }
    inflateEnd(&stream);
    if (status != Z_STREAM_END || stream.avail_in != 0) {
        throw std::runtime_error("invalid or trailing K2 zlib payload");
    }
    parse_k2_tag_stream(out);
    return out;
}

std::uint32_t k2_product_id(std::span<const std::byte> bytes) {
    if (bytes.size() < K2PatchHeader::serialized_size) {
        throw std::runtime_error("truncated BPatchHeaderV2");
    }
    const auto raw_magic = u32le(bytes, 0);
    const auto valid_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    const bool swapped =
            !valid_magic(raw_magic) && valid_magic(byteswap32(raw_magic));
    if (!valid_magic(raw_magic) && !swapped) {
        throw std::runtime_error("unsupported BPatchHeaderV2 magic");
    }
    auto word = u16le(bytes, 0x9c);
    auto flags = u32le(bytes, 0x9e);
    if (swapped) {
        word = static_cast<std::uint16_t>((word >> 8U) | (word << 8U));
        flags = byteswap32(flags);
    }
    if ((flags & 0x10U) != 0)
        return 0;
    const auto thousands = (word >> 3U) / 125U;
    auto remainder = static_cast<std::uint32_t>(word) - thousands * 1000U;
    const auto hundreds = (remainder >> 2U) / 25U;
    remainder -= hundreds * 100U;
    const auto tens = remainder / 10U;
    return (thousands << 12U) | ((hundreds * 5243U >> 9U) & 0xff00U) |
           ((tens * 205U >> 7U) & 0xf0U) | (remainder - tens * 10U);
}

bool k2_legacy_otp_encrypted(std::span<const std::byte> bytes) {
    if (bytes.size() < K2PatchHeader::serialized_size) {
        throw std::runtime_error("truncated BPatchHeaderV2");
    }
    const auto raw_magic = u32le(bytes, 0);
    const auto valid_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    const bool swapped =
            !valid_magic(raw_magic) && valid_magic(byteswap32(raw_magic));
    if (!valid_magic(raw_magic) && !swapped) {
        throw std::runtime_error("unsupported BPatchHeaderV2 magic");
    }
    auto flags = u32le(bytes, 0x9e);
    if (swapped)
        flags = byteswap32(flags);
    return (flags & 4U) != 0;
}

std::uint32_t calculate_k2_header_checksum(
        std::span<const std::byte> normalized_header) {
    if (normalized_header.size() != K2PatchHeader::serialized_size) {
        throw std::invalid_argument("BPatchHeaderV2 must be exactly 170 bytes");
    }
    std::array<std::byte, K2PatchHeader::serialized_size> bytes{};
    std::copy(
            normalized_header.begin(), normalized_header.end(), bytes.begin());
    std::fill(bytes.begin() + 0xa2, bytes.begin() + 0xa6, std::byte{ 0 });
    auto span = std::span<std::byte>(bytes);
    auto swap16_at = [&](std::size_t offset) {
        std::swap(span[offset], span[offset + 1]);
    };
    auto swap32_at = [&](std::size_t offset) {
        std::swap(span[offset], span[offset + 3]);
        std::swap(span[offset + 1], span[offset + 2]);
    };
    for (const auto offset : { 0U, 4U, 10U, 16U, 20U, 24U, 38U, 42U, 46U, 50U,
                 54U, 0x9eU, 0xa2U, 0xa6U }) {
        swap32_at(offset);
    }
    for (const auto offset :
            { 8U, 14U, 28U, 30U, 32U, 34U, 36U, 0x9aU, 0x9cU }) {
        swap16_at(offset);
    }
    std::uint32_t checksum = 0;
    for (std::uint32_t index = 0; index < bytes.size(); ++index) {
        auto rotation = index + 9U;
        const auto estimate = ((rotation & 0xffU) * 0x25U) >> 8U;
        rotation -=
                ((estimate + (((rotation - estimate) & 0xfeU) >> 1U)) >> 2U) *
                7U;
        const auto next_rotation =
                (index + 1U) - (((index + 1U) & 0xffU) / 18U) * 18U;
        const auto quotient = ((rotation + index) & 0xffU) / 17U;
        auto value = static_cast<std::uint32_t>(u8(span, index));
        const auto index_rotation = index - ((index & 0xffU) / 13U) * 13U;
        checksum += value << (index_rotation & 31U);
        if (index == bytes.size() - 1U) {
            checksum += value << (rotation & 31U);
            checksum += value << (next_rotation & 31U);
        } else {
            value = static_cast<std::uint32_t>(u8(span, index + 1U));
            checksum += value << (rotation & 31U);
            if (index > bytes.size() - 3U) {
                checksum += value << (next_rotation & 31U);
            }
            if (index <= bytes.size() - 3U) {
                value = static_cast<std::uint32_t>(u8(span, index + 2U));
                checksum += value << (next_rotation & 31U);
                if (index != bytes.size() - 3U) {
                    value = static_cast<std::uint32_t>(u8(span, index + 3U));
                }
            }
        }
        checksum +=
                value << (((rotation + index) - (quotient | (quotient << 4U))) &
                          31U);
    }
    return checksum;
}

std::vector<ChunkHeader> scan_chunk_sequence(
        std::span<const std::byte> bytes, std::size_t offset) {
    if (offset > bytes.size())
        throw std::invalid_argument("chunk sequence offset is out of bounds");
    std::vector<ChunkHeader> chunks;
    auto pos = offset;
    while (pos < bytes.size()) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error("truncated CHUNKED header");
        ChunkHeader chunk;
        chunk.offset = pos;
        chunk.type = u16le(bytes, pos);
        chunk.payload_size = u32le(bytes, pos + 2);
        chunk.payload_offset = pos + 6;
        if (chunk.payload_size > bytes.size() - chunk.payload_offset) {
            throw std::runtime_error("CHUNKED payload size is out of bounds");
        }
        chunks.push_back(chunk);
        pos = chunk.payload_offset + chunk.payload_size;
    }
    return chunks;
}

namespace {

SerializedFileName read_file_table_filename(
        std::span<const std::byte> bytes, std::size_t &pos, std::size_t end) {
    if (!has(bytes, pos, 4) || pos + 4 > end)
        throw std::runtime_error("truncated BFileName");
    const auto signed_count = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    SerializedFileName name;
    if (signed_count < 0) {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            throw std::runtime_error("truncated legacy BFileName");
        const auto length = u32le(bytes, pos);
        pos += 4;
        if (length > end - pos)
            throw std::runtime_error(
                    "legacy BFileName length is out of bounds");
        name.discarded_legacy_path = std::string(
                reinterpret_cast<const char *>(bytes.data() + pos), length);
        pos += length;
        return name;
    }
    if (static_cast<std::uint32_t>(signed_count) > end - pos) {
        throw std::runtime_error("BFileName segment count is out of bounds");
    }
    name.segments.reserve(static_cast<std::size_t>(signed_count));
    for (std::int32_t i = 0; i < signed_count; ++i) {
        if (!has(bytes, pos, 1) || pos + 1 > end)
            throw std::runtime_error("truncated BFileName segment");
        FileNameSegment segment;
        segment.serialized_kind = static_cast<std::int8_t>(u8(bytes, pos++));
        segment.kind = segment.serialized_kind;
        const auto kind = static_cast<unsigned>(
                static_cast<std::uint8_t>(segment.serialized_kind));
        if (kind < 11 && ((1U << kind) & 0x316U) != 0) {
            segment.payload_kind = FileNameSegmentPayloadKind::text;
            Document errors;
            auto value = read_wstring(bytes, pos, end, errors);
            if (!value)
                throw std::runtime_error("invalid BFileName segment string");
            segment.text = std::move(*value);
        } else if (kind == 5) {
            if (!has(bytes, pos, 2) || pos + 2 > end)
                throw std::runtime_error(
                        "truncated legacy BFileName segment value");
            segment.payload_kind =
                    FileNameSegmentPayloadKind::legacy_decimal_u16;
            segment.kind = 10;
            segment.value = static_cast<std::int16_t>(
                    legacy_decimal_to_packed_bcd(u16le(bytes, pos)));
            pos += 2;
        } else if (kind == 10) {
            if (!has(bytes, pos, 2) || pos + 2 > end)
                throw std::runtime_error("truncated BFileName segment value");
            segment.payload_kind = FileNameSegmentPayloadKind::signed_s16;
            segment.value = static_cast<std::int16_t>(u16le(bytes, pos));
            pos += 2;
        }
        name.segments.push_back(std::move(segment));
    }
    return name;
}

} // namespace

FileTable parse_file_table_v3(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x4b)
        throw std::invalid_argument("file table chunk type must be 0x4b");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("file table chunk is out of bounds");
    }
    const auto end = chunk.payload_offset + chunk.payload_size;
    std::size_t pos = chunk.payload_offset;
    if (!has(bytes, pos, 6))
        throw std::runtime_error("truncated file table header");
    FileTable table;
    table.chunk_type = chunk.type;
    table.version = u16le(bytes, pos);
    pos += 2;
    if (table.version != 3)
        throw std::invalid_argument("file table is not version 3");
    table.sample_filename_base = 0;
    table.special_filename_base = 0;
    const auto count = u32le(bytes, pos);
    pos += 4;
    if (count > (end - pos) / 24U)
        throw std::runtime_error("file table count is out of bounds");
    table.files.reserve(count);

    for (std::uint32_t i = 0; i < count; ++i) {
        if (!has(bytes, pos, 8) || pos + 8 > end)
            throw std::runtime_error("truncated content-file record");
        ContentFileInfo info;
        info.field_00 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        info.field_04 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        info.selected_path = read_file_table_filename(bytes, pos, end);
        info.secondary_path = read_file_table_filename(bytes, pos, end);
        if (!has(bytes, pos, 16) || pos + 16 > end)
            throw std::runtime_error("truncated content-file trailer");
        info.timestamp = u64le(bytes, pos);
        pos += 8;
        info.field_250 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        info.field_254 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        table.files.push_back(std::move(info));
    }
    if (pos != end)
        throw std::runtime_error("file table payload has trailing bytes");
    return table;
}

FileTable parse_file_table_v2(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x4b)
        throw std::invalid_argument("file table chunk type must be 0x4b");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("file table chunk is out of bounds");
    }
    const auto end = chunk.payload_offset + chunk.payload_size;
    std::size_t pos = chunk.payload_offset;
    if (!has(bytes, pos, 2) || pos + 2 > end)
        throw std::runtime_error("truncated file table header");
    FileTable table;
    table.chunk_type = chunk.type;
    table.version = u16le(bytes, pos);
    pos += 2;
    if (table.version != 2)
        throw std::invalid_argument("file table is not version 2");

    auto read_count = [&]() -> std::uint32_t {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            throw std::runtime_error("truncated version-2 file-table count");
        const auto value = u32le(bytes, pos);
        pos += 4;
        if (value > end - pos)
            throw std::runtime_error(
                    "version-2 file-table count is out of bounds");
        return value;
    };

    const auto path_only_count = read_count();
    table.sample_filename_base = path_only_count;
    table.files.resize(path_only_count);
    for (std::uint32_t i = 0; i < path_only_count; ++i) {
        table.files[i].selected_path =
                read_file_table_filename(bytes, pos, end);
    }

    const auto timestamp_count = read_count();
    const auto timestamp_begin = table.files.size();
    if (timestamp_count >
            std::numeric_limits<std::size_t>::max() - timestamp_begin) {
        throw std::runtime_error("version-2 file-table size overflows");
    }
    table.files.resize(timestamp_begin + timestamp_count);
    table.special_filename_base =
            static_cast<std::uint32_t>(table.files.size());
    for (std::size_t i = timestamp_begin; i < table.files.size(); ++i) {
        table.files[i].selected_path =
                read_file_table_filename(bytes, pos, end);
    }
    for (std::size_t i = timestamp_begin; i < table.files.size(); ++i) {
        if (!has(bytes, pos, 8) || pos + 8 > end)
            throw std::runtime_error("truncated version-2 timestamp run");
        table.files[i].timestamp = u64le(bytes, pos);
        pos += 8;
    }
    for (std::size_t i = timestamp_begin; i < table.files.size(); ++i) {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            throw std::runtime_error("truncated version-2 field_250 run");
        table.files[i].field_250 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }

    const auto short_count = read_count();
    const auto short_begin = table.files.size();
    if (short_count > std::numeric_limits<std::size_t>::max() - short_begin) {
        throw std::runtime_error("version-2 file-table size overflows");
    }
    table.files.resize(short_begin + short_count);
    for (std::size_t i = short_begin; i < table.files.size(); ++i) {
        table.files[i].selected_path =
                read_file_table_filename(bytes, pos, end);
    }
    for (std::size_t i = short_begin; i < table.files.size(); ++i) {
        if (!has(bytes, pos, 2) || pos + 2 > end)
            throw std::runtime_error("truncated version-2 field_254 run");
        table.files[i].field_254 = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
    }
    if (pos != end)
        throw std::runtime_error(
                "version-2 file table payload has trailing bytes");
    return table;
}

FileTable parse_file_table_pre_k51(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x3d)
        throw std::invalid_argument(
                "pre-K5.1 file table chunk type must be 0x3d");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument(
                "pre-K5.1 file table chunk is out of bounds");
    }
    const auto end = chunk.payload_offset + chunk.payload_size;
    std::size_t pos = chunk.payload_offset;
    FileTable table;
    table.chunk_type = chunk.type;
    table.version = 0;

    auto read_count = [&]() -> std::uint32_t {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            throw std::runtime_error("truncated pre-K5.1 file-table count");
        const auto value = u32le(bytes, pos);
        pos += 4;
        if (value > end - pos)
            throw std::runtime_error(
                    "pre-K5.1 file-table count is out of bounds");
        return value;
    };
    auto append_paths = [&](std::uint32_t count) -> std::size_t {
        const auto begin = table.files.size();
        if (count > std::numeric_limits<std::size_t>::max() - begin) {
            throw std::runtime_error("pre-K5.1 file-table size overflows");
        }
        table.files.resize(begin + count);
        for (std::size_t i = begin; i < table.files.size(); ++i) {
            table.files[i].selected_path =
                    read_file_table_filename(bytes, pos, end);
        }
        return begin;
    };

    const auto path_only_count = read_count();
    (void)append_paths(path_only_count);
    // like v2, samples start after the path-only run and special filenames
    // start after the timestamped sample run
    table.sample_filename_base = path_only_count;
    const auto timestamp_begin = append_paths(read_count());
    for (std::size_t i = timestamp_begin; i < table.files.size(); ++i) {
        if (!has(bytes, pos, 8) || pos + 8 > end)
            throw std::runtime_error("truncated pre-K5.1 timestamp run");
        table.files[i].timestamp = u64le(bytes, pos);
        pos += 8;
    }
    const auto field_begin = append_paths(read_count());
    table.special_filename_base = static_cast<std::uint32_t>(field_begin);
    for (std::size_t i = field_begin; i < table.files.size(); ++i) {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            throw std::runtime_error("truncated pre-K5.1 field_254 run");
        table.files[i].field_254 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    if (pos != end)
        throw std::runtime_error(
                "pre-K5.1 file table payload has trailing bytes");
    return table;
}

} // namespace libnki
