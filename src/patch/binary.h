// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include "../binary/read.h"
#include "libnki/nki.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace libnki::detail::patch {
using namespace binary;

inline constexpr std::size_t kCommonHeaderSize = 0x28;
inline constexpr std::size_t kOpaqueProbePrefixSize = 0x30;
inline constexpr std::size_t kMetadataScanLimit = 1U << 20;
inline constexpr std::size_t kMaxDepth = 128;
inline constexpr std::size_t kMaxFrames = 1U << 20;

inline bool domain_tag(std::span<const std::byte> bytes, std::size_t off) {
    return tag_is(bytes, off, "DSIN") || tag_is(bytes, off, "4KIN") ||
           tag_is(bytes, off, "NISD");
}

inline std::string hex(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        const auto v = std::to_integer<unsigned>(b);
        out.push_back(digits[v >> 4U]);
        out.push_back(digits[v & 0x0fU]);
    }
    return out;
}

inline std::string utf8_from_codepoint(std::uint32_t cp) {
    std::string out;
    if (cp <= 0x7f)
        out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
    return out;
}

inline std::optional<std::string> pascal_utf16(
        std::span<const std::byte> bytes, std::size_t off, std::size_t limit) {
    if (!has(bytes, off, 4))
        return std::nullopt;
    const auto count = u32le(bytes, off);
    if (count < 2 || count > 256 ||
            count > (limit - std::min(limit, off + 4)) / 2) {
        return std::nullopt;
    }
    const auto end = off + 4 + static_cast<std::size_t>(count) * 2;
    if (end > limit || end > bytes.size())
        return std::nullopt;
    std::string out;
    std::size_t printable_ascii = 0;
    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t cp =
                u8(bytes, off + 4 + i * 2) |
                (static_cast<std::uint32_t>(u8(bytes, off + 5 + i * 2)) << 8U);
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < count) {
            const std::uint32_t lo =
                    u8(bytes, off + 6 + i * 2) |
                    (static_cast<std::uint32_t>(u8(bytes, off + 7 + i * 2))
                            << 8U);
            if (lo >= 0xdc00 && lo <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10U) + (lo - 0xdc00);
                ++i;
            }
        }
        if (cp >= 0x20 && cp <= 0x7e)
            ++printable_ascii;
        if (cp == 0 || cp > 0x10ffff)
            return std::nullopt;
        out += utf8_from_codepoint(cp);
    }
    if (printable_ascii * 10 < count * 7)
        return std::nullopt;
    return out;
}

inline std::optional<std::string> read_wstring(std::span<const std::byte> bytes,
        std::size_t &pos, std::size_t limit, Document &doc) {
    if (!has(bytes, pos, 4) || pos + 4 > limit) {
        doc.errors.push_back({ pos, "truncated wide-string length" });
        return std::nullopt;
    }
    const auto count = static_cast<std::size_t>(u32le(bytes, pos));
    pos += 4;
    if (count > (limit - pos) / 2) {
        doc.errors.push_back(
                { pos - 4, "wide-string length is out of bounds" });
        return std::nullopt;
    }
    const auto end = pos + count * 2;
    std::string out;
    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t cp = u16le(bytes, pos + i * 2);
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 >= count) {
                doc.errors.push_back(
                        { pos + i * 2, "truncated UTF-16 surrogate pair" });
                return std::nullopt;
            }
            const auto lo =
                    static_cast<std::uint32_t>(u16le(bytes, pos + (i + 1) * 2));
            if (lo < 0xdc00 || lo > 0xdfff) {
                doc.errors.push_back(
                        { pos + i * 2, "invalid UTF-16 surrogate pair" });
                return std::nullopt;
            }
            cp = 0x10000 + ((cp - 0xd800) << 10U) + (lo - 0xdc00);
            ++i;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) {
            doc.errors.push_back(
                    { pos + i * 2, "unexpected UTF-16 low surrogate" });
            return std::nullopt;
        }
        out += utf8_from_codepoint(cp);
    }
    pos = end;
    return out;
}

inline std::optional<std::string> read_bstring(std::span<const std::byte> bytes,
        std::size_t &pos, std::size_t limit, const char *field_name) {
    if (!has(bytes, pos, 4) || pos + 4 > limit) {
        throw std::runtime_error(
                std::string("truncated ") + field_name + " length");
    }
    const auto signed_length = static_cast<std::int32_t>(u32le(bytes, pos));
    const auto length_offset = pos;
    pos += 4;
    if (signed_length < 0)
        return std::nullopt;
    const auto length = static_cast<std::size_t>(signed_length);
    if (length > limit - pos) {
        std::string nearby;
        static constexpr char digits[] = "0123456789abcdef";
        const auto begin = length_offset > 12 ? length_offset - 12 : 0;
        const auto finish = std::min(bytes.size(), length_offset + 16);
        for (auto i = begin; i < finish; ++i) {
            const auto value = u8(bytes, i);
            nearby.push_back(digits[value >> 4]);
            nearby.push_back(digits[value & 0x0f]);
        }
        throw std::runtime_error(std::string(field_name) + " length " +
                                 std::to_string(length) + " at offset " +
                                 std::to_string(length_offset) +
                                 " is out of bounds (near " + nearby + ")");
    }
    std::string out(reinterpret_cast<const char *>(bytes.data() + pos), length);
    pos += length;
    return out;
}

inline std::string read_utf16_string(std::span<const std::byte> bytes,
        std::size_t &pos, std::size_t limit, const char *field_name) {
    if (!has(bytes, pos, 4) || pos + 4 > limit) {
        throw std::runtime_error(
                std::string("truncated ") + field_name + " length");
    }
    const auto count = static_cast<std::size_t>(u32le(bytes, pos));
    pos += 4;
    if (count > (limit - pos) / 2) {
        throw std::runtime_error(
                std::string(field_name) + " length is out of bounds");
    }
    std::string out;
    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t cp = u16le(bytes, pos + i * 2);
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 >= count) {
                throw std::runtime_error(
                        std::string("truncated ") + field_name + " surrogate");
            }
            const auto low =
                    static_cast<std::uint32_t>(u16le(bytes, pos + (i + 1) * 2));
            if (low < 0xdc00 || low > 0xdfff) {
                throw std::runtime_error(
                        std::string("invalid ") + field_name + " surrogate");
            }
            cp = 0x10000 + ((cp - 0xd800) << 10U) + (low - 0xdc00);
            ++i;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) {
            throw std::runtime_error(
                    std::string("unexpected ") + field_name + " low surrogate");
        }
        out += utf8_from_codepoint(cp);
    }
    pos += count * 2;
    return out;
}

} // namespace libnki::detail::patch
