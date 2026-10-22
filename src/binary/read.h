// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace libnki::detail::binary {

inline std::uint8_t u8(std::span<const std::byte> bytes, std::size_t off) {
    return std::to_integer<std::uint8_t>(bytes[off]);
}

inline std::uint32_t u32le(std::span<const std::byte> bytes, std::size_t off) {
    return static_cast<std::uint32_t>(u8(bytes, off)) |
           (static_cast<std::uint32_t>(u8(bytes, off + 1)) << 8U) |
           (static_cast<std::uint32_t>(u8(bytes, off + 2)) << 16U) |
           (static_cast<std::uint32_t>(u8(bytes, off + 3)) << 24U);
}

inline std::uint16_t u16le(std::span<const std::byte> bytes, std::size_t off) {
    return static_cast<std::uint16_t>(u8(bytes, off)) |
           static_cast<std::uint16_t>(u8(bytes, off + 1) << 8U);
}

inline std::uint32_t byteswap32(std::uint32_t value) {
    return ((value & 0x000000ffU) << 24U) | ((value & 0x0000ff00U) << 8U) |
           ((value & 0x00ff0000U) >> 8U) | ((value & 0xff000000U) >> 24U);
}

inline std::uint64_t u64le(std::span<const std::byte> bytes, std::size_t off) {
    return static_cast<std::uint64_t>(u32le(bytes, off)) |
           (static_cast<std::uint64_t>(u32le(bytes, off + 4)) << 32U);
}

inline bool has(
        std::span<const std::byte> bytes, std::size_t off, std::size_t count) {
    return off <= bytes.size() && count <= bytes.size() - off;
}

inline bool tag_is(
        std::span<const std::byte> bytes, std::size_t off, const char *tag) {
    return has(bytes, off, 4) &&
           u8(bytes, off) == static_cast<unsigned char>(tag[0]) &&
           u8(bytes, off + 1) == static_cast<unsigned char>(tag[1]) &&
           u8(bytes, off + 2) == static_cast<unsigned char>(tag[2]) &&
           u8(bytes, off + 3) == static_cast<unsigned char>(tag[3]);
}

inline std::uint16_t swap16(std::uint16_t value) {
    return static_cast<std::uint16_t>((value >> 8U) | (value << 8U));
}

inline std::uint32_t swap32(std::uint32_t value) {
    return ((value & 0x000000ffU) << 24U) | ((value & 0x0000ff00U) << 8U) |
           ((value & 0x00ff0000U) >> 8U) | ((value & 0xff000000U) >> 24U);
}

inline std::uint64_t swap64(std::uint64_t value) {
    return (static_cast<std::uint64_t>(
                    swap32(static_cast<std::uint32_t>(value)))
                   << 32U) |
           swap32(static_cast<std::uint32_t>(value >> 32U));
}

} // namespace libnki::detail::binary
