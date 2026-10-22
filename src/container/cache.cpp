// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "libnki/nki.h"

#include <algorithm>
#include <bit>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <utility>

#include "../binary/read.h"
#include "internal.h"

namespace libnki {
using namespace detail::binary;
using namespace detail::container;

NkcCache parse_nkc_cache(std::span<const std::byte> bytes) {
    constexpr std::size_t file_header_size = 0x10;
    constexpr std::size_t node_header_size = 0x18;
    if (bytes.size() < file_header_size) {
        throw std::runtime_error("invalid or truncated NKC header");
    }
    NkcCache out;
    const auto stored_magic = u32le(bytes, 0);
    if (stored_magic != NkcCache::magic &&
            swap32(stored_magic) != NkcCache::magic) {
        throw std::runtime_error("invalid or truncated NKC header");
    }
    out.byte_swapped = stored_magic != NkcCache::magic;
    out.version = u16le(bytes, 4);
    if (out.byte_swapped)
        out.version = swap16(out.version);
    if (out.version != NkcCache::version_0110) {
        throw std::runtime_error("unsupported NKC version");
    }
    std::size_t cursor = file_header_size;
    std::size_t total_nodes = 0;
    auto read_node = [&](auto &&self, std::size_t depth) -> NkcNode {
        if (depth > 4096 || ++total_nodes > (1U << 20)) {
            throw std::runtime_error("NKC hierarchy exceeds safety limit");
        }
        if (cursor > bytes.size() || node_header_size > bytes.size() - cursor) {
            throw std::runtime_error("truncated NKC node header");
        }
        NkcNode node;
        node.parent_table_identifier = u32le(bytes, cursor);
        node.entry_attributes = u32le(bytes, cursor + 4);
        node.entry_type = u16le(bytes, cursor + 8);
        node.child_table_attributes = u32le(bytes, cursor + 0x0c);
        auto child_count = u32le(bytes, cursor + 0x10);
        auto name_units = u32le(bytes, cursor + 0x14);
        if (out.byte_swapped) {
            node.parent_table_identifier = swap32(node.parent_table_identifier);
            node.entry_attributes = swap32(node.entry_attributes);
            node.entry_type = swap16(node.entry_type);
            // the U32 at +0x0c stays in file byte order, even in a swapped
            // cache
            child_count = swap32(child_count);
            name_units = swap32(name_units);
        }
        cursor += node_header_size;
        if (child_count > (1U << 20) || name_units > 0x800U ||
                static_cast<std::size_t>(name_units) * 2U >
                        bytes.size() - cursor) {
            throw std::runtime_error("invalid NKC node count or name length");
        }
        node.name.reserve(name_units);
        for (std::uint32_t i = 0; i < name_units; ++i) {
            auto ch = u16le(bytes, cursor);
            if (out.byte_swapped)
                ch = swap16(ch);
            node.name.push_back(static_cast<char16_t>(ch));
            cursor += 2;
        }
        node.children.reserve(child_count);
        for (std::uint32_t i = 0; i < child_count; ++i) {
            node.children.push_back(self(self, depth + 1));
        }
        return node;
    };
    out.root = read_node(read_node, 0);
    out.end_offset = cursor;
    if (cursor != bytes.size()) {
        throw std::runtime_error("trailing bytes after NKC root node");
    }
    return out;
}

} // namespace libnki
