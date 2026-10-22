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

namespace {

bool monolith_name_equal(std::string_view stored, std::string_view requested) {
    if (stored.size() != requested.size())
        return false;
    for (std::size_t index = 0; index < stored.size(); ++index) {
        const auto left = static_cast<unsigned char>(stored[index]);
        const auto right = static_cast<unsigned char>(requested[index]);
        if (left == right)
            continue;
        // we only fold ASCII here; UTF-8 multibyte sequences must match exactly
        if (left >= 0x80U || right >= 0x80U ||
                std::tolower(left) != std::tolower(right))
            return false;
    }
    return true;
}

} // namespace

MonolithContainer parse_monolith_container(
        std::span<const std::byte> bytes, std::size_t root_offset) {
    if (root_offset > bytes.size() ||
            MonolithTable::table_header_size > bytes.size() - root_offset) {
        throw std::runtime_error("truncated monolith root table");
    }
    auto table_magic_at = [&](std::size_t offset) {
        if (offset > bytes.size() || 4 > bytes.size() - offset)
            return false;
        const auto magic = u32le(bytes, offset);
        return magic == MonolithTable::table_magic ||
               swap32(magic) == MonolithTable::table_magic;
    };
    if (!table_magic_at(root_offset)) {
        throw std::runtime_error("invalid monolith root table magic");
    }

    MonolithContainer out;
    out.root_offset = root_offset;
    std::vector<std::size_t> pending{ root_offset };
    std::vector<std::size_t> visited;
    while (!pending.empty()) {
        const auto table_offset = pending.back();
        pending.pop_back();
        if (std::find(visited.begin(), visited.end(), table_offset) !=
                visited.end())
            continue;
        if (visited.size() >= (1U << 20) || table_offset > bytes.size() ||
                MonolithTable::table_header_size >
                        bytes.size() - table_offset ||
                !table_magic_at(table_offset)) {
            throw std::runtime_error("invalid monolith child-table link");
        }
        visited.push_back(table_offset);

        MonolithTable table;
        table.offset = static_cast<std::uint32_t>(table_offset);
        if (static_cast<std::size_t>(table.offset) != table_offset) {
            throw std::runtime_error(
                    "monolith table offset exceeds U32 format range");
        }
        table.byte_swapped =
                u32le(bytes, table_offset) != MonolithTable::table_magic;
        auto endian_u16 = [&](std::size_t offset) {
            const auto value = u16le(bytes, offset);
            return table.byte_swapped ? swap16(value) : value;
        };
        auto endian_u32 = [&](std::size_t offset) {
            const auto value = u32le(bytes, offset);
            return table.byte_swapped ? swap32(value) : value;
        };
        table.version = endian_u16(table_offset + 4);
        // only 0x0100 has fixed narrow names; the other accepted versions use
        // variable UTF-16 records, even when they're older than 0x0100
        if (table.version >= 0x0112U) {
            throw std::runtime_error("unsupported monolith table version");
        }
        table.writer_argument = endian_u32(table_offset + 0x06);
        table.transform_mode = endian_u32(table_offset + 0x0a);
        table.entry_count = endian_u32(table_offset + 0x0e);
        table.table_identifier = endian_u32(table_offset + 0x12);
        if (table.entry_count > (1U << 20)) {
            throw std::runtime_error(
                    "monolith entry count exceeds safety limit");
        }
        auto cursor = table_offset + MonolithTable::table_header_size;
        table.entries.reserve(table.entry_count);
        for (std::uint32_t index = 0; index < table.entry_count; ++index) {
            MonolithEntry entry;
            if (table.version == 0x0100U) {
                constexpr std::size_t fixed_size = 0x87;
                if (cursor > bytes.size() ||
                        fixed_size > bytes.size() - cursor) {
                    throw std::runtime_error("truncated fixed monolith entry");
                }
                entry.serialized_size = fixed_size;
                entry.stored_offset = endian_u32(cursor + 0x81);
                entry.type = endian_u16(cursor + 0x85);
                std::size_t name_size = 0;
                while (name_size < 0x81 &&
                        bytes[cursor + name_size] != std::byte{ 0 }) {
                    entry.name.push_back(static_cast<char16_t>(
                            u8(bytes, cursor + name_size)));
                    ++name_size;
                }
                if (name_size == 0x81) {
                    throw std::runtime_error(
                            "unterminated fixed monolith entry name");
                }
                cursor += fixed_size;
            } else {
                if (cursor > bytes.size() || 8 > bytes.size() - cursor) {
                    throw std::runtime_error(
                            "truncated variable monolith entry prefix");
                }
                entry.serialized_size = endian_u16(cursor);
                if (entry.serialized_size < 10 ||
                        (entry.serialized_size & 1U) != 0 ||
                        entry.serialized_size > bytes.size() - cursor) {
                    throw std::runtime_error(
                            "invalid variable monolith entry size");
                }
                entry.stored_offset = endian_u32(cursor + 2);
                entry.type = endian_u16(cursor + 6);
                bool terminated = false;
                for (std::size_t name_offset = 8;
                        name_offset + 1 < entry.serialized_size;
                        name_offset += 2) {
                    const auto character = endian_u16(cursor + name_offset);
                    if (character == 0) {
                        terminated = true;
                        break;
                    }
                    entry.name.push_back(static_cast<char16_t>(character));
                }
                if (!terminated) {
                    throw std::runtime_error(
                            "unterminated variable monolith entry name");
                }
                cursor += entry.serialized_size;
            }
            entry.resolved_offset = entry.type == 2U
                                            ? entry.stored_offset ^ 0x1f4e0c8dU
                                            : entry.stored_offset;
            if (entry.resolved_offset > bytes.size()) {
                throw std::runtime_error(
                        "monolith entry offset is out of bounds: table=" +
                        std::to_string(table_offset) +
                        " entry=" + std::to_string(index) +
                        " type=" + std::to_string(entry.type) +
                        " stored=" + std::to_string(entry.stored_offset) +
                        " resolved=" + std::to_string(entry.resolved_offset) +
                        " file_size=" + std::to_string(bytes.size()));
            }
            entry.points_to_eof = entry.resolved_offset == bytes.size();
            if (entry.type == 1U && entry.points_to_eof) {
                throw std::runtime_error("monolith child table points to EOF");
            }
            if (entry.type == 1U)
                pending.push_back(entry.resolved_offset);
            if (!entry.points_to_eof && entry.type >= 2U && entry.type <= 4U) {
                const auto payload_offset =
                        static_cast<std::size_t>(entry.resolved_offset);
                const std::size_t header_size = entry.type == 2U   ? 0x1fU
                                                : entry.type == 3U ? 0x1bU
                                                                   : 0x16U;
                if (header_size > bytes.size() - payload_offset) {
                    throw std::runtime_error(
                            "truncated monolith item payload header");
                }
                MonolithEntry::PayloadHeader payload;
                payload.kind =
                        entry.type == 2U
                                ? MonolithEntry::PayloadHeader::Kind::sample
                        : entry.type == 3U
                                ? MonolithEntry::PayloadHeader::Kind::patch
                                : MonolithEntry::PayloadHeader::Kind::generic;
                payload.offset = entry.resolved_offset;
                payload.magic = endian_u32(payload_offset);
                payload.version = endian_u16(payload_offset + 4);
                const auto expected_magic = entry.type == 2U   ? 0x16ccf80aU
                                            : entry.type == 3U ? 0x4916e63cU
                                                               : 0x2ae905faU;
                // all three payload kinds use this layout below 0x0112
                if (payload.magic == expected_magic &&
                        payload.version < 0x0112U) {
                    payload.writer_argument = endian_u32(payload_offset + 6);
                    payload.transform_mode = endian_u32(payload_offset + 0x0a);
                    if (entry.type == 4U) {
                        payload.source_size = endian_u32(payload_offset + 0x0e);
                        payload.reserved_trailer =
                                endian_u32(payload_offset + 0x12);
                    } else {
                        payload.item_attributes =
                                endian_u32(payload_offset + 0x0e);
                        payload.reserved_marker =
                                u8(bytes, payload_offset + 0x12);
                        if (payload.version >= 0x0111U) {
                            auto source_size =
                                    u64le(bytes, payload_offset + 0x13);
                            payload.source_size = table.byte_swapped
                                                          ? swap64(source_size)
                                                          : source_size;
                        } else {
                            payload.source_size =
                                    endian_u32(payload_offset + 0x13);
                            payload.legacy_source_size_metadata =
                                    endian_u32(payload_offset + 0x17);
                        }
                        if (entry.type == 2U) {
                            payload.sample_trailer =
                                    endian_u32(payload_offset + 0x1b);
                        }
                    }
                    payload.header_size = header_size;
                    if (payload.source_size >
                            bytes.size() - payload_offset - header_size) {
                        throw std::runtime_error(
                                "monolith item payload exceeds file bounds: type=" +
                                std::to_string(entry.type) +
                                " offset=" + std::to_string(payload_offset) +
                                " version=" + std::to_string(payload.version) +
                                " source_size=" +
                                std::to_string(payload.source_size) +
                                " available=" +
                                std::to_string(bytes.size() - payload_offset -
                                               header_size));
                    }
                    payload.end_offset =
                            payload_offset + header_size +
                            static_cast<std::size_t>(payload.source_size);
                    entry.payload = payload;
                }
            }
            table.entries.push_back(std::move(entry));
        }
        table.end_offset = cursor;
        out.tables.push_back(std::move(table));
    }
    return out;
}

const MonolithEntry *find_monolith_entry(const MonolithContainer &container,
        std::span<const std::string_view> utf8_components) {
    if (utf8_components.empty())
        return nullptr;
    auto table = std::find_if(container.tables.begin(), container.tables.end(),
            [&](const MonolithTable &candidate) {
                return candidate.offset == container.root_offset;
            });
    if (table == container.tables.end())
        return nullptr;
    for (std::size_t index = 0; index < utf8_components.size(); ++index) {
        const auto entry = std::find_if(table->entries.begin(),
                table->entries.end(), [&](const MonolithEntry &candidate) {
                    return monolith_name_equal(
                            utf8(candidate.name), utf8_components[index]);
                });
        if (entry == table->entries.end())
            return nullptr;
        if (index + 1 == utf8_components.size())
            return &*entry;
        if (entry->type != 1U)
            return nullptr;
        table = std::find_if(container.tables.begin(), container.tables.end(),
                [&](const MonolithTable &candidate) {
                    return candidate.offset == entry->resolved_offset;
                });
        if (table == container.tables.end())
            return nullptr;
    }
    return nullptr;
}

std::optional<std::uint32_t> monolith_entry_library_id(
        const MonolithEntry &entry) noexcept {
    if (!entry.payload)
        return std::nullopt;
    const auto raw = entry.payload->writer_argument;
    if (entry.payload->version >= 0x111U)
        return raw;
    // these unsigned multipliers recover the legacy decimal digits; keep the
    // truncation and masks in this order
    const auto quarter_remainder = (raw % 1000U) >> 2U;
    const auto last_two = raw % 1000U - (quarter_remainder / 25U) * 100U;
    const auto low_byte = last_two & 0xffU;
    return ((quarter_remainder * 0x147bU >> 9U) & 0xff00U) |
           ((raw / 1000U) << 12U) | ((low_byte * 0xcdU >> 7U) & 0xf0U) |
           ((last_two - (low_byte / 10U) * 10U) & 0xffU);
}

} // namespace libnki
