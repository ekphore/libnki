// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "libnki/nki.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <limits>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>

#include "../binary/read.h"
#include "internal.h"

namespace libnki {
using namespace detail::binary;
using namespace detail::container;

namespace {

class TocByteSource {
  public:
    explicit TocByteSource(std::span<const std::byte> bytes)
        : single(bytes), byte_count(bytes.size()) {}

    explicit TocByteSource(std::span<const std::span<const std::byte>> parts)
        : parts(parts) {
        for (const auto part : this->parts) {
            if (part.size() >
                    std::numeric_limits<std::size_t>::max() - byte_count) {
                throw std::runtime_error(
                        "FileContainer multipart extent overflows address space");
            }
            byte_count += part.size();
        }
    }

    [[nodiscard]] std::size_t size() const { return byte_count; }

    [[nodiscard]] std::uint8_t byte(std::size_t offset) const {
        if (offset >= byte_count)
            throw std::runtime_error("FileContainer read exceeds extent");
        if (parts.empty())
            return u8(single, offset);
        std::size_t base = 0;
        for (const auto part : parts) {
            if (offset - base < part.size())
                return u8(part, offset - base);
            base += part.size();
        }
        throw std::runtime_error("FileContainer multipart read exceeds extent");
    }

    [[nodiscard]] std::uint32_t u32(std::size_t offset) const {
        return static_cast<std::uint32_t>(byte(offset)) |
               (static_cast<std::uint32_t>(byte(offset + 1)) << 8U) |
               (static_cast<std::uint32_t>(byte(offset + 2)) << 16U) |
               (static_cast<std::uint32_t>(byte(offset + 3)) << 24U);
    }

    [[nodiscard]] std::uint64_t u64(std::size_t offset) const {
        return static_cast<std::uint64_t>(u32(offset)) |
               (static_cast<std::uint64_t>(u32(offset + 4)) << 32U);
    }

    [[nodiscard]] bool magic(
            std::size_t offset, std::string_view expected) const {
        if (offset > byte_count || expected.size() > byte_count - offset)
            return false;
        for (std::size_t i = 0; i < expected.size(); ++i) {
            if (byte(offset + i) != static_cast<std::uint8_t>(expected[i]))
                return false;
        }
        return true;
    }

  private:
    std::span<const std::byte> single;
    std::span<const std::span<const std::byte>> parts;
    std::size_t byte_count{};
};

std::u16string read_toc_name(const TocByteSource &bytes,
        std::size_t record_offset, std::size_t record_size) {
    std::u16string out;
    for (std::size_t offset = record_offset + 0x20;
            offset + 1 < record_offset + record_size; offset += 2) {
        const auto code_unit = static_cast<char16_t>(
                static_cast<std::uint16_t>(bytes.byte(offset)) |
                static_cast<std::uint16_t>(bytes.byte(offset + 1) << 8U));
        if (code_unit == 0)
            break;
        out.push_back(code_unit);
    }
    return out;
}

NicntContentToc parse_content_toc(
        const TocByteSource &bytes, std::size_t toc_offset) {
    constexpr std::string_view toc_magic = "/\\ NI FC TOC  /\\";
    if (toc_offset > bytes.size() || 0x28 > bytes.size() - toc_offset ||
            !bytes.magic(toc_offset + 0x20, toc_magic)) {
        throw std::runtime_error("invalid NICNT FC TOC header");
    }
    NicntContentToc out;
    out.offset = toc_offset;
    out.version = bytes.u32(toc_offset);
    out.record_size = out.version == 1 ? 0x280 : 0xa0;
    if (bytes.u32(toc_offset + 4) != 0 ||
            bytes.u64(toc_offset + 8) != 0xf0f0f0f0f0f0f0f0ULL) {
        throw std::runtime_error("invalid NICNT FC TOC header marker");
    }
    out.entry_count = bytes.u32(toc_offset + 0x10);
    out.flags = bytes.u32(toc_offset + 0x14);
    out.total_content_size = bytes.u64(toc_offset + 0x18);
    if (out.entry_count > (1U << 20)) {
        throw std::runtime_error("unreasonable NICNT FC TOC entry count");
    }
    const auto index_size =
            (out.flags & 1U) != 0
                    ? static_cast<std::uint64_t>(out.entry_count) * 8U
                    : 0U;
    const auto record_count = static_cast<std::uint64_t>(out.entry_count) + 2U;
    // clang-format off
    if (record_count > std::numeric_limits<std::size_t>::max() /
            out.record_size || index_size >
            std::numeric_limits<std::size_t>::max() || toc_offset >
            std::numeric_limits<std::size_t>::max() -
            static_cast<std::size_t>(index_size) || toc_offset +
            static_cast<std::size_t>(index_size) >
            std::numeric_limits<std::size_t>::max() -
            static_cast<std::size_t>(record_count) * out.record_size) {
        // clang-format on
        throw std::runtime_error("NICNT FC TOC extent overflows address space");
    }
    out.index_offset = toc_offset + out.record_size;
    out.records_offset =
            out.index_offset + static_cast<std::size_t>(index_size);
    const auto toc_end =
            toc_offset + static_cast<std::size_t>(index_size) +
            static_cast<std::size_t>(record_count) * out.record_size;
    if (toc_end > bytes.size() ||
            out.total_content_size > bytes.size() - toc_end) {
        throw std::runtime_error("NICNT FC TOC or content region is truncated");
    }
    if ((out.flags & 1U) != 0) {
        out.id_index.reserve(out.entry_count);
        for (std::uint32_t index = 0; index < out.entry_count; ++index) {
            const auto offset =
                    out.index_offset + static_cast<std::size_t>(index) * 8U;
            out.id_index.push_back(
                    { bytes.u32(offset), bytes.u32(offset + 4) });
        }
    }
    out.sentinel_offset =
            out.records_offset +
            static_cast<std::size_t>(out.entry_count) * out.record_size;
    out.content_offset = toc_end;
    out.end_offset = out.content_offset +
                     static_cast<std::size_t>(out.total_content_size);
    out.entries.reserve(out.entry_count);
    for (std::uint32_t index = 0; index < out.entry_count; ++index) {
        const auto record_offset =
                out.records_offset +
                static_cast<std::size_t>(index) * out.record_size;
        const auto next_offset = bytes.u64(record_offset + out.record_size);
        NicntContentEntry entry;
        entry.relative_offset = bytes.u64(record_offset);
        if (next_offset < entry.relative_offset ||
                next_offset > out.total_content_size) {
            throw std::runtime_error(
                    "nonmonotonic NICNT FC TOC content offsets");
        }
        entry.size = next_offset - entry.relative_offset;
        entry.id = bytes.u32(record_offset + 8);
        entry.revision = bytes.u32(record_offset + 0x0c);
        entry.name = read_toc_name(bytes, record_offset, out.record_size);
        entry.data_offset = out.content_offset +
                            static_cast<std::size_t>(entry.relative_offset);
        entry.end_offset =
                entry.data_offset + static_cast<std::size_t>(entry.size);
        out.entries.push_back(std::move(entry));
    }
    return out;
}

std::vector<NicntContentToc> parse_file_container_tocs_source(
        const TocByteSource &bytes) {
    constexpr std::string_view toc_magic = "/\\ NI FC TOC  /\\";
    std::size_t offset = 0;
    while (offset <= bytes.size() &&
            NicntContainer::metadata_header_size <= bytes.size() - offset &&
            bytes.magic(offset, kMetadataMagic)) {
        const auto skip = static_cast<std::size_t>(bytes.u32(offset + 0x94));
        if (skip >
                bytes.size() - offset - NicntContainer::metadata_header_size) {
            throw std::runtime_error(
                    "FileContainer MTD skip exceeds file extent");
        }
        offset += NicntContainer::metadata_header_size + skip;
    }
    std::vector<NicntContentToc> tocs;
    while (offset < bytes.size()) {
        if (0x28 > bytes.size() - offset ||
                !bytes.magic(offset + 0x20, toc_magic)) {
            if (tocs.empty())
                return {};
            throw std::runtime_error("invalid trailing NICNT FC TOC table");
        }
        auto toc = parse_content_toc(bytes, offset);
        offset = toc.end_offset;
        tocs.push_back(std::move(toc));
    }
    return tocs;
}

std::string toc_name_utf8(std::u16string_view name) {
    std::string out;
    out.reserve(name.size());
    for (std::size_t index = 0; index < name.size(); ++index) {
        std::uint32_t code_point = name[index];
        if (code_point >= 0xd800U && code_point <= 0xdbffU) {
            if (++index == name.size() || name[index] < 0xdc00U ||
                    name[index] > 0xdfffU) {
                throw std::runtime_error("invalid UTF-16 name in NICNT FC TOC");
            }
            code_point = 0x10000U + ((code_point - 0xd800U) << 10U) +
                         (static_cast<std::uint32_t>(name[index]) - 0xdc00U);
        } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
            throw std::runtime_error("invalid UTF-16 name in NICNT FC TOC");
        }
        if (code_point <= 0x7fU) {
            out.push_back(static_cast<char>(code_point));
        } else if (code_point <= 0x7ffU) {
            out.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
            out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
        } else if (code_point <= 0xffffU) {
            out.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
            out.push_back(
                    static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
            out.push_back(
                    static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
            out.push_back(
                    static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
        }
    }
    return out;
}

template <typename Matches>
const NicntContentEntry *find_content(
        const NicntContentToc &toc, std::uint32_t revision, Matches matches) {
    const NicntContentEntry *best = nullptr;
    for (const auto &entry : toc.entries) {
        if (!matches(entry))
            continue;
        if (revision != nicnt_any_content_revision) {
            if (entry.revision == revision)
                return &entry;
            continue;
        }
        if (best == nullptr || entry.revision > best->revision)
            best = &entry;
    }
    return best;
}

} // namespace

std::optional<NicntContentToc> parse_file_container_toc(
        std::span<const std::byte> bytes) {
    auto tocs = parse_file_container_tocs(bytes);
    if (tocs.empty())
        return std::nullopt;
    return std::move(tocs.front());
}

std::vector<NicntContentToc> parse_file_container_tocs(
        std::span<const std::byte> bytes) {
    return parse_file_container_tocs_source(TocByteSource(bytes));
}

std::vector<NicntContentToc> parse_file_container_tocs(
        std::span<const std::span<const std::byte>> parts) {
    return parse_file_container_tocs_source(TocByteSource(parts));
}

const NicntContentEntry *find_nicnt_content_by_id(
        const NicntContentToc &toc, std::uint32_t id, std::uint32_t revision) {
    return find_content(toc, revision,
            [id](const NicntContentEntry &entry) { return entry.id == id; });
}

const NicntContentEntry *find_nicnt_content_by_id(
        std::span<const NicntContentToc> tocs, std::uint32_t id,
        std::uint32_t revision) {
    const NicntContentEntry *best = nullptr;
    for (const auto &toc : tocs) {
        const auto *candidate = find_nicnt_content_by_id(toc, id, revision);
        if (candidate == nullptr)
            continue;
        if (revision != nicnt_any_content_revision)
            return candidate;
        if (best == nullptr || candidate->revision > best->revision)
            best = candidate;
    }
    return best;
}

const NicntContentEntry *find_nicnt_content_by_name(const NicntContentToc &toc,
        std::string_view utf8_name, std::uint32_t revision) {
    return find_content(toc, revision, [&](const NicntContentEntry &entry) {
        return toc_name_utf8(entry.name) == utf8_name;
    });
}

const NicntContentEntry *find_nicnt_content_by_name(
        std::span<const NicntContentToc> tocs, std::string_view utf8_name,
        std::uint32_t revision) {
    const NicntContentEntry *best = nullptr;
    for (const auto &toc : tocs) {
        const auto *candidate =
                find_nicnt_content_by_name(toc, utf8_name, revision);
        if (candidate == nullptr)
            continue;
        if (revision != nicnt_any_content_revision)
            return candidate;
        if (best == nullptr || candidate->revision > best->revision)
            best = candidate;
    }
    return best;
}

std::span<const std::byte> nicnt_content_bytes(
        std::span<const std::byte> container, const NicntContentEntry &entry) {
    if (entry.data_offset > container.size() ||
            entry.size > container.size() - entry.data_offset ||
            entry.size > std::numeric_limits<std::size_t>::max() ||
            entry.end_offset !=
                    entry.data_offset + static_cast<std::size_t>(entry.size)) {
        throw std::runtime_error(
                "NICNT content entry exceeds container extent");
    }
    return container.subspan(
            entry.data_offset, static_cast<std::size_t>(entry.size));
}

std::vector<NicntContentPartSpan> nicnt_content_parts(
        std::span<const std::span<const std::byte>> parts,
        const NicntContentEntry &entry) {
    if (entry.size > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("NICNT content size exceeds address space");
    }
    std::size_t logical_size = 0;
    for (const auto part : parts) {
        if (part.size() >
                std::numeric_limits<std::size_t>::max() - logical_size) {
            throw std::runtime_error(
                    "NICNT multipart extent overflows address space");
        }
        logical_size += part.size();
    }
    const auto size = static_cast<std::size_t>(entry.size);
    if (entry.data_offset > logical_size ||
            size > logical_size - entry.data_offset ||
            entry.end_offset != entry.data_offset + size) {
        throw std::runtime_error(
                "NICNT content entry exceeds multipart extent");
    }
    std::vector<NicntContentPartSpan> result;
    if (size == 0)
        return result;
    std::size_t part_base = 0;
    std::size_t remaining = size;
    std::size_t position = entry.data_offset;
    for (std::size_t index = 0; index < parts.size() && remaining != 0;
            ++index) {
        const auto part = parts[index];
        const auto part_end = part_base + part.size();
        if (position < part_end) {
            const auto offset = position - part_base;
            const auto count = std::min(remaining, part.size() - offset);
            result.push_back({ index, offset, part.subspan(offset, count) });
            position += count;
            remaining -= count;
        }
        part_base = part_end;
    }
    if (remaining != 0) {
        throw std::runtime_error("NICNT multipart content range is incomplete");
    }
    return result;
}

std::vector<NicntContentToc> parse_nicnt_content_subcontainer(
        std::span<const std::byte> container, const NicntContentEntry &entry) {
    const auto content = nicnt_content_bytes(container, entry);
    return parse_file_container_tocs(content);
}

std::vector<NicntContentToc> parse_nicnt_content_subcontainer(
        std::span<const std::span<const std::byte>> parts,
        const NicntContentEntry &entry) {
    const auto content_parts = nicnt_content_parts(parts, entry);
    std::vector<std::span<const std::byte>> views;
    views.reserve(content_parts.size());
    for (const auto &part : content_parts)
        views.push_back(part.bytes);
    return parse_file_container_tocs(views);
}

std::optional<std::vector<NicntContentToc>> open_nicnt_content_subpath(
        std::span<const std::span<const std::byte>> parts,
        std::span<const NicntContentSelector> selectors,
        std::uint32_t revision) {
    std::vector<std::span<const std::byte>> current_parts(
            parts.begin(), parts.end());
    auto current_tocs = parse_file_container_tocs(current_parts);
    for (const auto &selector : selectors) {
        const NicntContentEntry *entry = nullptr;
        if (selector.kind == NicntContentSelectorKind::id) {
            entry = find_nicnt_content_by_id(
                    current_tocs, selector.id, revision);
        } else {
            entry = find_nicnt_content_by_name(
                    current_tocs, selector.name, revision);
        }
        if (entry == nullptr)
            return std::nullopt;
        const auto selected_parts = nicnt_content_parts(current_parts, *entry);
        current_parts.clear();
        current_parts.reserve(selected_parts.size());
        for (const auto &part : selected_parts)
            current_parts.push_back(part.bytes);
        current_tocs = parse_file_container_tocs(current_parts);
        if (current_tocs.empty())
            return std::nullopt;
    }
    return current_tocs;
}

std::optional<std::vector<NicntContentToc>> open_nicnt_content_subpath(
        std::span<const std::byte> container,
        std::span<const NicntContentSelector> selectors,
        std::uint32_t revision) {
    const std::array parts = { container };
    return open_nicnt_content_subpath(
            std::span<const std::span<const std::byte>>(parts), selectors,
            revision);
}

std::optional<NicntFileContentRange> nicnt_content_range(
        std::span<const std::span<const std::byte>> parts,
        const NicntContentEntry &entry) {
    if (entry.size == 0)
        return std::nullopt;
    if (entry.size > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("NICNT content size exceeds address space");
    }
    std::size_t logical_size = 0;
    for (const auto part : parts) {
        if (part.size() >
                std::numeric_limits<std::size_t>::max() - logical_size) {
            throw std::runtime_error(
                    "NICNT multipart extent overflows address space");
        }
        logical_size += part.size();
    }
    const auto content_size = static_cast<std::size_t>(entry.size);
    if (entry.data_offset >= logical_size ||
            content_size > logical_size - entry.data_offset ||
            entry.end_offset != entry.data_offset + content_size) {
        throw std::runtime_error(
                "NICNT content entry exceeds multipart extent");
    }
    std::size_t part_base = 0;
    std::size_t selected = parts.size();
    for (std::size_t index = 0; index < parts.size(); ++index) {
        const auto end = part_base + parts[index].size();
        if (entry.data_offset < end) {
            selected = index;
            break;
        }
        if (entry.data_offset == end && index + 1 < parts.size()) {
            selected = index + 1;
            part_base = end;
            break;
        }
        part_base = end;
    }
    if (selected == parts.size() ||
            selected > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error(
                "NICNT content start has no multipart storage part");
    }
    NicntFileContentRange range;
    range.part_index = static_cast<std::uint32_t>(selected);
    range.primary_extent_size =
            std::min<std::uint64_t>(parts[selected].size(), entry.size);
    range.part_relative_offset = entry.data_offset - part_base;
    range.logical_content_offset = entry.data_offset;
    range.content_size = entry.size;
    if (parts[selected].size() < entry.size) {
        range.has_mapped_part = true;
        range.mapped_part_index = range.part_index;
        range.mapped_part_relative_offset = range.part_relative_offset;
    }
    return range;
}

} // namespace libnki
