// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../patch/internal.h"
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

namespace libnki::detail::protection {
using namespace patch;

std::uint32_t license_integrity_crc32(
        std::span<const std::byte> bytes) noexcept {
    std::uint32_t crc = 0xffffffffU;
    for (const auto value : bytes) {
        crc ^= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value))
               << 24U;
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc << 1U) ^ (0x04c11db7U & (0U - (crc >> 31U)));
        }
    }
    return ~crc;
}

std::optional<ParsedAuthorizationPayload> parse_authorization_payload(
        std::span<const std::byte> bytes, std::size_t item_record,
        std::size_t auth_end, Document &doc) {
    if (!inherited_record(bytes, item_record, 1, auth_end, doc))
        return std::nullopt;
    const auto item_size = static_cast<std::size_t>(u64le(bytes, item_record));
    if (item_size != 24 || item_size > auth_end - item_record) {
        doc.errors.push_back(
                { item_record, "Authorization Item record must contain its U32 "
                               "payload version" });
        return std::nullopt;
    }
    ParsedAuthorizationPayload out;
    out.base_payload_version = u32le(bytes, item_record + 20);
    if (out.base_payload_version != 1) {
        doc.errors.push_back({ item_record + 20,
                "unsupported Authorization Item payload version" });
        return std::nullopt;
    }
    std::size_t pos = item_record + item_size;
    if (!has(bytes, pos, 8) || pos + 8 > auth_end) {
        doc.errors.push_back({ pos, "truncated Authorization payload" });
        return std::nullopt;
    }
    out.payload_version = u32le(bytes, pos);
    pos += 4;
    out.level = u32le(bytes, pos);
    pos += 4;
    if (out.payload_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported Authorization payload version" });
        return std::nullopt;
    }
    if (out.level == 1) {
        const auto license_start = pos;
        if (!has(bytes, pos, 8) || pos + 8 > auth_end) {
            doc.errors.push_back({ pos, "truncated LicenseInfo header" });
            return std::nullopt;
        }
        LicenseInfoPayload license;
        license.version = u32le(bytes, pos);
        pos += 4;
        if (license.version != 1) {
            doc.errors.push_back(
                    { pos - 4, "unsupported LicenseInfo version" });
            return std::nullopt;
        }
        const auto binding_count = u32le(bytes, pos);
        pos += 4;
        if (binding_count > (auth_end - pos) / 4U) {
            doc.errors.push_back(
                    { pos - 4, "LicenseInfo binding count is out of bounds" });
            return std::nullopt;
        }
        license.product_bindings.reserve(binding_count);
        for (std::uint32_t i = 0; i < binding_count; ++i) {
            auto binding = read_wstring(bytes, pos, auth_end, doc);
            if (!binding)
                return std::nullopt;
            license.product_bindings.push_back(std::move(*binding));
        }
        if (!has(bytes, pos, 4) || pos + 4 > auth_end) {
            doc.errors.push_back(
                    { pos, "truncated LicenseInfo metadata word" });
            return std::nullopt;
        }
        license.license_metadata_word = u32le(bytes, pos);
        pos += 4;
        auto watermark = read_wstring(bytes, pos, auth_end, doc);
        if (!watermark)
            return std::nullopt;
        license.watermark = std::move(*watermark);
        if (!has(bytes, pos, 4) || pos + 4 > auth_end) {
            doc.errors.push_back({ pos, "truncated LicenseInfo checksum" });
            return std::nullopt;
        }
        const auto checksum_offset = pos;
        license.checksum = u32le(bytes, pos);
        pos += 4;
        license.checksum_valid =
                license_integrity_crc32(bytes.subspan(license_start,
                        checksum_offset - license_start)) == license.checksum;
        if (!license.checksum_valid) {
            doc.errors.push_back(
                    { checksum_offset, "LicenseInfo checksum mismatch" });
            return std::nullopt;
        }
        out.license_info = std::move(license);
    }
    if (pos != auth_end) {
        doc.errors.push_back({ pos,
                "Authorization payload does not end at its record boundary" });
        return std::nullopt;
    }
    return out;
}

std::optional<ProtectedItem> parse_protected_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, ProtectedItemKind kind, Document &doc) {
    const auto frame_size = static_cast<std::size_t>(frame.size);
    if (frame.offset > bytes.size() || frame_size > bytes.size() - frame.offset)
        return std::nullopt;
    const auto end = frame.offset + frame_size;
    std::size_t pos = frame.offset + kCommonHeaderSize;
    const auto outer_record = pos;
    if (!has(bytes, outer_record, 8))
        return std::nullopt;
    const auto outer_size =
            static_cast<std::size_t>(u64le(bytes, outer_record));
    if (outer_size < 20 || outer_size > end - outer_record) {
        doc.errors.push_back({ outer_record,
                "protected item record size is out of bounds" });
        return std::nullopt;
    }
    const auto container_offset = outer_record + outer_size;

    if (kind == ProtectedItemKind::app_specific) {
        if (!inherited_record(bytes, pos, 117, container_offset, doc))
            return std::nullopt;
        pos += 20;
    }
    if (kind == ProtectedItemKind::encryption_item) {
        if (!inherited_record(bytes, pos, 116, container_offset, doc))
            return std::nullopt;
        pos += 20;
    }
    if (!inherited_record(bytes, pos, 115, container_offset, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, container_offset, doc))
        return std::nullopt;
    pos += 20;

    if (!has(bytes, pos, 9) || pos + 9 > container_offset) {
        doc.errors.push_back({ pos, "truncated SubtreeItem payload header" });
        return std::nullopt;
    }
    ProtectedItem item;
    item.frame_index = frame_index;
    item.offset = frame.offset;
    item.frame_size = frame.size;
    item.kind = kind;
    item.base_payload_version = u32le(bytes, pos);
    item.subtree_payload_version = u32le(bytes, pos + 4);
    if (item.base_payload_version != 1 || item.subtree_payload_version != 1) {
        doc.errors.push_back(
                { pos, "unsupported SubtreeItem payload version" });
        return std::nullopt;
    }
    item.uses_compression = u8(bytes, pos + 8) != 0;
    pos += 9;

    if (!item.uses_compression) {
        // an uncompressed child starts with its ordinary U64-sized hsin frame;
        // there's no extra length field before it
        if (!has(bytes, pos, kCommonHeaderSize) ||
                pos + kCommonHeaderSize > container_offset) {
            doc.errors.push_back({ pos, "truncated direct SubtreeItem child" });
            return std::nullopt;
        }
        const auto nested_size = u64le(bytes, pos);
        if (nested_size < kCommonHeaderSize ||
                nested_size > container_offset - pos ||
                !tag_is(bytes, pos + 0x0c, "hsin")) {
            doc.errors.push_back(
                    { pos, "invalid direct SubtreeItem child frame" });
            return std::nullopt;
        }
        item.nested_item_offset = pos;
        item.nested_item_size = nested_size;
        pos += static_cast<std::size_t>(nested_size);
    } else {
        if (!has(bytes, pos, 8) || pos + 8 > container_offset) {
            doc.errors.push_back(
                    { pos, "truncated compressed SubtreeItem sizes" });
            return std::nullopt;
        }
        item.uncompressed_size = u32le(bytes, pos);
        item.compressed_size = u32le(bytes, pos + 4);
        pos += 8;
        if (*item.compressed_size > container_offset - pos) {
            doc.errors.push_back({ pos - 4,
                    "SubtreeItem compressed size is out of bounds" });
            return std::nullopt;
        }
        item.compressed_data_offset = pos;
        pos += *item.compressed_size;
    }

    if (kind == ProtectedItemKind::encryption_item) {
        if (!has(bytes, pos, 5) || pos + 5 > container_offset) {
            doc.errors.push_back(
                    { pos, "truncated EncryptionItem payload trailer" });
            return std::nullopt;
        }
        item.encryption_payload_version = u32le(bytes, pos);
        if (*item.encryption_payload_version != 1) {
            doc.errors.push_back(
                    { pos, "unsupported EncryptionItem payload version" });
            return std::nullopt;
        }
        item.xor_enabled = u8(bytes, pos + 4) != 0;
        pos += 5;
    } else if (kind == ProtectedItemKind::app_specific) {
        if (!has(bytes, pos, 8) || pos + 8 > container_offset) {
            doc.errors.push_back(
                    { pos, "truncated AppSpecific payload trailer" });
            return std::nullopt;
        }
        item.app_payload_version = u32le(bytes, pos);
        pos += 4;
        if (*item.app_payload_version != 1) {
            doc.errors.push_back(
                    { pos - 4, "unsupported AppSpecific payload version" });
            return std::nullopt;
        }
        item.app_field_98 = u32le(bytes, pos);
        pos += 4;
        auto version = read_wstring(bytes, pos, container_offset, doc);
        if (!version)
            return std::nullopt;
        item.authoring_application_version = std::move(*version);
    }
    if (pos != container_offset || !has(bytes, pos, 8) || pos + 8 > end) {
        doc.errors.push_back(
                { pos, "invalid protected-item child-container boundary" });
        return std::nullopt;
    }
    item.child_container_version = u32le(bytes, pos);
    pos += 4;
    item.child_count = u32le(bytes, pos);
    pos += 4;
    if (item.child_container_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported protected-item child container" });
        return std::nullopt;
    }
    return item;
}

} // namespace libnki::detail::protection
