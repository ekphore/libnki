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

bool inherited_record_with_domain(std::span<const std::byte> bytes,
        std::size_t off, const char *expected_domain,
        std::uint32_t expected_item_id, std::size_t limit, Document &doc) {
    if (!has(bytes, off, 20) || off + 20 > limit) {
        doc.errors.push_back(
                { off, "truncated inherited NISound item record" });
        return false;
    }
    if (!tag_is(bytes, off + 8, expected_domain)) {
        doc.errors.push_back({ off + 8, "invalid inherited NISound domain" });
        return false;
    }
    if (u32le(bytes, off + 12) != expected_item_id) {
        doc.errors.push_back(
                { off + 12, "unexpected inherited NISound item ID" });
        return false;
    }
    if (u32le(bytes, off + 16) != 1) {
        doc.errors.push_back(
                { off + 16, "unsupported inherited NISound item version" });
        return false;
    }
    return true;
}

bool inherited_record(std::span<const std::byte> bytes, std::size_t off,
        std::uint32_t expected_item_id, std::size_t limit, Document &doc) {
    return inherited_record_with_domain(
            bytes, off, "DSIN", expected_item_id, limit, doc);
}

std::optional<RepositoryRoot> parse_repository_root(
        std::span<const std::byte> bytes, const Frame &frame, Document &doc) {
    const auto frame_size = static_cast<std::size_t>(frame.size);
    if (frame.offset > bytes.size() || frame_size > bytes.size() - frame.offset)
        return std::nullopt;
    const auto end = frame.offset + frame_size;
    const auto root_record = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, root_record, 118, end, doc))
        return std::nullopt;
    const auto root_record_size =
            static_cast<std::size_t>(u64le(bytes, root_record));
    if (root_record_size < 20 || root_record_size > end - root_record) {
        doc.errors.push_back({ root_record,
                "RepositoryRoot inherited record size is out of bounds" });
        return std::nullopt;
    }
    const auto container_offset = root_record + root_record_size;
    const auto auth_record = root_record + 20;
    if (!inherited_record(bytes, auth_record, 106, container_offset, doc))
        return std::nullopt;
    const auto auth_record_size =
            static_cast<std::size_t>(u64le(bytes, auth_record));
    if (auth_record_size < 40 ||
            auth_record_size > container_offset - auth_record) {
        doc.errors.push_back({ auth_record,
                "Authorization inherited record size is out of bounds" });
        return std::nullopt;
    }
    const auto auth_end = auth_record + auth_record_size;
    const auto item_record = auth_record + 20;
    auto authorization =
            parse_authorization_payload(bytes, item_record, auth_end, doc);
    if (!authorization)
        return std::nullopt;
    RepositoryRoot root;
    root.authorization_mode = authorization->level;
    root.license_info = std::move(authorization->license_info);
    if (root.license_info && root.license_info->product_bindings.size() == 1) {
        root.authorization_snpid = root.license_info->product_bindings.front();
    }
    root.payload_offset = auth_end;
    root.container_offset = container_offset;
    std::size_t pos = auth_end;
    if (!has(bytes, pos, 16) || pos + 16 > container_offset) {
        doc.errors.push_back({ pos, "truncated RepositoryRoot payload" });
        return std::nullopt;
    }
    root.version = u32le(bytes, pos);
    if (root.version != 1) {
        doc.errors.push_back(
                { pos, "unsupported RepositoryRoot payload version" });
        return std::nullopt;
    }
    root.creator_version_packed = u32le(bytes, pos + 4);
    root.repository_magic = u32le(bytes, pos + 8);
    root.repository_type = u32le(bytes, pos + 12);
    pos += 16;
    if (!has(bytes, pos, 8) || pos + 8 > container_offset) {
        doc.errors.push_back({ pos, "truncated FileReference header" });
        return std::nullopt;
    }
    root.file_reference.version = u32le(bytes, pos);
    if (root.file_reference.version != 1) {
        doc.errors.push_back({ pos, "unsupported FileReference version" });
        return std::nullopt;
    }
    root.file_reference.kind = u32le(bytes, pos + 4);
    pos += 8;
    auto path = read_wstring(bytes, pos, container_offset, doc);
    if (!path)
        return std::nullopt;
    root.file_reference.path = std::move(*path);
    auto secondary = read_wstring(bytes, pos, container_offset, doc);
    if (!secondary)
        return std::nullopt;
    root.file_reference.secondary_path = std::move(*secondary);
    auto snpid = read_wstring(bytes, pos, container_offset, doc);
    if (!snpid)
        return std::nullopt;
    root.file_reference.snpid = std::move(*snpid);
    if (!has(bytes, pos, 16) || pos + 16 > container_offset) {
        doc.errors.push_back({ pos, "truncated RepositoryRoot UUID" });
        return std::nullopt;
    }
    root.repository_uuid_hex = hex(bytes.subspan(pos, 16));
    pos += 16;
    if (pos != container_offset) {
        doc.errors.push_back({ pos, "RepositoryRoot payload does not end at "
                                    "its inherited record boundary" });
        return std::nullopt;
    }
    return root;
}

std::optional<AuthorizationItem> parse_authorization_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto auth_record = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, auth_record, 106, end, doc))
        return std::nullopt;
    const auto auth_size = static_cast<std::size_t>(u64le(bytes, auth_record));
    if (auth_size < 40 || auth_size > end - auth_record) {
        doc.errors.push_back(
                { auth_record, "Authorization record size is out of bounds" });
        return std::nullopt;
    }
    const auto auth_end = auth_record + auth_size;
    auto parsed =
            parse_authorization_payload(bytes, auth_record + 20, auth_end, doc);
    if (!parsed)
        return std::nullopt;
    if (!has(bytes, auth_end, 8) || auth_end + 8 > end) {
        doc.errors.push_back(
                { auth_end, "truncated Authorization child container" });
        return std::nullopt;
    }
    AuthorizationItem out;
    out.frame_index = frame_index;
    out.base_payload_version = parsed->base_payload_version;
    out.payload_version = parsed->payload_version;
    out.level = parsed->level;
    out.license_info = std::move(parsed->license_info);
    out.child_container_version = u32le(bytes, auth_end);
    out.child_count = u32le(bytes, auth_end + 4);
    if (out.child_container_version != 1) {
        doc.errors.push_back(
                { auth_end, "unsupported Authorization child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<BaseItem> parse_base_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto item_record = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, item_record, 1, end, doc))
        return std::nullopt;
    const auto item_size = static_cast<std::size_t>(u64le(bytes, item_record));
    if (item_size != 24 || item_size > end - item_record) {
        doc.errors.push_back({ item_record,
                "Item record must contain its U32 payload version" });
        return std::nullopt;
    }
    const auto container_offset = item_record + item_size;
    if (!has(bytes, container_offset, 8) || container_offset + 8 > end) {
        doc.errors.push_back(
                { container_offset, "truncated Item child container" });
        return std::nullopt;
    }
    BaseItem out;
    out.frame_index = frame_index;
    out.payload_version = u32le(bytes, item_record + 20);
    out.child_container_version = u32le(bytes, container_offset);
    out.child_count = u32le(bytes, container_offset + 4);
    if (out.payload_version != 1 || out.child_container_version != 1) {
        doc.errors.push_back({ item_record + 20,
                "unsupported Item payload/container version" });
        return std::nullopt;
    }
    return out;
}

std::optional<PresetInfo> parse_kontakt_preset(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto frame_size = static_cast<std::size_t>(frame.size);
    if (frame.offset > bytes.size() || frame_size > bytes.size() - frame.offset)
        return std::nullopt;
    const auto end = frame.offset + frame_size;
    const auto kontakt_record = frame.offset + kCommonHeaderSize;
    if (!inherited_record_with_domain(
                bytes, kontakt_record, "4KIN", 3, end, doc))
        return std::nullopt;
    const auto kontakt_size =
            static_cast<std::size_t>(u64le(bytes, kontakt_record));
    if (kontakt_size < 20 || kontakt_size > end - kontakt_record) {
        doc.errors.push_back({ kontakt_record,
                "BNISoundPreset record size is out of bounds" });
        return std::nullopt;
    }
    const auto container_offset = kontakt_record + kontakt_size;
    const auto preset_record = kontakt_record + 20;
    if (!inherited_record(bytes, preset_record, 101, container_offset, doc))
        return std::nullopt;
    const auto preset_size =
            static_cast<std::size_t>(u64le(bytes, preset_record));
    if (preset_size < 20 || preset_size > container_offset - preset_record) {
        doc.errors.push_back(
                { preset_record, "Preset record size is out of bounds" });
        return std::nullopt;
    }
    const auto preset_end = preset_record + preset_size;
    const auto auth_record = preset_record + 20;
    if (!inherited_record(bytes, auth_record, 106, preset_end, doc))
        return std::nullopt;
    const auto auth_size = static_cast<std::size_t>(u64le(bytes, auth_record));
    if (auth_size < 40 || auth_size > preset_end - auth_record) {
        doc.errors.push_back({ auth_record,
                "Preset Authorization record size is out of bounds" });
        return std::nullopt;
    }
    const auto auth_end = auth_record + auth_size;
    const auto item_record = auth_record + 20;
    auto authorization =
            parse_authorization_payload(bytes, item_record, auth_end, doc);
    if (!authorization)
        return std::nullopt;
    PresetInfo preset;
    preset.frame_index = frame_index;
    preset.authorization_mode = authorization->level;
    preset.license_info = std::move(authorization->license_info);
    if (preset.license_info &&
            preset.license_info->product_bindings.size() == 1) {
        preset.authorization_snpid =
                preset.license_info->product_bindings.front();
    }
    preset.payload_offset = auth_end;
    preset.container_offset = container_offset;
    std::size_t pos = auth_end;
    if (!has(bytes, pos, 13) || pos + 13 > preset_end) {
        doc.errors.push_back({ pos, "truncated Preset payload" });
        return std::nullopt;
    }
    preset.version = u32le(bytes, pos);
    if (preset.version != 1) {
        doc.errors.push_back({ pos, "unsupported Preset payload version" });
        return std::nullopt;
    }
    preset.factory_content = u8(bytes, pos + 4) != 0;
    preset.authoring_application_id = u32le(bytes, pos + 5);
    preset.authoring_info_version = u32le(bytes, pos + 9);
    if (preset.authoring_info_version != 1) {
        doc.errors.push_back(
                { pos + 9, "unsupported Preset authoring-info version" });
        return std::nullopt;
    }
    pos += 13;
    auto creator = read_wstring(bytes, pos, preset_end, doc);
    if (!creator)
        return std::nullopt;
    preset.creator_version = std::move(*creator);
    if (pos != preset_end) {
        doc.errors.push_back(
                { pos, "Preset payload does not end at its record boundary" });
        return std::nullopt;
    }
    if (!has(bytes, pos, 2) || pos + 2 > container_offset) {
        doc.errors.push_back({ pos, "truncated BNISoundPreset extension" });
        return std::nullopt;
    }
    preset.kontakt_extension_version = u16le(bytes, pos);
    if (preset.kontakt_extension_version != 0 || pos + 2 != container_offset) {
        doc.errors.push_back({ pos, "unsupported BNISoundPreset extension" });
        return std::nullopt;
    }
    if (!has(bytes, container_offset, 8) || container_offset + 8 > end) {
        doc.errors.push_back(
                { container_offset, "truncated Preset child container" });
        return std::nullopt;
    }
    preset.child_container_version = u32le(bytes, container_offset);
    preset.child_count = u32le(bytes, container_offset + 4);
    if (preset.child_container_version != 1) {
        doc.errors.push_back(
                { container_offset, "unsupported Preset child container" });
        return std::nullopt;
    }
    return preset;
}

std::optional<PresetInfo> parse_preset_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto preset_record = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, preset_record, 101, end, doc))
        return std::nullopt;
    const auto preset_size =
            static_cast<std::size_t>(u64le(bytes, preset_record));
    if (preset_size < 20 || preset_size > end - preset_record) {
        doc.errors.push_back(
                { preset_record, "Preset record size is out of bounds" });
        return std::nullopt;
    }
    const auto container_offset = preset_record + preset_size;
    const auto auth_record = preset_record + 20;
    if (!inherited_record(bytes, auth_record, 106, container_offset, doc)) {
        return std::nullopt;
    }
    const auto auth_size = static_cast<std::size_t>(u64le(bytes, auth_record));
    if (auth_size < 40 || auth_size > container_offset - auth_record) {
        doc.errors.push_back({ auth_record,
                "Preset Authorization record size is out of bounds" });
        return std::nullopt;
    }
    const auto auth_end = auth_record + auth_size;
    auto authorization =
            parse_authorization_payload(bytes, auth_record + 20, auth_end, doc);
    if (!authorization)
        return std::nullopt;
    PresetInfo preset;
    preset.frame_index = frame_index;
    preset.authorization_mode = authorization->level;
    preset.license_info = std::move(authorization->license_info);
    if (preset.license_info &&
            preset.license_info->product_bindings.size() == 1) {
        preset.authorization_snpid =
                preset.license_info->product_bindings.front();
    }
    preset.payload_offset = auth_end;
    preset.container_offset = container_offset;
    std::size_t pos = auth_end;
    if (!has(bytes, pos, 13) || pos + 13 > container_offset) {
        doc.errors.push_back({ pos, "truncated Preset payload" });
        return std::nullopt;
    }
    preset.version = u32le(bytes, pos);
    pos += 4;
    preset.factory_content = u8(bytes, pos++) != 0;
    preset.authoring_application_id = u32le(bytes, pos);
    pos += 4;
    preset.authoring_info_version = u32le(bytes, pos);
    pos += 4;
    if (preset.version != 1 || preset.authoring_info_version != 1) {
        doc.errors.push_back(
                { auth_end, "unsupported Preset payload version" });
        return std::nullopt;
    }
    auto creator = read_wstring(bytes, pos, container_offset, doc);
    if (!creator)
        return std::nullopt;
    preset.creator_version = std::move(*creator);
    if (pos != container_offset || !has(bytes, pos, 8) || pos + 8 > end) {
        doc.errors.push_back(
                { pos, "invalid Preset child-container boundary" });
        return std::nullopt;
    }
    preset.child_container_version = u32le(bytes, pos);
    pos += 4;
    preset.child_count = u32le(bytes, pos);
    pos += 4;
    if (preset.child_container_version != 1) {
        doc.errors.push_back({ pos - 8, "unsupported Preset child container" });
        return std::nullopt;
    }
    return preset;
}

std::optional<SoundInfoItem> parse_sound_info(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 108, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    SoundInfoItem out;
    out.frame_index = frame_index;
    if (!has(bytes, pos, 12) || pos + 12 > end) {
        doc.errors.push_back({ pos, "truncated SoundInfo header" });
        return std::nullopt;
    }
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    out.payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1 ||
            out.payload_version != 2) {
        doc.errors.push_back(
                { pos - 12, "unsupported SoundInfo payload version" });
        return std::nullopt;
    }
    for (auto &value : out.leading_u32) {
        value = u32le(bytes, pos);
        pos += 4;
    }
    for (auto &value : out.strings) {
        auto s = read_wstring(bytes, pos, end, doc);
        if (!s)
            return std::nullopt;
        value = std::move(*s);
    }
    if (!has(bytes, pos, 28) || pos + 28 > end) {
        doc.errors.push_back({ pos, "truncated SoundInfo scalar fields" });
        return std::nullopt;
    }
    for (auto &value : out.trailing_u32) {
        value = u32le(bytes, pos);
        pos += 4;
    }
    out.trailing_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    auto read_string_groups =
            [&](std::vector<std::vector<std::string>> &groups) -> bool {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            return false;
        const auto group_count = u32le(bytes, pos);
        pos += 4;
        groups.resize(group_count);
        for (auto &group : groups) {
            if (!has(bytes, pos, 4) || pos + 4 > end)
                return false;
            const auto count = u32le(bytes, pos);
            pos += 4;
            group.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                auto s = read_wstring(bytes, pos, end, doc);
                if (!s)
                    return false;
                group.push_back(std::move(*s));
            }
        }
        return true;
    };
    if (!read_string_groups(out.bank_chain_strings)) {
        doc.errors.push_back({ pos, "truncated SoundInfo bank-chain strings" });
        return std::nullopt;
    }
    auto read_string_list = [&](std::vector<std::string> &values) -> bool {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            return false;
        const auto count = u32le(bytes, pos);
        pos += 4;
        values.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto s = read_wstring(bytes, pos, end, doc);
            if (!s)
                return false;
            values.push_back(std::move(*s));
        }
        return true;
    };
    auto read_pairs =
            [&](std::vector<std::pair<std::string, std::string>> &values)
            -> bool {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            return false;
        const auto count = u32le(bytes, pos);
        pos += 4;
        values.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto a = read_wstring(bytes, pos, end, doc);
            if (!a)
                return false;
            auto b = read_wstring(bytes, pos, end, doc);
            if (!b)
                return false;
            values.emplace_back(std::move(*a), std::move(*b));
        }
        return true;
    };
    if (!read_string_list(out.tags) || !read_pairs(out.user_set_attributes) ||
            !read_pairs(out.final_string_map)) {
        doc.errors.push_back({ pos, "truncated SoundInfo collections" });
        return std::nullopt;
    }
    return out;
}

std::optional<AutomationParameters> parse_automation_parameters(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 120, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 12) || pos + 12 > end) {
        doc.errors.push_back({ pos, "truncated AutomationParameters header" });
        return std::nullopt;
    }
    AutomationParameters out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.payload_version != 1) {
        doc.errors.push_back({ pos - 8,
                "unsupported AutomationParameters payload version" });
        return std::nullopt;
    }
    const auto count = u32le(bytes, pos);
    pos += 4;
    out.descriptors.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            return std::nullopt;
        ParameterDescriptor descriptor;
        descriptor.version = u32le(bytes, pos);
        pos += 4;
        if (descriptor.version != 1) {
            doc.errors.push_back(
                    { pos - 4, "unsupported ParameterDescriptor version" });
            return std::nullopt;
        }
        for (auto &value : descriptor.strings) {
            auto s = read_wstring(bytes, pos, end, doc);
            if (!s)
                return std::nullopt;
            value = std::move(*s);
        }
        if (!has(bytes, pos, 12) || pos + 12 > end) {
            doc.errors.push_back(
                    { pos, "truncated ParameterDescriptor values" });
            return std::nullopt;
        }
        for (auto &value : descriptor.values) {
            const auto bits = u32le(bytes, pos);
            pos += 4;
            std::memcpy(&value, &bits, sizeof(value));
        }
        out.descriptors.push_back(std::move(descriptor));
    }
    return out;
}

std::optional<ControllerAssignments> parse_controller_assignments(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 121, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 16) || pos + 16 > end) {
        doc.errors.push_back({ pos, "truncated ControllerAssignments header" });
        return std::nullopt;
    }
    ControllerAssignments out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.payload_version = u32le(bytes, pos);
    pos += 4;
    out.collection_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.payload_version != 1 ||
            out.collection_version != 1) {
        doc.errors.push_back(
                { pos - 12, "unsupported ControllerAssignments version" });
        return std::nullopt;
    }
    const auto group_count = u32le(bytes, pos);
    pos += 4;
    if (group_count > (end - pos) / 12U) {
        doc.errors.push_back({ pos - 4,
                "ControllerAssignments group count is out of bounds" });
        return std::nullopt;
    }
    out.groups.reserve(group_count);
    for (std::uint32_t group_index = 0; group_index < group_count;
            ++group_index) {
        if (!has(bytes, pos, 8) || pos + 8 > end) {
            doc.errors.push_back(
                    { pos, "truncated ControllerGroupAssignments header" });
            return std::nullopt;
        }
        ControllerGroupAssignments group;
        group.version = u32le(bytes, pos);
        pos += 4;
        if (group.version != 1) {
            doc.errors.push_back({ pos - 4,
                    "unsupported ControllerGroupAssignments version" });
            return std::nullopt;
        }
        const auto assignment_count = u32le(bytes, pos);
        pos += 4;
        auto group_name = read_wstring(bytes, pos, end, doc);
        if (!group_name)
            return std::nullopt;
        group.name = std::move(*group_name);
        if (assignment_count > (end - pos) / 24U) {
            doc.errors.push_back(
                    { pos, "ControllerAssignment count is out of bounds" });
            return std::nullopt;
        }
        group.assignments.reserve(assignment_count);
        for (std::uint32_t assignment_index = 0;
                assignment_index < assignment_count; ++assignment_index) {
            if (!has(bytes, pos, 4) || pos + 4 > end) {
                doc.errors.push_back(
                        { pos, "truncated ControllerAssignment version" });
                return std::nullopt;
            }
            ControllerAssignment assignment;
            assignment.version = u32le(bytes, pos);
            pos += 4;
            if (assignment.version != 1) {
                doc.errors.push_back({ pos - 4,
                        "unsupported ControllerAssignment version" });
                return std::nullopt;
            }
            auto name = read_wstring(bytes, pos, end, doc);
            if (!name)
                return std::nullopt;
            assignment.name = std::move(*name);
            if (!has(bytes, pos, 16) || pos + 16 > end) {
                doc.errors.push_back(
                        { pos, "truncated ControllerAssignment values" });
                return std::nullopt;
            }
            for (auto &value : assignment.f32) {
                const auto bits = u32le(bytes, pos);
                pos += 4;
                std::memcpy(&value, &bits, sizeof(value));
            }
            for (auto &value : assignment.u32) {
                value = u32le(bytes, pos);
                pos += 4;
            }
            group.assignments.push_back(std::move(assignment));
        }
        out.groups.push_back(std::move(group));
    }
    return out;
}

std::optional<BNISoundHeader> parse_bnisound_header(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record_with_domain(bytes, pos, "4KIN", 4, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 4 + 0xde) || pos + 4 + 0xde > end) {
        doc.errors.push_back({ pos, "truncated BNISoundHeader payload" });
        return std::nullopt;
    }
    BNISoundHeader out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1) {
        doc.errors.push_back(
                { pos - 4, "unsupported BNISoundHeader Item payload version" });
        return std::nullopt;
    }
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
            out.verified_bytes.size(), out.verified_bytes.begin());
    const auto raw_magic = u32le(out.verified_bytes, 0);
    const auto is_v42_magic = [](std::uint32_t value) {
        return value == 0xab85ef01U || value == 0x10874353U ||
               value == 0x7fa89012U;
    };
    const bool swapped =
            !is_v42_magic(raw_magic) && is_v42_magic(byteswap32(raw_magic));
    const auto raw_kind = u16le(out.verified_bytes, 0x0e);
    out.artifact_kind = swapped ? static_cast<std::uint16_t>(
                                          (raw_kind >> 8U) | (raw_kind << 8U))
                                : raw_kind;
    return out;
}

std::optional<AudioSampleItem> parse_audio_sample_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 112, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 28) || pos + 28 > end) {
        doc.errors.push_back(
                { pos, "truncated AudioSampleItem/AudioBlock header" });
        return std::nullopt;
    }

    AudioSampleItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported AudioSampleItem payload version" });
        return std::nullopt;
    }
    out.sample_index = u32le(bytes, pos);
    pos += 4;
    out.audio_block_version = u32le(bytes, pos);
    pos += 4;
    if (out.audio_block_version != 1) {
        doc.errors.push_back(
                { pos - 4, "unsupported AudioBlock payload version" });
        return std::nullopt;
    }
    out.frame_count = u32le(bytes, pos);
    pos += 4;
    out.channel_count = u32le(bytes, pos);
    pos += 4;
    // AudioBlock has a fixed 0x2800-byte channel-pointer table; larger channel
    // counts don't fit the object, even if the sample data fits the frame
    constexpr std::uint32_t kAudioBlockChannelCapacity = 0x2800U / 8U;
    if (out.channel_count > kAudioBlockChannelCapacity) {
        doc.errors.push_back({ pos - 4,
                "AudioBlock channel count exceeds object capacity" });
        return std::nullopt;
    }
    const auto remaining_float_bytes = end - pos;
    if (out.channel_count != 0 &&
            out.frame_count > std::numeric_limits<std::size_t>::max() /
                                      out.channel_count) {
        doc.errors.push_back({ pos - 8, "AudioBlock dimensions overflow" });
        return std::nullopt;
    }
    const auto sample_count =
            static_cast<std::size_t>(out.frame_count) * out.channel_count;
    if (sample_count >
            (remaining_float_bytes -
                    std::min<std::size_t>(remaining_float_bytes, 8U)) /
                    4U) {
        doc.errors.push_back(
                { pos - 8, "AudioBlock sample data is out of bounds" });
        return std::nullopt;
    }
    out.channels.resize(out.channel_count);
    for (auto &channel : out.channels) {
        channel.resize(out.frame_count);
        for (auto &sample : channel) {
            const auto bits = u32le(bytes, pos);
            pos += 4;
            std::memcpy(&sample, &bits, sizeof(sample));
        }
    }
    if (!has(bytes, pos, 8) || pos + 8 > end) {
        doc.errors.push_back(
                { pos, "truncated AudioSampleItem child container" });
        return std::nullopt;
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    if (out.container_version != 1) {
        doc.errors.push_back(
                { pos - 4, "unsupported AudioSampleItem container version" });
        return std::nullopt;
    }
    return out;
}

std::optional<ExternalFileReferenceItem> parse_external_file_reference_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 110, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 12) || pos + 12 > end) {
        doc.errors.push_back({ pos, "truncated ExternalFileReference header" });
        return std::nullopt;
    }
    ExternalFileReferenceItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    out.file_reference_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1 ||
            out.file_reference_version != 1) {
        doc.errors.push_back(
                { pos - 12, "unsupported ExternalFileReference version" });
        return std::nullopt;
    }
    if (!has(bytes, pos, 4) || pos + 4 > end) {
        doc.errors.push_back(
                { pos, "truncated ExternalFileReference value code" });
        return std::nullopt;
    }
    out.value_code = u32le(bytes, pos);
    pos += 4;
    auto string_0 = read_wstring(bytes, pos, end, doc);
    if (!string_0)
        return std::nullopt;
    out.string_0 = std::move(*string_0);
    auto string_1 = read_wstring(bytes, pos, end, doc);
    if (!string_1)
        return std::nullopt;
    out.string_1 = std::move(*string_1);
    auto snpid = read_wstring(bytes, pos, end, doc);
    if (!snpid)
        return std::nullopt;
    out.snpid = std::move(*snpid);
    if (!has(bytes, pos, 8) || pos + 8 > end) {
        doc.errors.push_back(
                { pos, "truncated ExternalFileReference child container" });
        return std::nullopt;
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1) {
        doc.errors.push_back({ pos - 8,
                "unsupported ExternalFileReference child container" });
        return std::nullopt;
    }
    if (pos != end) {
        doc.errors.push_back({ pos, "ExternalFileReference payload does not "
                                    "end at its frame boundary" });
        return std::nullopt;
    }
    return out;
}

std::optional<InternalResourceReferenceItem>
parse_internal_resource_reference_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 113, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 24) || pos + 24 > end) {
        doc.errors.push_back(
                { pos, "truncated InternalResourceReferenceItem payload" });
        return std::nullopt;
    }
    InternalResourceReferenceItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1) {
        doc.errors.push_back({ pos - 8,
                "unsupported InternalResourceReferenceItem payload version" });
        return std::nullopt;
    }
    out.resource_type = u32le(bytes, pos);
    pos += 4;
    out.reference_id = u32le(bytes, pos);
    pos += 4;
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    if (out.container_version != 1) {
        doc.errors.push_back({ pos - 4,
                "unsupported InternalResourceReferenceItem container version" });
        return std::nullopt;
    }
    return out;
}

std::optional<PictureItem> parse_picture_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 114, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 104, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 20) || pos + 20 > end) {
        doc.errors.push_back(
                { pos, "truncated PictureItem/BinaryChunk header" });
        return std::nullopt;
    }

    PictureItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.binary_chunk_item_version = u32le(bytes, pos);
    pos += 4;
    out.binary_chunk_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.binary_chunk_item_version != 1 ||
            out.binary_chunk_version != 1) {
        doc.errors.push_back(
                { pos - 12, "unsupported PictureItem/BinaryChunk version" });
        return std::nullopt;
    }
    out.binary_data_size = u64le(bytes, pos);
    pos += 8;
    if (out.binary_data_size > end - pos ||
            end - pos - out.binary_data_size < 24) {
        doc.errors.push_back(
                { pos - 8, "PictureItem binary chunk is out of bounds" });
        return std::nullopt;
    }
    out.binary_data_offset = pos;
    // clang-format off
    out.binary_data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
            bytes.begin() + static_cast<std::ptrdiff_t>(pos +
            static_cast<std::size_t>(out.binary_data_size)));
    // clang-format on
    pos += static_cast<std::size_t>(out.binary_data_size);
    out.context_id = u32le(bytes, pos);
    pos += 4;
    out.picture_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.picture_payload_version != 1 && out.picture_payload_version != 2) {
        doc.errors.push_back(
                { pos - 4, "unsupported PictureItem payload version" });
        return std::nullopt;
    }
    out.picture_type = u32le(bytes, pos);
    pos += 4;
    const auto read_gp_string = [&](std::string &value) -> bool {
        if (!has(bytes, pos, 4) || pos + 4 > end)
            return false;
        const auto size = static_cast<std::size_t>(u32le(bytes, pos));
        pos += 4;
        if (size > end - pos)
            return false;
        value.assign(reinterpret_cast<const char *>(bytes.data() + pos), size);
        pos += size;
        return true;
    };
    if (out.picture_payload_version == 2) {
        if (!read_gp_string(out.filename) || end - pos < 8) {
            doc.errors.push_back(
                    { pos, "PictureItem filename is out of bounds" });
            return std::nullopt;
        }
    } else {
        if (!has(bytes, pos, 6) || pos + 6 > end) {
            doc.errors.push_back(
                    { pos, "truncated PictureItem legacy filename" });
            return std::nullopt;
        }
        out.legacy_filename_version = u32le(bytes, pos);
        pos += 4;
        out.legacy_filename_format =
                std::to_integer<std::uint8_t>(bytes[pos++]);
        out.legacy_filename_kind = std::to_integer<std::uint8_t>(bytes[pos++]);
        const auto legacy_version = *out.legacy_filename_version;
        const auto legacy_kind = *out.legacy_filename_kind;
        if (legacy_version < 3) {
            std::size_t component_count = 0;
            if (legacy_kind == 1)
                component_count = 4;
            else if (legacy_kind == 2)
                component_count = 2;
            else if (legacy_kind == 3)
                component_count = 1;
            out.legacy_filename_components.resize(component_count);
            for (auto &component : out.legacy_filename_components) {
                if (!read_gp_string(component)) {
                    doc.errors.push_back({ pos, "PictureItem legacy filename "
                                                "component is out of bounds" });
                    return std::nullopt;
                }
            }
        } else {
            const auto uri_begin = pos;
            while (pos < end && pos - uri_begin < 0xfff &&
                    bytes[pos] != std::byte{ 0 })
                ++pos;
            if (pos == end || pos - uri_begin == 0xfff ||
                    bytes[pos] != std::byte{ 0 }) {
                doc.errors.push_back({ uri_begin,
                        "unterminated PictureItem legacy filename URI" });
                return std::nullopt;
            }
            out.legacy_filename_uri.assign(
                    reinterpret_cast<const char *>(bytes.data() + uri_begin),
                    pos - uri_begin);
            ++pos;
        }
        if (end - pos < 8) {
            doc.errors.push_back(
                    { pos, "truncated PictureItem child container" });
            return std::nullopt;
        }
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported PictureItem child container" });
        return std::nullopt;
    }
    if (pos != end) {
        doc.errors.push_back({ pos,
                "PictureItem payload does not end at its frame boundary" });
        return std::nullopt;
    }
    return out;
}

std::optional<BinaryChunkItem> parse_binary_chunk_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto end = frame.offset + static_cast<std::size_t>(frame.size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 104, end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 20) || pos + 20 > end) {
        doc.errors.push_back({ pos, "truncated BinaryChunkItem header" });
        return std::nullopt;
    }
    BinaryChunkItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    out.binary_chunk_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1 ||
            out.binary_chunk_version != 1) {
        doc.errors.push_back(
                { pos - 12, "unsupported BinaryChunkItem version" });
        return std::nullopt;
    }
    out.binary_data_size = u64le(bytes, pos);
    pos += 8;
    if (out.binary_data_size > end - pos ||
            end - pos - out.binary_data_size < 12) {
        doc.errors.push_back(
                { pos - 8, "BinaryChunkItem data is out of bounds" });
        return std::nullopt;
    }
    out.binary_data_offset = pos;
    // clang-format off
    out.binary_data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
            bytes.begin() + static_cast<std::ptrdiff_t>(pos +
            static_cast<std::size_t>(out.binary_data_size)));
    // clang-format on
    pos += static_cast<std::size_t>(out.binary_data_size);
    out.context_id = u32le(bytes, pos);
    pos += 4;
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1 || pos != end) {
        doc.errors.push_back(
                { pos - 8, "unsupported BinaryChunkItem child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<ResourcesItem> parse_resources_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    if (!frame.payload_prefix_size) {
        doc.errors.push_back(
                { frame.offset + 0x28, "missing Resources payload size" });
        return std::nullopt;
    }
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto payload_start = frame.offset + kOpaqueProbePrefixSize;
    if (*frame.payload_prefix_size > frame_end - payload_start) {
        doc.errors.push_back(
                { frame.offset + 0x28, "Resources payload is out of bounds" });
        return std::nullopt;
    }
    const auto payload_end =
            payload_start +
            static_cast<std::size_t>(*frame.payload_prefix_size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 111, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 16) || pos + 16 > payload_end) {
        doc.errors.push_back({ pos, "truncated Resources payload" });
        return std::nullopt;
    }
    ResourcesItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported Resources payload version" });
        return std::nullopt;
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported Resources child container" });
        return std::nullopt;
    }
    if (pos != payload_end) {
        doc.errors.push_back({ pos,
                "Resources payload does not end at its declared boundary" });
        return std::nullopt;
    }

    for (std::size_t i = frame_index + 1; i < doc.frames.size(); ++i) {
        const auto &child = doc.frames[i];
        if (child.offset >= frame_end)
            break;
        if (!child.item_id)
            continue;
        if (*child.item_id == 112) {
            out.sample_frames.push_back(i);
            ++out.num_samples;
        } else if (*child.item_id == 114) {
            out.picture_frames.push_back(i);
            ++out.num_pictures;
        } else if (*child.item_id == 104) {
            out.generic_binary_frames.push_back(i);
            ++out.num_generic_binaries;
        }
    }
    return out;
}

std::string fourcc(std::span<const std::byte> bytes, std::size_t off) {
    if (!has(bytes, off, 4))
        return {};
    return std::string(reinterpret_cast<const char *>(bytes.data() + off), 4);
}

bool factory_has_concrete_item(std::string_view domain, std::uint32_t item_id) {
    if (domain == "4KIN")
        return item_id == 3 || item_id == 4;
    if (domain != "DSIN")
        return false;
    switch (item_id) {
        case 1:
        case 100:
        case 101:
        case 102:
        case 103:
        case 104:
        case 106:
        case 108:
        case 109:
        case 110:
        case 111:
        case 112:
        case 113:
        case 114:
        case 115:
        case 116:
        case 117:
        case 118:
        case 120:
        case 121:
        case 122:
        case 123:
            return true;
        default:
            return false;
    }
}

std::optional<GenericItem> parse_generic_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    if (frame.offset > bytes.size() || frame_end > bytes.size())
        return std::nullopt;
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!has(bytes, pos, 20))
        return std::nullopt;
    const auto outer_domain = fourcc(bytes, pos + 8);
    const auto outer_id = u32le(bytes, pos + 12);
    if (!domain_tag(bytes, pos + 8) ||
            factory_has_concrete_item(outer_domain, outer_id)) {
        return std::nullopt;
    }

    GenericItem out;
    out.frame_index = frame_index;
    const auto outer_size = static_cast<std::size_t>(u64le(bytes, pos));
    std::size_t adjusted_size = outer_size;
    while (has(bytes, pos, 20) && pos + 20 <= frame_end &&
            domain_tag(bytes, pos + 8) &&
            !(tag_is(bytes, pos + 8, "DSIN") && u32le(bytes, pos + 12) == 1)) {
        out.derived_records.push_back(
                { u64le(bytes, pos), fourcc(bytes, pos + 8),
                        u32le(bytes, pos + 12), u32le(bytes, pos + 16) });
        if (adjusted_size < 20) {
            doc.errors.push_back(
                    { pos, "GenericItem derived record size underflow" });
            return std::nullopt;
        }
        adjusted_size -= 20;
        pos += 20;
    }
    if (out.derived_records.empty() || !has(bytes, pos, 24) ||
            pos + 24 > frame_end || !tag_is(bytes, pos + 8, "DSIN") ||
            u32le(bytes, pos + 12) != 1) {
        doc.errors.push_back(
                { pos, "GenericItem is missing its DSIN:1 base record" });
        return std::nullopt;
    }
    const auto item_size = static_cast<std::size_t>(u64le(bytes, pos));
    if (item_size != 24 || adjusted_size < item_size) {
        doc.errors.push_back(
                { pos, "GenericItem DSIN:1 record must be 24 bytes" });
        return std::nullopt;
    }
    if (u32le(bytes, pos + 16) != 1) {
        doc.errors.push_back(
                { pos + 16, "unsupported GenericItem inherited Item version" });
        return std::nullopt;
    }
    out.base_payload_version = u32le(bytes, pos + 20);
    if (out.base_payload_version != 1) {
        doc.errors.push_back(
                { pos + 20, "unsupported GenericItem Item payload version" });
        return std::nullopt;
    }
    const auto raw_size = adjusted_size - item_size;
    const auto raw_start = pos + item_size;
    if (!has(bytes, raw_start, raw_size + 8) ||
            raw_start + raw_size + 8 > frame_end) {
        doc.errors.push_back(
                { raw_start, "GenericItem derived payload is out of bounds" });
        return std::nullopt;
    }
    const auto container = raw_start + raw_size;
    // the outer record ends where Item's child container starts
    if (frame.offset + kCommonHeaderSize + outer_size != container) {
        doc.errors.push_back(
                { container, "GenericItem outer record boundary mismatch" });
        return std::nullopt;
    }
    out.derived_payload.assign(
            bytes.begin() + static_cast<std::ptrdiff_t>(raw_start),
            bytes.begin() + static_cast<std::ptrdiff_t>(container));
    out.container_version = u32le(bytes, container);
    out.child_count = u32le(bytes, container + 4);
    if (out.container_version != 1) {
        doc.errors.push_back({ container,
                "unsupported GenericItem child container version" });
        return std::nullopt;
    }
    return out;
}

std::optional<ModuleItem> parse_module_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    if (!frame.payload_prefix_size)
        return std::nullopt;
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto payload_start = frame.offset + kOpaqueProbePrefixSize;
    if (*frame.payload_prefix_size > frame_end - payload_start) {
        doc.errors.push_back(
                { frame.offset + 0x28, "Module payload is out of bounds" });
        return std::nullopt;
    }
    const auto payload_end =
            payload_start +
            static_cast<std::size_t>(*frame.payload_prefix_size);
    const auto module_record = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, module_record, 122, payload_end, doc))
        return std::nullopt;
    const auto module_size =
            static_cast<std::size_t>(u64le(bytes, module_record));
    if (module_size < 60 || module_size > payload_end - module_record) {
        doc.errors.push_back({ module_record,
                "Module inherited record size is out of bounds" });
        return std::nullopt;
    }
    const auto container_offset = module_record + module_size;
    const auto auth_record = module_record + 20;
    if (!inherited_record(bytes, auth_record, 106, container_offset, doc))
        return std::nullopt;
    const auto auth_size = static_cast<std::size_t>(u64le(bytes, auth_record));
    if (auth_size < 40 || auth_size > container_offset - auth_record) {
        doc.errors.push_back({ auth_record,
                "Module Authorization record size is out of bounds" });
        return std::nullopt;
    }
    const auto auth_end = auth_record + auth_size;
    const auto item_record = auth_record + 20;
    auto authorization =
            parse_authorization_payload(bytes, item_record, auth_end, doc);
    if (!authorization)
        return std::nullopt;
    ModuleItem out;
    out.frame_index = frame_index;
    out.base_payload_version = authorization->base_payload_version;
    out.authorization_payload_version = authorization->payload_version;
    out.authorization_level = authorization->level;
    out.license_info = std::move(authorization->license_info);
    std::size_t pos = auth_end;
    if (!has(bytes, pos, 16) || pos + 16 > container_offset) {
        doc.errors.push_back({ pos, "truncated Module payload" });
        return std::nullopt;
    }
    out.module_payload_version = u32le(bytes, pos);
    pos += 4;
    out.authoring_application_id = u32le(bytes, pos);
    pos += 4;
    out.authoring_info_version = u32le(bytes, pos);
    pos += 4;
    if (out.module_payload_version != 1 || out.authoring_info_version != 1) {
        doc.errors.push_back(
                { pos - 12, "unsupported Module payload version" });
        return std::nullopt;
    }
    auto authoring_version = read_wstring(bytes, pos, container_offset, doc);
    if (!authoring_version)
        return std::nullopt;
    out.authoring_application_version = std::move(*authoring_version);
    if (!has(bytes, pos, 4) || pos + 4 > container_offset) {
        doc.errors.push_back({ pos, "truncated Module flags" });
        return std::nullopt;
    }
    out.module_flags = u32le(bytes, pos);
    pos += 4;
    if (pos != container_offset || !has(bytes, pos, 8) ||
            pos + 8 > payload_end) {
        doc.errors.push_back(
                { pos, "invalid Module child-container boundary" });
        return std::nullopt;
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1 || pos != payload_end) {
        doc.errors.push_back({ pos - 8, "unsupported Module child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<ModuleBankItem> parse_module_bank_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    if (!frame.payload_prefix_size)
        return std::nullopt;
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto payload_start = frame.offset + kOpaqueProbePrefixSize;
    if (*frame.payload_prefix_size > frame_end - payload_start)
        return std::nullopt;
    const auto payload_end =
            payload_start +
            static_cast<std::size_t>(*frame.payload_prefix_size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 123, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 8) || pos + 8 > payload_end) {
        doc.errors.push_back({ pos, "truncated ModuleBank payload" });
        return std::nullopt;
    }
    ModuleBankItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported ModuleBank payload version" });
        return std::nullopt;
    }
    auto name = read_wstring(bytes, pos, payload_end, doc);
    if (!name)
        return std::nullopt;
    out.name = std::move(*name);
    if (!has(bytes, pos, 8) || pos + 8 > payload_end) {
        doc.errors.push_back({ pos, "truncated ModuleBank child container" });
        return std::nullopt;
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1 || pos != payload_end) {
        doc.errors.push_back(
                { pos - 8, "unsupported ModuleBank child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<BankItem> parse_bank_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc) {
    if (!frame.payload_prefix_size)
        return std::nullopt;
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto payload_start = frame.offset + kOpaqueProbePrefixSize;
    if (*frame.payload_prefix_size > frame_end - payload_start)
        return std::nullopt;
    const auto payload_end =
            payload_start +
            static_cast<std::size_t>(*frame.payload_prefix_size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 100, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 8) || pos + 8 > payload_end) {
        doc.errors.push_back({ pos, "truncated Bank payload" });
        return std::nullopt;
    }
    BankItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.bank_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.bank_payload_version != 1) {
        doc.errors.push_back({ pos - 8, "unsupported Bank payload version" });
        return std::nullopt;
    }
    auto name = read_wstring(bytes, pos, payload_end, doc);
    if (!name)
        return std::nullopt;
    out.name = std::move(*name);
    if (!has(bytes, pos, 8) || pos + 8 > payload_end) {
        doc.errors.push_back({ pos, "truncated Bank child container" });
        return std::nullopt;
    }
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1 || pos != payload_end) {
        doc.errors.push_back({ pos - 8, "unsupported Bank child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<BankContainerItem> parse_bank_container_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    if (!frame.payload_prefix_size)
        return std::nullopt;
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto payload_start = frame.offset + kOpaqueProbePrefixSize;
    if (*frame.payload_prefix_size > frame_end - payload_start)
        return std::nullopt;
    const auto payload_end =
            payload_start +
            static_cast<std::size_t>(*frame.payload_prefix_size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 102, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 20) || pos + 20 > payload_end) {
        doc.errors.push_back({ pos, "truncated BankContainer payload" });
        return std::nullopt;
    }
    BankContainerItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.container_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.container_payload_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported BankContainer payload version" });
        return std::nullopt;
    }
    out.selected_bank_index = u32le(bytes, pos);
    pos += 4;
    out.child_container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.child_container_version != 1 || pos != payload_end) {
        doc.errors.push_back(
                { pos - 8, "unsupported BankContainer child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<PresetContainerItem> parse_preset_container_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    if (!frame.payload_prefix_size)
        return std::nullopt;
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    const auto payload_start = frame.offset + kOpaqueProbePrefixSize;
    if (*frame.payload_prefix_size > frame_end - payload_start)
        return std::nullopt;
    const auto payload_end =
            payload_start +
            static_cast<std::size_t>(*frame.payload_prefix_size);
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 103, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 16) || pos + 16 > payload_end) {
        doc.errors.push_back({ pos, "truncated PresetContainer payload" });
        return std::nullopt;
    }
    PresetContainerItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.container_payload_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.container_payload_version != 1) {
        doc.errors.push_back(
                { pos - 8, "unsupported PresetContainer payload version" });
        return std::nullopt;
    }
    out.child_container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.child_container_version != 1 || pos != payload_end) {
        doc.errors.push_back(
                { pos - 8, "unsupported PresetContainer child container" });
        return std::nullopt;
    }
    return out;
}

std::optional<PresetChunkItem> parse_preset_chunk_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc) {
    const auto frame_end = frame.offset + static_cast<std::size_t>(frame.size);
    // runs to the end of the frame after two inherited records, the U64 at
    // +0x28 is part of the first one, NOT a length
    const auto payload_end = frame_end;
    std::size_t pos = frame.offset + kCommonHeaderSize;
    if (!inherited_record(bytes, pos, 109, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!inherited_record(bytes, pos, 1, payload_end, doc))
        return std::nullopt;
    pos += 20;
    if (!has(bytes, pos, 24) || pos + 24 > payload_end) {
        doc.errors.push_back({ pos, "truncated PresetChunkItem header" });
        return std::nullopt;
    }
    PresetChunkItem out;
    out.frame_index = frame_index;
    out.base_payload_version = u32le(bytes, pos);
    pos += 4;
    out.item_payload_version = u32le(bytes, pos);
    pos += 4;
    out.preset_chunk_version = u32le(bytes, pos);
    pos += 4;
    out.binary_chunk_version = u32le(bytes, pos);
    pos += 4;
    if (out.base_payload_version != 1 || out.item_payload_version != 1 ||
            out.preset_chunk_version != 1 || out.binary_chunk_version != 1) {
        doc.errors.push_back({ pos - 16,
                "unsupported PresetChunkItem/BinaryChunk version" });
        return std::nullopt;
    }
    out.binary_data_size = u64le(bytes, pos);
    pos += 8;
    if (out.binary_data_size > payload_end - pos ||
            payload_end - pos - out.binary_data_size < 16) {
        doc.errors.push_back({ pos - 8, "BinaryChunk size is out of bounds" });
        return std::nullopt;
    }
    out.binary_data_offset = pos;
    pos += static_cast<std::size_t>(out.binary_data_size);
    out.context_id = u32le(bytes, pos);
    pos += 4;
    out.item_context_id = u32le(bytes, pos);
    pos += 4;
    out.container_version = u32le(bytes, pos);
    pos += 4;
    out.child_count = u32le(bytes, pos);
    pos += 4;
    if (out.container_version != 1 || out.child_count != 0) {
        doc.errors.push_back(
                { pos - 8, "unsupported PresetChunkItem child container" });
        return std::nullopt;
    }
    if (pos != payload_end) {
        doc.errors.push_back({ pos, "PresetChunkItem payload does not end at "
                                    "its declared boundary" });
        return std::nullopt;
    }
    return out;
}

} // namespace detail::patch

} // namespace libnki
