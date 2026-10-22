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

bool looks_like_version(const std::string &s) {
    if (s.empty())
        return false;
    bool dot = false;
    for (const char c : s) {
        if (c == '.')
            dot = true;
        else if (c < '0' || c > '9')
            return false;
    }
    return dot;
}

bool alphabetic(const std::string &s) {
    return std::any_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    });
}

void extract_metadata(std::span<const std::byte> bytes, Metadata &meta) {
    struct StringAt {
        std::size_t off;
        std::string value;
    };
    std::vector<StringAt> strings;
    const auto limit = std::min(bytes.size(), kMetadataScanLimit);
    for (std::size_t off = kCommonHeaderSize; off + 8 <= limit;) {
        if (auto value = pascal_utf16(bytes, off, limit)) {
            strings.push_back({ off, *value });
            off += 4 + static_cast<std::size_t>(u32le(bytes, off)) * 2;
        } else {
            ++off;
        }
    }

    static constexpr std::array products = { "Kontakt", "KontaktInstrument",
        "Massive", "Massive X", "Absynth", "FM8", "Reaktor", "Guitar Rig",
        "Battery" };
    std::optional<std::size_t> product_off;
    std::optional<std::size_t> version_off;
    for (const auto &item : strings) {
        if (!meta.product && std::find(products.begin(), products.end(),
                                     item.value) != products.end()) {
            meta.product =
                    item.value == "KontaktInstrument" ? "Kontakt" : item.value;
            product_off = item.off;
        }
        if (!meta.version && looks_like_version(item.value)) {
            meta.version = item.value;
            version_off = item.off;
        }
    }
    for (std::size_t i = 0; i < strings.size(); ++i) {
        const auto &item = strings[i];
        if (version_off && item.off <= *version_off)
            continue;
        if (product_off && item.off >= *product_off)
            break;
        if (!alphabetic(item.value) || looks_like_version(item.value))
            continue;
        meta.name = item.value;
        if (i + 1 < strings.size())
            meta.author = strings[i + 1].value;
        if (i + 2 < strings.size())
            meta.vendor = strings[i + 2].value;
        if (i + 3 < strings.size())
            meta.description = strings[i + 3].value;
        break;
    }
}

void walk_frame(std::span<const std::byte> bytes, std::size_t off,
        std::size_t depth, std::size_t parent_end, Document &doc) {
    if (depth > kMaxDepth) {
        doc.errors.push_back({ off, "frame nesting exceeds safety limit" });
        return;
    }
    if (doc.frames.size() >= kMaxFrames) {
        doc.errors.push_back({ off, "frame count exceeds safety limit" });
        return;
    }
    if (!has(bytes, off, kOpaqueProbePrefixSize)) {
        doc.errors.push_back({ off, "truncated hsin frame header" });
        return;
    }
    const auto frame_size = u64le(bytes, off);
    const auto payload_prefix_size = u64le(bytes, off + 0x28);
    if (!tag_is(bytes, off + 0x0c, "hsin")) {
        doc.errors.push_back({ off + 0x0c, "missing hsin frame marker" });
        return;
    }
    if (frame_size < kCommonHeaderSize || frame_size > parent_end - off ||
            frame_size > bytes.size() - off) {
        doc.errors.push_back({ off, "frame size is out of bounds" });
        return;
    }
    const auto frame_end = off + static_cast<std::size_t>(frame_size);
    const auto data_start = off + kOpaqueProbePrefixSize;
    if (payload_prefix_size > frame_end - data_start) {
        doc.errors.push_back(
                { off + 0x28, "opaque payload prefix size is out of bounds" });
        return;
    }
    const auto data_end =
            data_start + static_cast<std::size_t>(payload_prefix_size);
    std::optional<std::uint32_t> item_id;
    std::size_t pos = data_start;
    while (pos + 20 <= data_end && domain_tag(bytes, pos)) {
        const auto id = u32le(bytes, pos + 4);
        if (!item_id)
            item_id = id;
        if (id == 1)
            break;
        const auto inner = u64le(bytes, pos + 12);
        if (inner > data_end - (pos + 20)) {
            doc.errors.push_back(
                    { pos + 12, "stack item size is out of bounds" });
            break;
        }
        pos += 20 + static_cast<std::size_t>(inner);
    }
    doc.frames.push_back({ off, frame_size, u32le(bytes, off + 0x08),
            u32le(bytes, off + 0x10), u32le(bytes, off + 0x14),
            hex(bytes.subspan(off + 0x18, 16)), payload_prefix_size, item_id,
            depth });

    pos = data_end;
    while (pos < frame_end) {
        if (pos + 20 > frame_end || !domain_tag(bytes, pos + 4)) {
            doc.errors.push_back({ pos, "invalid child frame prefix" });
            return;
        }
        const auto child_off = pos + 12;
        if (!has(bytes, child_off, 8)) {
            doc.errors.push_back({ child_off, "truncated child frame" });
            return;
        }
        const auto child_size = u64le(bytes, child_off);
        if (child_size < kCommonHeaderSize ||
                child_size > frame_end - child_off) {
            doc.errors.push_back(
                    { child_off, "child frame size is out of bounds" });
            return;
        }
        walk_frame(bytes, child_off, depth + 1, frame_end, doc);
        pos = child_off + static_cast<std::size_t>(child_size);
    }
}

} // namespace detail::patch

const char *format_name(Format format) noexcept {
    switch (format) {
        case Format::nisound_hsin:
            return "nisound-hsin";
        case Format::legacy_ni_fc_mtd:
            return "legacy-ni-fc-mtd";
        case Format::monolith_hitemfolder:
            return "monolith-hitemfolder";
        default:
            return "unknown";
    }
}

const char *generation_name(PatchGeneration generation) noexcept {
    switch (generation) {
        case PatchGeneration::k1:
            return "k1";
        case PatchGeneration::k2:
            return "k2";
        case PatchGeneration::k42:
            return "k42";
        case PatchGeneration::k43_nisound:
            return "k43-nisound";
        default:
            return "unknown";
    }
}

const char *protected_item_kind_name(ProtectedItemKind kind) noexcept {
    switch (kind) {
        case ProtectedItemKind::compressed_subtree:
            return "compressed-subtree";
        case ProtectedItemKind::encryption_item:
            return "encryption-item";
        case ProtectedItemKind::app_specific:
            return "app-specific";
    }
    return "unknown";
}

PatchGeneration detect_patch_generation(
        std::span<const std::byte> bytes) noexcept {
    if (has(bytes, 0, kCommonHeaderSize) && tag_is(bytes, 0x0c, "hsin")) {
        return PatchGeneration::k43_nisound;
    }
    if (!has(bytes, 0, 10))
        return PatchGeneration::unknown;
    const auto raw_magic = u32le(bytes, 0);
    const bool swapped = !legacy_patch_magic(raw_magic) &&
                         legacy_patch_magic(byteswap32(raw_magic));
    if (!legacy_patch_magic(raw_magic) && !swapped)
        return PatchGeneration::unknown;
    auto revision = u16le(bytes, 8);
    if (swapped)
        revision =
                static_cast<std::uint16_t>((revision >> 8U) | (revision << 8U));
    if (revision <= 0x00ffU)
        return PatchGeneration::k1;
    if (revision <= 0x010fU)
        return PatchGeneration::k2;
    return PatchGeneration::k42;
}

Support supports_zone_struct_version(std::uint16_t version) noexcept {
    return ((version >= 0x92 && version <= 0x95) ||
                   (version >= 0x97 && version <= 0x9c))
                   ? Support::supported
                   : Support::unsupported;
}

Support supports_file_table_version(std::uint16_t version) noexcept {
    return (version == 2 || version == 3) ? Support::supported
                                          : Support::unsupported;
}

Support supports_parameter_array_version(std::uint16_t version) noexcept {
    return version <= 0x13 ? Support::supported : Support::unsupported;
}

Support supports_source_mode_version(std::uint16_t version) noexcept {
    return (version >= 0x100 && version <= 0x106) ? Support::supported
                                                  : Support::unsupported;
}

Support supports_program_struct_version(std::uint16_t version) noexcept {
    return (version == 0x80 || version == 0x82 ||
                   (version >= 0x90 && version <= 0x92) ||
                   (version >= 0xa0 && version <= 0xb5))
                   ? Support::supported
                   : Support::unsupported;
}

Support supports_par_script_version(std::uint16_t version) noexcept {
    return (version == 0x50 || version == 0x60) ? Support::supported
                                                : Support::unsupported;
}

Support supports_group_struct_version(std::uint16_t version) noexcept {
    return (version >= 0x90 && version <= 0x96) ? Support::supported
                                                : Support::unsupported;
}

Document parse(std::span<const std::byte> bytes,
        std::span<const std::byte> encryption_key) {
    Document doc;
    doc.actual_size = bytes.size();
    doc.generation = detect_patch_generation(bytes);
    auto append_modern_patch = [&](std::span<const std::byte> patch,
                                       std::optional<std::size_t>
                                               preset_chunk_index,
                                       bool context_ids_enabled,
                                       std::optional<std::uint16_t>
                                               artifact_kind = std::nullopt) {
        ModernPatchPayload patch_payload;
        patch_payload.preset_chunk_index = preset_chunk_index;
        patch_payload.artifact_kind = artifact_kind;
        try {
            patch_payload.chunks = scan_chunk_sequence(patch);
            for (const auto &chunk : patch_payload.chunks) {
                try {
                    if (artifact_kind) {
                        std::optional<std::uint16_t> required_kind;
                        if (chunk.type == 3)
                            required_kind = 0; // NKM / bank
                        else if (chunk.type == 0x28)
                            required_kind = 1; // NKI / program
                        else if (chunk.type == 0x29)
                            required_kind = 2; // NKB / program container
                        else if (chunk.type == 0x30)
                            required_kind = 3; // NKP / preset payload
                        else if (chunk.type == 0x2f)
                            required_kind = 4; // NKG / group complete ser
                        // when we read a zone or output chunk (0x2e/0x3e),
                        // we don't check artifact kinds 5/6
                        else if (chunk.type == 0x51 || chunk.type == 0x4f)
                            required_kind = 7; // NKSN
                        if (required_kind && *required_kind != *artifact_kind) {
                            patch_payload.errors.push_back(
                                    "BPatchHeaderV42 artifact kind " +
                                    std::to_string(*artifact_kind) +
                                    " does not route chunk type " +
                                    std::to_string(chunk.type));
                            continue;
                        }
                    }
                    if (chunk.type == 3 && !patch_payload.bank) {
                        patch_payload.bank = parse_bank(
                                patch.subspan(0, chunk.payload_offset +
                                                         chunk.payload_size),
                                chunk, context_ids_enabled);
                    } else if (chunk.type == 0x28 && !patch_payload.program) {
                        patch_payload.program = parse_program(
                                patch.subspan(0, chunk.payload_offset +
                                                         chunk.payload_size),
                                chunk.payload_offset, context_ids_enabled);
                    } else if (chunk.type == 0x29 &&
                               !patch_payload.program_container) {
                        patch_payload.program_container =
                                parse_program_container(
                                        patch.subspan(
                                                0, chunk.payload_offset +
                                                           chunk.payload_size),
                                        chunk, context_ids_enabled);
                    } else if (chunk.type == 0x30 && !patch_payload.preset) {
                        patch_payload.preset = parse_preset(
                                patch.subspan(0, chunk.payload_offset +
                                                         chunk.payload_size),
                                chunk, context_ids_enabled);
                    } else if (chunk.type == 0x2f &&
                               !patch_payload.group_complete) {
                        patch_payload.group_complete = parse_group_complete(
                                patch.subspan(0, chunk.payload_offset +
                                                         chunk.payload_size),
                                chunk);
                    } else if (chunk.type == 0x2e &&
                               !patch_payload.zone_array) {
                        auto zones = parse_zone_array(
                                patch.subspan(0, chunk.payload_offset +
                                                         chunk.payload_size),
                                chunk.payload_offset);
                        if (zones.end_offset !=
                                chunk.payload_offset + chunk.payload_size) {
                            throw std::runtime_error(
                                    "BZoneArraySer has trailing bytes");
                        }
                        patch_payload.zone_array = std::move(zones);
                    } else if (chunk.type == 0x3e &&
                               !patch_payload.output_configuration) {
                        patch_payload.output_configuration =
                                parse_output_configuration(
                                        patch.subspan(
                                                0, chunk.payload_offset +
                                                           chunk.payload_size),
                                        chunk);
                    } else if (chunk.type == 0x51 &&
                               !patch_payload.snapshot_metadata) {
                        patch_payload.snapshot_metadata =
                                parse_snapshot_metadata(
                                        patch.subspan(
                                                0, chunk.payload_offset +
                                                           chunk.payload_size),
                                        chunk);
                    } else if (chunk.type == 0x4f &&
                               !patch_payload.standalone_snapshot) {
                        auto snapshot = parse_snapshot(
                                patch.subspan(0, chunk.payload_offset +
                                                         chunk.payload_size),
                                chunk.payload_offset, true);
                        if (snapshot.end_offset !=
                                chunk.payload_offset + chunk.payload_size) {
                            throw std::runtime_error(
                                    "standalone BSnapshot ends at " +
                                    std::to_string(snapshot.end_offset) +
                                    ", expected " +
                                    std::to_string(chunk.payload_offset +
                                                   chunk.payload_size) +
                                    ", version " +
                                    std::to_string(
                                            snapshot.serializable.version) +
                                    ", discriminator " +
                                    std::to_string(
                                            snapshot.version_3_discriminator
                                                    .value_or(-1)) +
                                    ", groups " +
                                    std::to_string(snapshot.groups.size()) +
                                    ", third-effect " +
                                    (snapshot.third_effect_array ? "present"
                                                                 : "absent") +
                                    ", string counts [" +
                                    std::to_string(
                                            snapshot.string_arrays[0].size()) +
                                    "," +
                                    std::to_string(
                                            snapshot.string_arrays[1].size()) +
                                    "," +
                                    std::to_string(
                                            snapshot.string_arrays[2].size()) +
                                    "," +
                                    std::to_string(
                                            snapshot.string_arrays[3].size()) +
                                    "," +
                                    std::to_string(
                                            snapshot.string_arrays[4].size()) +
                                    "]");
                        }
                        patch_payload.standalone_snapshot = std::move(snapshot);
                    } else if (chunk.type == 0x4b &&
                               !patch_payload.file_table) {
                        if (chunk.payload_size < 2) {
                            throw std::runtime_error(
                                    "truncated filename-table version");
                        }
                        const auto version = u16le(patch, chunk.payload_offset);
                        if (version == 3) {
                            patch_payload.file_table =
                                    parse_file_table_v3(patch, chunk);
                        } else if (version == 2) {
                            patch_payload.file_table =
                                    parse_file_table_v2(patch, chunk);
                        } else {
                            throw std::runtime_error(
                                    "unsupported filename-table version " +
                                    std::to_string(version));
                        }
                    } else if (chunk.type == 0x3d &&
                               !patch_payload.file_table) {
                        patch_payload.file_table =
                                parse_file_table_pre_k51(patch, chunk);
                    }
                } catch (const std::exception &error) {
                    patch_payload.errors.push_back("chunk type " +
                                                   std::to_string(chunk.type) +
                                                   ": " + error.what());
                }
            }
        } catch (const std::exception &error) {
            patch_payload.errors.push_back(error.what());
        }
        doc.modern_patches.push_back(std::move(patch_payload));
    };
    const auto monolith_magic_at = [&](std::size_t offset) {
        return has(bytes, offset, 4) &&
               u32le(bytes, offset) == MonolithTable::table_magic;
    };
    const auto monolith_root =
            monolith_magic_at(0) ? std::optional<std::size_t>{ 0 }
            : monolith_magic_at(K42PatchHeader::serialized_size)
                    ? std::optional<
                              std::size_t>{ K42PatchHeader::serialized_size }
                    : std::nullopt;
    if (monolith_root) {
        doc.format = Format::monolith_hitemfolder;
        try {
            doc.resource_monolith =
                    parse_monolith_container(bytes, *monolith_root);
        } catch (const std::exception &error) {
            doc.errors.push_back({ *monolith_root, error.what() });
        }
        return doc;
    }
    if (has(bytes, 0, 12) && tag_is(bytes, 0, "/\\ N")) {
        doc.format = Format::legacy_ni_fc_mtd;
        return doc;
    }
    if (doc.generation == PatchGeneration::k42) {
        doc.format = Format::legacy_ni_fc_mtd;
        try {
            doc.k42_patch_data =
                    parse_k42_patch_data(bytes, std::nullopt, encryption_key);
            append_modern_patch(doc.k42_patch_data->decompressed, std::nullopt,
                    false, doc.k42_patch_data->header.artifact_kind);
        } catch (const std::exception &error) {
            doc.errors.push_back({ 0, error.what() });
        }
        return doc;
    }
    if (doc.generation == PatchGeneration::k2) {
        doc.format = Format::legacy_ni_fc_mtd;
        try {
            doc.k2_patch_data =
                    parse_k2_patch_data(bytes, std::nullopt, encryption_key);
        } catch (const std::exception &error) {
            doc.errors.push_back({ 0, error.what() });
        }
        return doc;
    }
    if (doc.generation == PatchGeneration::k1) {
        doc.format = Format::legacy_ni_fc_mtd;
        try {
            doc.k1_patch_data = parse_k1_patch_data(bytes);
        } catch (const std::exception &error) {
            doc.errors.push_back({ 0, error.what() });
        }
        return doc;
    }
    if (!has(bytes, 0, kCommonHeaderSize) || !tag_is(bytes, 0x0c, "hsin")) {
        doc.errors.push_back({ 0, "unrecognized Kontakt/NI container" });
        return doc;
    }
    doc.format = Format::nisound_hsin;
    doc.declared_size = u64le(bytes, 0);
    if (u32le(bytes, 0x08) != 1) {
        doc.errors.push_back(
                { 0x08, "unsupported NISound item header version" });
    }
    if (has(bytes, 0x18, 16))
        doc.identity_hex = hex(bytes.subspan(0x18, 16));
    walk_frame(bytes, 0, 0, bytes.size(), doc);
    if (!doc.frames.empty() && doc.frames[0].item_id &&
            *doc.frames[0].item_id == 118) {
        doc.repository_root = parse_repository_root(bytes, doc.frames[0], doc);
    }
    for (std::size_t i = 0; i < doc.frames.size(); ++i) {
        const auto &frame = doc.frames[i];
        if (!frame.item_id)
            continue;
        if (*frame.item_id == 1) {
            if (auto item = parse_base_item(bytes, frame, i, doc)) {
                doc.base_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 3) {
            if (auto preset = parse_kontakt_preset(bytes, frame, i, doc)) {
                doc.presets.push_back(*preset);
            }
        } else if (*frame.item_id == 101) {
            if (auto preset = parse_preset_item(bytes, frame, i, doc)) {
                doc.presets.push_back(std::move(*preset));
            }
        }
        if (*frame.item_id == 108) {
            if (auto item = parse_sound_info(bytes, frame, i, doc))
                doc.sound_info_items.push_back(*item);
        } else if (*frame.item_id == 120) {
            if (auto item = parse_automation_parameters(bytes, frame, i, doc))
                doc.automation_parameters.push_back(*item);
        } else if (*frame.item_id == 121) {
            if (auto item = parse_controller_assignments(
                        bytes, frame, i, doc)) {
                doc.controller_assignments.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 4) {
            if (auto item = parse_bnisound_header(bytes, frame, i, doc))
                doc.bnisound_headers.push_back(*item);
        } else if (*frame.item_id == 112) {
            if (auto item = parse_audio_sample_item(bytes, frame, i, doc)) {
                doc.audio_sample_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 110) {
            if (auto item = parse_external_file_reference_item(
                        bytes, frame, i, doc)) {
                doc.external_file_references.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 111) {
            if (auto item = parse_resources_item(bytes, frame, i, doc)) {
                doc.resources_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 113) {
            if (auto item = parse_internal_resource_reference_item(
                        bytes, frame, i, doc)) {
                doc.internal_resource_references.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 114) {
            if (auto item = parse_picture_item(bytes, frame, i, doc)) {
                doc.picture_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 104) {
            if (auto item = parse_binary_chunk_item(bytes, frame, i, doc)) {
                doc.binary_chunk_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 100) {
            if (auto item = parse_bank_item(bytes, frame, i, doc)) {
                doc.bank_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 102) {
            if (auto item = parse_bank_container_item(bytes, frame, i, doc)) {
                doc.bank_container_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 103) {
            if (auto item = parse_preset_container_item(bytes, frame, i, doc)) {
                doc.preset_container_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 106) {
            if (auto item = parse_authorization_item(bytes, frame, i, doc)) {
                doc.authorization_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 122) {
            if (auto item = parse_module_item(bytes, frame, i, doc)) {
                doc.module_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 123) {
            if (auto item = parse_module_bank_item(bytes, frame, i, doc)) {
                doc.module_bank_items.push_back(std::move(*item));
            }
        } else if (*frame.item_id == 109) {
            if (auto item = parse_preset_chunk_item(bytes, frame, i, doc))
                doc.preset_chunks.push_back(*item);
        } else if (auto item = parse_generic_item(bytes, frame, i, doc)) {
            doc.generic_items.push_back(std::move(*item));
        }
        switch (*frame.item_id) {
            case static_cast<std::uint32_t>(
                    ProtectedItemKind::compressed_subtree):
            case static_cast<std::uint32_t>(ProtectedItemKind::encryption_item):
            case static_cast<std::uint32_t>(ProtectedItemKind::app_specific):
                if (auto item = parse_protected_item(bytes, frame, i,
                            static_cast<ProtectedItemKind>(*frame.item_id),
                            doc)) {
                    doc.protected_items.push_back(*item);
                }
                break;
            default:
                break;
        }
    }
    for (std::size_t i = 0; i < doc.preset_chunks.size(); ++i) {
        const auto &preset_chunk = doc.preset_chunks[i];
        const auto patch = bytes.subspan(preset_chunk.binary_data_offset,
                static_cast<std::size_t>(preset_chunk.binary_data_size));
        // when we load an instrument file, we leave context IDs disabled, so
        // v0x11 parameter-array entries have no optional per-slot S32 here
        const auto artifact_kind =
                doc.bnisound_headers.empty()
                        ? std::optional<std::uint16_t>{}
                        : std::optional<std::uint16_t>{
                              doc.bnisound_headers.front().artifact_kind
                          };
        append_modern_patch(patch, i, false, artifact_kind);
    }
    extract_metadata(bytes, doc.metadata);
    return doc;
}

Document parse_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input)
        throw std::runtime_error("cannot open " + path.string());
    const auto end = input.tellg();
    if (end < 0)
        throw std::runtime_error("cannot size " + path.string());
    if (static_cast<std::uint64_t>(end) >
            std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("file is too large for this process");
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    input.seekg(0);
    if (!bytes.empty() &&
            !input.read(reinterpret_cast<char *>(bytes.data()), end)) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return parse(bytes);
}

} // namespace libnki
