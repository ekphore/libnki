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

SerializableHeader parse_serializable_header(std::span<const std::byte> bytes,
        std::size_t offset, bool expected_structured,
        std::uint16_t maximum_version) {
    if (!has(bytes, offset, 3))
        throw std::runtime_error("truncated serializable header");
    SerializableHeader header;
    header.offset = offset;
    header.structured = u8(bytes, offset) != 0;
    header.version = u16le(bytes, offset + 1);
    header.payload_offset = offset + 3;
    if (header.structured != expected_structured) {
        throw std::runtime_error(
                "serializable structured flag does not match object type");
    }
    if (header.version > maximum_version) {
        throw std::runtime_error("serializable version " +
                                 std::to_string(header.version) +
                                 " at offset " + std::to_string(offset) +
                                 " is newer than object maximum " +
                                 std::to_string(maximum_version));
    }
    return header;
}

PresetImplPrefix parse_preset_impl_prefix(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x30)
        throw std::invalid_argument("PresetImpl chunk type must be 0x30");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("PresetImpl chunk is out of bounds");
    }
    PresetImplPrefix prefix;
    prefix.chunk = chunk;
    prefix.serializable =
            parse_serializable_header(bytes, chunk.payload_offset, false, 1);
    if (prefix.serializable.version != 1) {
        throw std::runtime_error("unsupported PresetImpl version");
    }
    const auto end = chunk.payload_offset + chunk.payload_size;
    auto pos = prefix.serializable.payload_offset;
    if (!has(bytes, pos, 2) || pos + 2 > end) {
        throw std::runtime_error("truncated PresetImpl payload prefix");
    }
    prefix.saved_group_iteration_flag = u8(bytes, pos) != 0;
    prefix.saved_preset_kind = u8(bytes, pos + 1);
    prefix.implementation_payload_offset = pos + 2;
    return prefix;
}

GroupArrayHeader parse_snapshot_group_array_header(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x33)
        throw std::invalid_argument("BSnapshot group chunk type must be 0x33");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset ||
            chunk.payload_size < 4) {
        throw std::invalid_argument("BSnapshot group chunk is out of bounds");
    }
    GroupArrayHeader header;
    header.chunk = chunk;
    header.group_count =
            static_cast<std::int32_t>(u32le(bytes, chunk.payload_offset));
    if (header.group_count < 0)
        throw std::runtime_error("negative BSnapshot group count");
    header.groups_offset = chunk.payload_offset + 4;
    if (static_cast<std::uint32_t>(header.group_count) >
            chunk.payload_offset + chunk.payload_size - header.groups_offset) {
        throw std::runtime_error("BSnapshot group count is out of bounds");
    }
    return header;
}

GroupSnapshotPrefix parse_group_snapshot_prefix(
        std::span<const std::byte> bytes, std::size_t offset) {
    GroupSnapshotPrefix prefix;
    prefix.serializable = parse_serializable_header(bytes, offset, false, 4);
    if (prefix.serializable.version < 1) {
        throw std::runtime_error("unsupported BGroupSnapshot version");
    }
    auto pos = prefix.serializable.payload_offset;
    if (!has(bytes, pos, 24))
        throw std::runtime_error("truncated BGroupSnapshot prefix");
    for (auto &value : prefix.leading_f32) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    for (auto &value : prefix.flags)
        value = u8(bytes, pos++) != 0;
    prefix.field_after_flags = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    prefix.mode = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (prefix.mode < 0 || prefix.mode > 2) {
        throw std::runtime_error("BGroupSnapshot mode is out of range");
    }
    prefix.child_serializables_offset = pos;
    return prefix;
}

ParameterArrayPrefix parse_parameter_array_prefix(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled) {
    ParameterArrayPrefix prefix;
    prefix.serializable = parse_serializable_header(bytes, offset, false, 0x13);
    auto pos = prefix.serializable.payload_offset;
    if (prefix.serializable.version < 0x13) {
        prefix.entry_count = 8;
    } else {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BParameterArraySer count");
        prefix.entry_count = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        if (prefix.entry_count < 0)
            throw std::runtime_error("negative BParameterArraySer count");
    }
    prefix.version_0x11_context_ids =
            prefix.serializable.version == 0x11 && context_ids_enabled;
    prefix.entries_offset = pos;
    return prefix;
}

SourceModePrefix parse_source_mode_prefix(
        std::span<const std::byte> bytes, std::size_t offset) {
    SourceModePrefix prefix;
    prefix.serializable =
            parse_serializable_header(bytes, offset, false, 0x106);
    if (supports_source_mode_version(prefix.serializable.version) !=
            Support::supported) {
        throw std::runtime_error("unsupported BParSrcMode version");
    }
    auto pos = prefix.serializable.payload_offset;
    const auto common_size = prefix.serializable.version >= 0x102 ? 27U : 18U;
    if (!has(bytes, pos, common_size))
        throw std::runtime_error("truncated BParSrcMode prefix");
    prefix.serialized_mode = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (prefix.serialized_mode < 0 || prefix.serialized_mode >= 10) {
        throw std::runtime_error("BParSrcMode serialized mode is out of range");
    }
    static constexpr std::array<std::int32_t, 10> kModeConversion = { 0, 1, 3,
        4, 5, 6, 7, 8, 9, 2 };
    prefix.internal_mode =
            kModeConversion[static_cast<std::size_t>(prefix.serialized_mode)];
    auto read_float = [&]() {
        float value;
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    };
    prefix.field_after_mode = read_float();
    prefix.flag_after_field = u8(bytes, pos++) != 0;
    prefix.range_1_to_5 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (prefix.range_1_to_5 < 1 || prefix.range_1_to_5 > 5) {
        throw std::runtime_error("BParSrcMode range field is out of bounds");
    }
    prefix.second_flag = u8(bytes, pos++) != 0;
    prefix.versioned_f32[0] = read_float();
    if (prefix.serializable.version >= 0x102) {
        prefix.versioned_f32[1] = read_float();
        prefix.versioned_f32[2] = read_float();
        prefix.version_0x102_flag = u8(bytes, pos++) != 0;
    }
    prefix.variant_payload_offset = pos;
    return prefix;
}

SourceModePayload parse_source_mode(
        std::span<const std::byte> bytes, std::size_t offset) {
    SourceModePayload out;
    out.prefix = parse_source_mode_prefix(bytes, offset);
    auto pos = out.prefix.variant_payload_offset;
    auto need = [&](std::size_t count) {
        if (!has(bytes, pos, count))
            throw std::runtime_error("truncated BParSrcMode variant payload");
    };
    auto read_float = [&]() {
        need(4);
        float value;
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
        out.variant_f32.push_back(value);
    };
    auto read_s32 = [&]() {
        need(4);
        out.variant_s32.push_back(static_cast<std::int32_t>(u32le(bytes, pos)));
        pos += 4;
    };
    auto read_bool = [&]() {
        need(1);
        out.variant_bool.push_back(u8(bytes, pos++) != 0);
    };
    const auto version = out.prefix.serializable.version;
    switch (out.prefix.internal_mode) {
        case 1:
        case 3:
            read_float();
            read_float();
            read_bool();
            break;
        case 5:
            read_float();
            read_float();
            read_bool();
            if (version >= 0x106)
                read_bool();
            break;
        case 6:
            read_bool();
            read_s32();
            read_s32();
            break;
        case 9:
            read_bool();
            if (version == 0x100)
                read_s32();
            else
                read_bool();
            read_float();
            read_float();
            break;
        case 2:
            if (version >= 0x103) {
                read_float();
                read_float();
                read_float();
                read_float();
                read_s32();
                // warp selectors are one-based 1..34, not zero-based DSP enums
                if (out.variant_s32.back() < 1 || out.variant_s32.back() > 34)
                    throw std::runtime_error(
                            "BParSrcMode warp-1 enum is out of bounds");
                read_s32();
                if (out.variant_s32.back() < 1 || out.variant_s32.back() > 4) {
                    throw std::runtime_error(
                            "BParSrcMode mode-2 range is out of bounds");
                }
            }
            if (version >= 0x104) {
                read_bool();
                read_float();
            }
            if (version >= 0x105) {
                read_float();
                read_s32();
                if (out.variant_s32.back() < 1 || out.variant_s32.back() > 34)
                    throw std::runtime_error(
                            "BParSrcMode warp-2 enum is out of bounds");
                read_s32();
                read_s32();
                if (out.variant_s32[out.variant_s32.size() - 2] < 0 ||
                        out.variant_s32[out.variant_s32.size() - 2] >= 10 ||
                        out.variant_s32.back() < 0 ||
                        out.variant_s32.back() >= 13) {
                    throw std::runtime_error(
                            "BParSrcMode mode-2 enum is out of bounds");
                }
                read_float();
                read_float();
                need(4);
                out.variant_u32.push_back(u32le(bytes, pos));
                pos += 4;
                read_float();
                read_float();
                read_bool();
                read_bool();
            }
            break;
        default:
            break;
    }
    out.end_offset = pos;
    return out;
}

std::span<const ParFxTypeMapping>
kontakt8_runtime_par_fx_type_mappings() noexcept {
    static constexpr std::array<ParFxTypeMapping, 22> mappings{ {
            { 49, 68 },
            { 51, 65 },
            { 52, 24 },
            { 53, 26 },
            { 54, 38 },
            { 55, 15 },
            { 56, 31 },
            { 57, 69 },
            { 58, 23 },
            { 59, 44 },
            { 60, 45 },
            { 61, 46 },
            { 62, 47 },
            { 63, 49 },
            { 64, 48 },
            { 65, 50 },
            { 66, 51 },
            { 67, 52 },
            { 68, 53 },
            { 69, 54 },
            { 70, 55 },
            { 71, 56 },
    } };
    return mappings;
}

ParFxPayload parse_par_fx(std::span<const std::byte> bytes,
        const ChunkHeader &chunk,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 0x25) {
        throw std::invalid_argument(
                "BParFX chunk type " + std::to_string(chunk.type) +
                " at offset " + std::to_string(chunk.offset) + " must be 0x25");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BParFX chunk is out of bounds");
    }
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    ParFxPayload out;
    out.chunk = chunk;
    out.serializable =
            parse_serializable_header(bytes, chunk.payload_offset, true, 0x50);
    if (out.serializable.version != 0x50) {
        throw std::runtime_error("unsupported BParFX version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count) {
        if (pos > chunk_end || count > chunk_end - pos) {
            throw std::runtime_error("truncated BParFX payload");
        }
    };
    auto read_s32 = [&]() {
        need(4);
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    auto read_float = [&]() {
        need(4);
        const auto bits = u32le(bytes, pos);
        pos += 4;
        float value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    };
    auto read_bool = [&]() {
        need(1);
        return u8(bytes, pos++) != 0;
    };

    // private, public and children each start with an S32 marker we don't
    // validate
    out.phase_markers[0] = read_s32();
    out.serialized_fix_type = read_s32();
    static constexpr std::array<std::int32_t, 51> kBuiltInFixTypeToType = { 0,
        0, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 0, 0, 59, 60, 61, 62, 67, 70, 71,
        13, 14, 17, 29, 5, 30, 32, 34, 35, 33, 18, 19, 20, 21, 25, 27, 28, 64,
        63, 66, 36, 37, 39, 40, 42, 43, 22, 41, 0, 16 };
    static constexpr std::uint64_t kBuiltInFixTypeMask = 0x5ffffffffcffdULL;
    if (out.serialized_fix_type >= 0 && out.serialized_fix_type < 51 &&
            ((kBuiltInFixTypeMask >> out.serialized_fix_type) & 1U) != 0) {
        out.internal_type = kBuiltInFixTypeToType[static_cast<std::size_t>(
                out.serialized_fix_type)];
    } else {
        for (const auto &mapping : runtime_type_mappings) {
            if (mapping.serialized_fix_type == out.serialized_fix_type) {
                out.internal_type = mapping.internal_type;
                break;
            }
        }
        if (!out.internal_type) {
            for (const auto &mapping :
                    kontakt8_runtime_par_fx_type_mappings()) {
                if (mapping.serialized_fix_type == out.serialized_fix_type) {
                    out.internal_type = mapping.internal_type;
                    break;
                }
            }
        }
        if (!out.internal_type) {
            throw std::runtime_error(
                    "BParFX fix type " +
                    std::to_string(out.serialized_fix_type) +
                    " is not registered by Kontakt 8 or the caller mapping");
        }
    }
    if (*out.internal_type != 0) {
        out.private_bool.push_back(read_bool());
        out.private_s32.push_back(read_s32());
        out.private_bool.push_back(read_bool());
        out.private_f32.push_back(read_float());
        out.private_f32.push_back(read_float());
        out.private_s32.push_back(read_s32());
    }
    if (*out.internal_type == 0x28) {
        throw std::runtime_error("BParFX type is disabled by Kontakt");
    }
    out.phase_markers[1] = read_s32();
    out.phase_markers[2] = read_s32();
    if (*out.internal_type != 0) {
        need(6);
        ChunkHeader child;
        child.offset = pos;
        child.type = u16le(bytes, pos);
        child.payload_size = u32le(bytes, pos + 2);
        child.payload_offset = pos + 6;
        if (child.payload_size > chunk_end - child.payload_offset) {
            throw std::runtime_error("BParFX child chunk is out of bounds");
        }
        out.child_chunk = child;
        pos = child.payload_offset + child.payload_size;
        auto parse_known_child = [&](ParFxChildKind kind,
                                         std::uint16_t expected_type,
                                         std::uint16_t maximum_version) {
            if (child.type != expected_type) {
                throw std::runtime_error("BParFX concrete child chunk type "
                                         "does not match effect type");
            }
            ParFxChildPayload parsed;
            parsed.kind = kind;
            parsed.serializable = parse_serializable_header(
                    bytes.subspan(0, child.payload_offset + child.payload_size),
                    child.payload_offset, false, maximum_version);
            auto child_pos = parsed.serializable.payload_offset;
            const auto child_end = child.payload_offset + child.payload_size;
            auto child_need = [&](std::size_t count) {
                if (child_pos > child_end || count > child_end - child_pos) {
                    throw std::runtime_error("truncated BParFX concrete child");
                }
            };
            auto child_f32 = [&]() {
                child_need(4);
                const auto bits = u32le(bytes, child_pos);
                child_pos += 4;
                float value;
                std::memcpy(&value, &bits, sizeof(value));
                parsed.f32.push_back(value);
            };
            switch (kind) {
                case ParFxChildKind::limiter:
                    if (parsed.serializable.version != 0x60) {
                        throw std::runtime_error(
                                "unsupported BParFXLimiter version");
                    }
                    child_f32();
                    child_f32();
                    break;
                case ParFxChildKind::compressor:
                    if (parsed.serializable.version != 0x70) {
                        throw std::runtime_error(
                                "unsupported BParFXCompressor version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 3) {
                        throw std::runtime_error(
                                "BParFXCompressor mode is out of bounds");
                    }
                    child_f32();
                    child_f32();
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::delay:
                case ParFxChildKind::chorus:
                case ParFxChildKind::flanger:
                case ParFxChildKind::phaser: {
                    const auto version = parsed.serializable.version;
                    if (version != 0x50 && version != 0x51) {
                        throw std::runtime_error(
                                "unsupported modulation/delay BParFX version");
                    }
                    std::size_t count = 0;
                    if (kind == ParFxChildKind::delay ||
                            kind == ParFxChildKind::phaser) {
                        count = version == 0x50 ? 5 : 7;
                    } else if (kind == ParFxChildKind::chorus) {
                        count = version == 0x50 ? 4 : 6;
                    } else {
                        count = version == 0x50 ? 6 : 8;
                    }
                    for (std::size_t i = 0; i < count; ++i)
                        child_f32();
                    if (version == 0x51) {
                        child_need(1);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::phasis:
                    if (parsed.serializable.version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXPhasis version");
                    }
                    for (std::size_t i = 0; i < 9; ++i)
                        child_f32();
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    child_f32();
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::flair:
                    if (parsed.serializable.version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXFlair version");
                    }
                    for (std::size_t i = 0; i < 10; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 3; ++i) {
                        child_need(4);
                        parsed.s32.push_back(static_cast<std::int32_t>(
                                u32le(bytes, child_pos)));
                        child_pos += 4;
                    }
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 3 ||
                            parsed.s32[1] < 0 || parsed.s32[1] >= 3 ||
                            parsed.s32[2] < 0 || parsed.s32[2] >= 24) {
                        throw std::runtime_error(
                                "BParFXFlair enum is out of bounds");
                    }
                    child_f32();
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::gainer:
                    if (parsed.serializable.version != 0x50) {
                        throw std::runtime_error(
                                "unsupported BParFXGainer version");
                    }
                    child_f32();
                    break;
                case ParFxChildKind::hilbert_limiter:
                    if (parsed.serializable.version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXHilbertLimiter version");
                    }
                    child_f32();
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::supercharger:
                    if (parsed.serializable.version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXSupercharger version");
                    }
                    for (std::size_t i = 0; i < 7; ++i)
                        child_f32();
                    for (std::size_t i = 0; i < 4; ++i) {
                        child_need(4);
                        const auto value = static_cast<std::int32_t>(
                                u32le(bytes, child_pos));
                        child_pos += 4;
                        if (value < 0 || value >= 3) {
                            throw std::runtime_error(
                                    "BParFXSupercharger enum is out of bounds");
                        }
                        parsed.s32.push_back(value);
                    }
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::bass_invader:
                    if (parsed.serializable.version != 0x51 &&
                            parsed.serializable.version != 0x52) {
                        throw std::runtime_error(
                                "unsupported BParFXBassInvader version");
                    }
                    for (std::size_t i = 0; i < 7; ++i)
                        child_f32();
                    child_need(parsed.serializable.version == 0x51 ? 3 : 4);
                    for (std::size_t i = 0;
                            i < (parsed.serializable.version == 0x51 ? 3U : 4U);
                            ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                case ParFxChildKind::reverb:
                case ParFxChildKind::plate_reverb:
                    if (parsed.serializable.version !=
                            (kind == ParFxChildKind::reverb ? 0x50 : 0x10)) {
                        throw std::runtime_error(
                                "unsupported BParFX reverb version");
                    }
                    for (std::size_t i = 0; i < 5; ++i)
                        child_f32();
                    break;
                case ParFxChildKind::galois_reverb:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXGaloisReverb version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 2) {
                        throw std::runtime_error(
                                "BParFXGaloisReverb enum is out of bounds");
                    }
                    for (std::size_t i = 0; i < 9; ++i)
                        child_f32();
                    break;
                case ParFxChildKind::inverter:
                    if (parsed.serializable.version != 0x60) {
                        throw std::runtime_error(
                                "unsupported BParFXInverter version");
                    }
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::dyx:
                    if (parsed.serializable.version != 0x60) {
                        throw std::runtime_error(
                                "unsupported BParFXDYX version");
                    }
                    child_f32();
                    child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::surround_panner: {
                    if (parsed.serializable.version != 0x70) {
                        throw std::runtime_error(
                                "unsupported BParFXSurroundPanner version");
                    }
                    auto read_points = [&]() {
                        child_need(4);
                        const auto count = static_cast<std::int32_t>(
                                u32le(bytes, child_pos));
                        child_pos += 4;
                        parsed.s32.push_back(count);
                        if (count > 0) {
                            if (static_cast<std::uint64_t>(count) >
                                    static_cast<std::uint64_t>(
                                            child_end - child_pos) /
                                            9U) {
                                throw std::runtime_error(
                                        "BParFXSurroundPanner point count is out "
                                        "of bounds");
                            }
                            for (std::int32_t i = 0; i < count; ++i) {
                                child_f32();
                                child_f32();
                                child_need(1);
                                parsed.u8.push_back(u8(bytes, child_pos++));
                            }
                        }
                    };
                    read_points();
                    read_points();
                    for (std::size_t i = 0; i < 6; ++i)
                        child_f32();
                    for (std::size_t i = 0; i < 2; ++i) {
                        child_need(4);
                        parsed.s32.push_back(static_cast<std::int32_t>(
                                u32le(bytes, child_pos)));
                        child_pos += 4;
                    }
                    if (parsed.s32[parsed.s32.size() - 2] < 0 ||
                            parsed.s32[parsed.s32.size() - 2] >= 3 ||
                            parsed.s32.back() < 0 || parsed.s32.back() >= 7) {
                        throw std::runtime_error(
                                "BParFXSurroundPanner enum is out of bounds");
                    }
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    for (std::size_t i = 0; i < 4; ++i)
                        child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    break;
                }
                case ParFxChildKind::lo_fi:
                    if (parsed.serializable.version != 0x70) {
                        throw std::runtime_error(
                                "unsupported BParFXLoFi version");
                    }
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    child_f32();
                    child_f32();
                    break;
                case ParFxChildKind::shaper:
                    if (parsed.serializable.version != 0x80) {
                        throw std::runtime_error(
                                "unsupported BParFXShaper version");
                    }
                    child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    break;
                case ParFxChildKind::stereo_spread:
                    if (parsed.serializable.version != 0x70) {
                        throw std::runtime_error(
                                "unsupported BParFXStereoSpread version");
                    }
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::distortion:
                    if (parsed.serializable.version != 0x60) {
                        throw std::runtime_error(
                                "unsupported BParFXDistortion version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 2) {
                        throw std::runtime_error(
                                "BParFXDistortion enum is out of bounds");
                    }
                    child_f32();
                    child_f32();
                    break;
                case ParFxChildKind::filter: {
                    const auto version = parsed.serializable.version;
                    if (version != 0x80 && (version < 0x90 || version > 0x95)) {
                        throw std::runtime_error(
                                "unsupported BParFXFilter version");
                    }
                    auto convert_fix_type =
                            [](std::int32_t signed_value) -> std::int32_t {
                        const auto value =
                                static_cast<std::uint32_t>(signed_value);
                        if (value >= 0x1e && value < 0x2a)
                            return static_cast<std::int32_t>(value - 8);
                        if ((value & ~1U) == 0x32)
                            return static_cast<std::int32_t>(value - 8);
                        if (value >= 0x34 && value < 0x37)
                            return static_cast<std::int32_t>(value - 6);
                        if (value >= 0x37 && value < 0x3b)
                            return static_cast<std::int32_t>(value - 4);
                        if (value >= 0x3b && value < 0x3f)
                            return static_cast<std::int32_t>(value - 2);
                        if (value >= 0x3f && value < 0x42)
                            return static_cast<std::int32_t>(value);
                        if ((value & ~1U) == 0x5a)
                            return static_cast<std::int32_t>(value - 0x12);
                        if ((value & ~1U) == 0x46)
                            return static_cast<std::int32_t>(value - 2);
                        if (value >= 100 && value < 109)
                            return static_cast<std::int32_t>(value - 0x18);
                        if (value == 0x78)
                            return 0x58;
                        if (value == 0x82)
                            return 0x5b;
                        if ((value & ~3U) == 0x8c)
                            return static_cast<std::int32_t>(value - 0x68);
                        static constexpr std::array<std::int32_t, 23>
                                kLegacy = { 2, 3, 4, 0, 6, 7, 8, 9, 10, 11, 12,
                                    13, 14, 15, 16, 17, 0, 19, 0, 0, 95, 96,
                                    97 };
                        if (value >= 2 && value < 25)
                            return kLegacy[value - 2];
                        return 0;
                    };
                    auto read_fix_type = [&]() {
                        child_need(4);
                        const auto serialized = static_cast<std::int32_t>(
                                u32le(bytes, child_pos));
                        child_pos += 4;
                        parsed.s32.push_back(serialized);
                        const auto converted = convert_fix_type(serialized);
                        parsed.converted_type.push_back(converted);
                        return converted;
                    };
                    auto read_bool_field = [&]() {
                        child_need(1);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    };
                    auto read_enum_and_five = [&]() {
                        child_need(4);
                        const auto value = static_cast<std::int32_t>(
                                u32le(bytes, child_pos));
                        child_pos += 4;
                        if (value < 0 || value >= 3) {
                            throw std::runtime_error(
                                    "BParFXFilter enum is out of bounds");
                        }
                        parsed.s32.push_back(value);
                        for (std::size_t i = 0; i < 5; ++i)
                            child_f32();
                    };
                    if (version == 0x95) {
                        const auto type = read_fix_type();
                        if (type == 0x58 || (type >= 0x16 && type < 0x22))
                            read_bool_field();
                    }
                    if (version >= 0x94) {
                        const auto type = read_fix_type();
                        if (type >= 0x24 && type < 0x28)
                            read_enum_and_five();
                    }
                    if (version >= 0x93) {
                        if (read_fix_type() == 0x5b) {
                            for (std::size_t i = 0; i < 5; ++i)
                                child_f32();
                        }
                    }
                    if (version >= 0x92) {
                        const auto type = read_fix_type();
                        if (type >= 0x16 && type < 0x22)
                            read_bool_field();
                    }
                    const auto type = read_fix_type();
                    if ((type >= 0x16 && type < 0x22) || type == 0x44 ||
                            type == 0x45) {
                        child_f32();
                    }
                    if (type == 0x48 || type == 0x49) {
                        child_f32();
                        child_f32();
                        child_f32();
                    }
                    if (type >= 0x3f && type < 0x42)
                        child_f32();
                    if (type == 0x58) {
                        child_f32();
                        child_f32();
                    }
                    if (type >= 2 && type <= 92 && type != 0x48 &&
                            type != 0x49 && type != 0x58 && type != 0x5b &&
                            !(type >= 0x24 && type < 0x28)) {
                        child_f32();
                        child_f32();
                        if (type == 0x13) {
                            for (std::size_t i = 0; i < 11; ++i)
                                child_f32();
                        }
                    }
                    if (type >= 0x5f && type < 0x62) {
                        child_f32();
                        child_f32();
                        child_f32();
                        if (type == 0x60 || type == 0x61) {
                            child_f32();
                            child_f32();
                            child_f32();
                            if (type == 0x61) {
                                child_f32();
                                child_f32();
                                child_f32();
                            }
                        }
                    }
                    break;
                }
                case ParFxChildKind::send_levels: {
                    const auto version = parsed.serializable.version;
                    if (version != 0x50 && version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXSendLevels version");
                    }
                    child_need(4);
                    const auto first_count = u32le(bytes, child_pos);
                    child_pos += 4;
                    parsed.u32.push_back(first_count);
                    const auto first_read_count =
                            std::min<std::uint32_t>(first_count, 8);
                    for (std::uint32_t i = 0; i < first_read_count; ++i)
                        child_f32();
                    if (version == 0x51) {
                        child_need(4);
                        const auto second_count = u32le(bytes, child_pos);
                        child_pos += 4;
                        parsed.u32.push_back(second_count);
                        const auto second_read_count =
                                std::min<std::uint32_t>(second_count, 17);
                        for (std::uint32_t i = 0; i < second_read_count; ++i)
                            child_f32();
                    }
                    break;
                }
                case ParFxChildKind::skreamer:
                    if (parsed.serializable.version != 0x50) {
                        throw std::runtime_error(
                                "unsupported BParFXSkreamer version");
                    }
                    for (std::size_t i = 0; i < 5; ++i)
                        child_f32();
                    break;
                case ParFxChildKind::rotator:
                    if (parsed.serializable.version != 0x50) {
                        throw std::runtime_error(
                                "unsupported BParFXRotator version");
                    }
                    for (std::size_t i = 0; i < 6; ++i)
                        child_f32();
                    break;
                case ParFxChildKind::ring_modulator:
                    if (parsed.serializable.version != 0x50) {
                        throw std::runtime_error(
                                "unsupported BParFXRingModulator version");
                    }
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 4; ++i)
                        child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 2) {
                        throw std::runtime_error(
                                "BParFXRingModulator enum is out of bounds");
                    }
                    for (std::size_t i = 0; i < 5; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::twang:
                    if (parsed.serializable.version != 0x50 &&
                            parsed.serializable.version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXTwang version");
                    }
                    for (std::size_t i = 0; i < 4; ++i)
                        child_f32();
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::jump:
                case ParFxChildKind::van51:
                case ParFxChildKind::ac_box:
                case ParFxChildKind::hot_solo:
                case ParFxChildKind::bass_pro: {
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFX amplifier version");
                    }
                    std::size_t float_count = 0;
                    std::size_t bool_count = 0;
                    switch (kind) {
                        case ParFxChildKind::jump:
                            float_count = 6;
                            bool_count = 2;
                            break;
                        case ParFxChildKind::van51:
                            float_count = 8;
                            bool_count = 5;
                            break;
                        case ParFxChildKind::ac_box:
                            float_count = 7;
                            bool_count = 1;
                            break;
                        case ParFxChildKind::hot_solo:
                            float_count = 8;
                            bool_count = 2;
                            break;
                        case ParFxChildKind::bass_pro:
                            float_count = 17;
                            bool_count = 5;
                            break;
                        default:
                            break;
                    }
                    for (std::size_t i = 0; i < float_count; ++i)
                        child_f32();
                    child_need(bool_count);
                    for (std::size_t i = 0; i < bool_count; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::cat:
                case ParFxChildKind::d_stortion:
                case ParFxChildKind::cry_wah:
                case ParFxChildKind::tape: {
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFX distortion/cabinet version");
                    }
                    std::size_t float_count = 0;
                    if (kind == ParFxChildKind::cat)
                        float_count = 7;
                    else if (kind == ParFxChildKind::d_stortion)
                        float_count = 6;
                    else if (kind == ParFxChildKind::cry_wah)
                        float_count = 1;
                    else
                        float_count = 3;
                    for (std::size_t i = 0; i < float_count; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                }
                case ParFxChildKind::cabinet:
                    if (parsed.serializable.version != 0x50) {
                        throw std::runtime_error(
                                "unsupported BParFXCabinet version");
                    }
                    for (std::size_t i = 0; i < 4; ++i)
                        child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    break;
                case ParFxChildKind::transient_master:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXTrans version");
                    }
                    child_f32();
                    child_f32();
                    child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 2) {
                        throw std::runtime_error(
                                "BParFXTrans enum is out of bounds");
                    }
                    break;
                case ParFxChildKind::feedback_compressor:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXFBComp version");
                    }
                    for (std::size_t i = 0; i < 7; ++i)
                        child_f32();
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                case ParFxChildKind::solid_g_eq: {
                    const auto version = parsed.serializable.version;
                    if (version != 0x10 && version != 0x11) {
                        throw std::runtime_error(
                                "unsupported BParFXSSLGEQ version");
                    }
                    child_f32();
                    child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 8; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    if (version == 0x11) {
                        child_f32();
                        child_f32();
                        child_need(2);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::solid_bus_compressor: {
                    const auto version = parsed.serializable.version;
                    if (version < 0x10 || version > 0x12) {
                        throw std::runtime_error(
                                "unsupported BParFXSSLGBusComp version");
                    }
                    for (std::size_t i = 0; i < 6; ++i)
                        child_f32();
                    child_need(version == 0x10 ? 1 : 2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    if (version >= 0x11)
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    if (version == 0x12)
                        child_f32();
                    break;
                }
                case ParFxChildKind::choral:
                    if (parsed.serializable.version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParFXChoral version");
                    }
                    for (std::size_t i = 0; i < 7; ++i)
                        child_f32();
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 4) {
                        throw std::runtime_error(
                                "BParFXChoral enum is out of bounds");
                    }
                    break;
                case ParFxChildKind::replika_delay: {
                    const auto version = parsed.serializable.version;
                    if (version < 0x10 || version > 0x12) {
                        throw std::runtime_error(
                                "unsupported BParFXReplikaDelay version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 5) {
                        throw std::runtime_error(
                                "BParFXReplikaDelay enum is out of bounds");
                    }
                    for (std::size_t i = 0; i < 10; ++i)
                        child_f32();
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    if (version >= 0x11) {
                        for (std::size_t i = 0; i < 4; ++i)
                            child_f32();
                        child_need(1);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    if (version >= 0x12) {
                        for (std::size_t i = 0; i < 9; ++i)
                            child_f32();
                        child_need(1);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::irc: {
                    const auto version = parsed.serializable.version;
                    if ((version | 0x10U) != 0x70U) {
                        throw std::runtime_error(
                                "unsupported BParFXIRC version");
                    }
                    child_f32();
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    for (std::size_t i = 0; i < 8; ++i)
                        child_f32();
                    child_need(5);
                    for (std::size_t i = 0; i < 5; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    for (std::size_t array = 0; array < 2; ++array) {
                        child_need(4);
                        const auto count = u32le(bytes, child_pos);
                        child_pos += 4;
                        parsed.u32.push_back(count);
                        for (std::uint32_t i = 0; i < std::min(count, 8U); ++i)
                            child_f32();
                    }
                    // signed filename table index, not a path
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    break;
                }
                case ParFxChildKind::psyche_delay:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXPsycheDelay version");
                    }
                    for (std::size_t i = 0; i < 6; ++i)
                        child_f32();
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::twin_delay:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXTwinDelay version");
                    }
                    for (std::size_t group = 0; group < 4; ++group) {
                        for (std::size_t i = 0; i < 3; ++i)
                            child_f32();
                        child_need(1);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    for (std::size_t i = 0; i < 10; ++i)
                        child_f32();
                    break;
                case ParFxChildKind::raum:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXRaum version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 3) {
                        throw std::runtime_error(
                                "BParFXRaum mode is out of bounds");
                    }
                    for (std::size_t i = 0; i < 12; ++i)
                        child_f32();
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::bite:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXBite version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 3) {
                        throw std::runtime_error(
                                "BParFXBite mode is out of bounds");
                    }
                    for (std::size_t i = 0; i < 10; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::dirt:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXDirt version");
                    }
                    for (std::size_t i = 0; i < 10; ++i)
                        child_f32();
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 3; ++i) {
                        child_need(4);
                        parsed.s32.push_back(static_cast<std::int32_t>(
                                u32le(bytes, child_pos)));
                        child_pos += 4;
                        if (parsed.s32.back() < 0 || parsed.s32.back() >= 3) {
                            throw std::runtime_error(
                                    "BParFXDirt mode is out of bounds");
                        }
                    }
                    break;
                case ParFxChildKind::freak:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXFreak version");
                    }
                    for (std::size_t i = 0; i < 13; ++i)
                        child_f32();
                    child_need(5);
                    for (std::size_t i = 0; i < 5; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 3) {
                        throw std::runtime_error(
                                "BParFXFreak mode is out of bounds");
                    }
                    break;
                case ParFxChildKind::vibrato_chorus:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXVibratoChorus version");
                    }
                    for (const auto upper_bound : { 6, 3 }) {
                        child_need(4);
                        parsed.s32.push_back(static_cast<std::int32_t>(
                                u32le(bytes, child_pos)));
                        child_pos += 4;
                        if (parsed.s32.back() < 0 ||
                                parsed.s32.back() >= upper_bound) {
                            throw std::runtime_error(
                                    "BParFXVibratoChorus mode is out of bounds");
                        }
                    }
                    for (std::size_t i = 0; i < 4; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::wow_flutter:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXWowFlutter version");
                    }
                    for (std::size_t i = 0; i < 7; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    child_f32();
                    break;
                case ParFxChildKind::ep_preamps: {
                    const auto version = parsed.serializable.version;
                    if (version != 0x10 && version != 0x11) {
                        throw std::runtime_error(
                                "unsupported BParFXEPPreamps version");
                    }
                    for (std::size_t i = 0; i < 11; ++i)
                        child_f32();
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    constexpr std::array<std::int32_t, 4> bounds{ 5, 6, 7, 5 };
                    for (const auto upper_bound : bounds) {
                        child_need(4);
                        parsed.s32.push_back(static_cast<std::int32_t>(
                                u32le(bytes, child_pos)));
                        child_pos += 4;
                        if (parsed.s32.back() < 0 ||
                                parsed.s32.back() >= upper_bound) {
                            throw std::runtime_error(
                                    "BParFXEPPreamps mode is out of bounds");
                        }
                    }
                    if (version == 0x11) {
                        child_need(4);
                        for (std::size_t i = 0; i < 4; ++i) {
                            parsed.boolean.push_back(
                                    u8(bytes, child_pos++) != 0);
                        }
                    }
                    break;
                }
                case ParFxChildKind::fuzz:
                case ParFxChildKind::big_fuzz:
                case ParFxChildKind::stereo_tune: {
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported simple registered BParFX version");
                    }
                    const auto float_count =
                            kind == ParFxChildKind::fuzz ? 3U : 4U;
                    for (std::size_t i = 0; i < float_count; ++i)
                        child_f32();
                    if (kind != ParFxChildKind::stereo_tune) {
                        child_need(1);
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::beat_masher:
                    if (parsed.serializable.version != 1) {
                        throw std::runtime_error(
                                "unsupported BParFXBeatMasher version");
                    }
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 9) {
                        throw std::runtime_error(
                                "BParFXBeatMasher mode is out of bounds");
                    }
                    break;
                case ParFxChildKind::beat_slicer:
                    if (parsed.serializable.version != 1) {
                        throw std::runtime_error(
                                "unsupported BParFXBeatSlicer version");
                    }
                    for (std::size_t i = 0; i < 2; ++i)
                        child_f32();
                    child_need(3);
                    for (std::size_t i = 0; i < 3; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    for (std::size_t i = 0; i < 2; ++i) {
                        child_need(4);
                        parsed.s32.push_back(static_cast<std::int32_t>(
                                u32le(bytes, child_pos)));
                        child_pos += 4;
                        if (parsed.s32.back() < 0 || parsed.s32.back() >= 5) {
                            throw std::runtime_error(
                                    "BParFXBeatSlicer mode is out of bounds");
                        }
                    }
                    break;
                case ParFxChildKind::gater:
                case ParFxChildKind::reverse_grain: {
                    if (parsed.serializable.version != 1) {
                        throw std::runtime_error(
                                "unsupported time-effect BParFX version");
                    }
                    for (std::size_t i = 0; i < 4; ++i)
                        child_f32();
                    const auto bool_count =
                            kind == ParFxChildKind::gater ? 4U : 3U;
                    child_need(bool_count);
                    for (std::size_t i = 0; i < bool_count; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::transpose_stretch:
                case ParFxChildKind::super_fast_100:
                case ParFxChildKind::chainsaw: {
                    const auto expected_version =
                            kind == ParFxChildKind::transpose_stretch ? 1U
                                                                      : 0x10U;
                    if (parsed.serializable.version != expected_version) {
                        throw std::runtime_error(
                                "unsupported registered BParFX version");
                    }
                    std::size_t float_count = 4;
                    std::size_t bool_count = 1;
                    if (kind == ParFxChildKind::transpose_stretch)
                        bool_count = 3;
                    if (kind == ParFxChildKind::super_fast_100) {
                        float_count = 8;
                        bool_count = 4;
                    }
                    for (std::size_t i = 0; i < float_count; ++i)
                        child_f32();
                    child_need(bool_count);
                    for (std::size_t i = 0; i < bool_count; ++i) {
                        parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    }
                    break;
                }
                case ParFxChildKind::skreamer_dlx:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXSkreamerDlx version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 3) {
                        throw std::runtime_error(
                                "BParFXSkreamerDlx mode is out of bounds");
                    }
                    for (std::size_t i = 0; i < 5; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::kolor:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXKolor version");
                    }
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 10) {
                        throw std::runtime_error(
                                "BParFXKolor mode is out of bounds");
                    }
                    for (std::size_t i = 0; i < 11; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
                case ParFxChildKind::reverb_delight:
                    if (parsed.serializable.version != 0x10) {
                        throw std::runtime_error(
                                "unsupported BParFXReverbDelight version");
                    }
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    child_need(4);
                    parsed.s32.push_back(
                            static_cast<std::int32_t>(u32le(bytes, child_pos)));
                    child_pos += 4;
                    if (parsed.s32[0] < 0 || parsed.s32[0] >= 2) {
                        throw std::runtime_error(
                                "BParFXReverbDelight mode is out of bounds");
                    }
                    child_f32();
                    child_need(2);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    for (std::size_t i = 0; i < 3; ++i)
                        child_f32();
                    child_need(1);
                    parsed.boolean.push_back(u8(bytes, child_pos++) != 0);
                    break;
            }
            if (child_pos != child_end) {
                throw std::runtime_error(
                        "BParFX concrete child has trailing bytes");
            }
            parsed.end_offset = child_pos;
            out.parsed_child = std::move(parsed);
        };
        switch (*out.internal_type) {
            case 2:
                parse_known_child(ParFxChildKind::compressor, 0x19, 0x70);
                break;
            case 3:
                parse_known_child(ParFxChildKind::limiter, 0x1c, 0x60);
                break;
            case 4:
                parse_known_child(ParFxChildKind::inverter, 0x1a, 0x60);
                break;
            case 5:
                parse_known_child(ParFxChildKind::dyx, 0x1b, 0x60);
                break;
            case 6:
                parse_known_child(ParFxChildKind::surround_panner, 0x1d, 0x70);
                break;
            case 7:
                parse_known_child(ParFxChildKind::shaper, 0x1d, 0x80);
                break;
            case 8:
                parse_known_child(ParFxChildKind::filter, 0x18, 0x95);
                break;
            case 9:
                parse_known_child(ParFxChildKind::lo_fi, 0x20, 0x70);
                break;
            case 10:
                parse_known_child(ParFxChildKind::stereo_spread, 0x1f, 0x70);
                break;
            case 11:
                parse_known_child(ParFxChildKind::distortion, 0x1e, 0x60);
                break;
            case 12:
                parse_known_child(ParFxChildKind::send_levels, 0x17, 0x51);
                break;
            case 13:
                parse_known_child(ParFxChildKind::skreamer, 0x21, 0x50);
                break;
            case 14:
                parse_known_child(ParFxChildKind::rotator, 0x22, 0x50);
                break;
            case 15:
                parse_known_child(ParFxChildKind::vibrato_chorus, 0x69, 0x10);
                break;
            case 16:
                parse_known_child(ParFxChildKind::ring_modulator, 100, 0x50);
                break;
            case 17:
                parse_known_child(ParFxChildKind::twang, 0x23, 0x51);
                break;
            case 18:
                parse_known_child(ParFxChildKind::jump, 0x4d, 0x10);
                break;
            case 19:
                parse_known_child(ParFxChildKind::van51, 0x52, 0x10);
                break;
            case 20:
                parse_known_child(ParFxChildKind::ac_box, 0x53, 0x10);
                break;
            case 21:
                parse_known_child(ParFxChildKind::hot_solo, 0x54, 0x10);
                break;
            case 22:
                parse_known_child(ParFxChildKind::bass_pro, 0x61, 0x10);
                break;
            case 23:
                parse_known_child(ParFxChildKind::ep_preamps, 0x6c, 0x11);
                break;
            case 24:
                parse_known_child(ParFxChildKind::bite, 0x66, 0x10);
                break;
            case 25:
                parse_known_child(ParFxChildKind::cat, 0x55, 0x10);
                break;
            case 26:
                parse_known_child(ParFxChildKind::dirt, 0x67, 0x10);
                break;
            case 27:
                parse_known_child(ParFxChildKind::d_stortion, 0x56, 0x10);
                break;
            case 28:
                parse_known_child(ParFxChildKind::cry_wah, 0x58, 0x10);
                break;
            case 29:
                parse_known_child(ParFxChildKind::cabinet, 0x24, 0x50);
                break;
            case 30:
                parse_known_child(ParFxChildKind::tape, 0x42, 0x10);
                break;
            case 31:
                parse_known_child(ParFxChildKind::wow_flutter, 0x6a, 0x10);
                break;
            case 32:
                parse_known_child(ParFxChildKind::transient_master, 0x43, 0x10);
                break;
            case 33:
                parse_known_child(
                        ParFxChildKind::feedback_compressor, 0x4c, 0x10);
                break;
            case 34:
                parse_known_child(ParFxChildKind::solid_g_eq, 0x44, 0x11);
                break;
            case 35:
                parse_known_child(
                        ParFxChildKind::solid_bus_compressor, 0x46, 0x12);
                break;
            case 36:
                parse_known_child(ParFxChildKind::phasis, 0x5b, 0x51);
                break;
            case 37:
                parse_known_child(ParFxChildKind::flair, 0x5c, 0x51);
                break;
            case 38:
                parse_known_child(ParFxChildKind::freak, 0x68, 0x10);
                break;
            case 39:
                parse_known_child(ParFxChildKind::choral, 0x5d, 0x51);
                break;
            case 41:
                parse_known_child(ParFxChildKind::bass_invader, 0x54, 0x52);
                break;
            case 42:
                parse_known_child(ParFxChildKind::hilbert_limiter, 0x5f, 0x51);
                break;
            case 43:
                parse_known_child(ParFxChildKind::supercharger, 0x60, 0x51);
                break;
            case 44:
                parse_known_child(ParFxChildKind::fuzz, 0x6e, 0x10);
                break;
            case 45:
                parse_known_child(ParFxChildKind::big_fuzz, 0x6f, 0x10);
                break;
            case 46:
                parse_known_child(ParFxChildKind::stereo_tune, 0x70, 0x10);
                break;
            case 47:
                parse_known_child(ParFxChildKind::beat_masher, 0x71, 1);
                break;
            case 48:
                parse_known_child(ParFxChildKind::beat_slicer, 0x73, 1);
                break;
            case 49:
                parse_known_child(ParFxChildKind::gater, 0x72, 1);
                break;
            case 50:
                parse_known_child(ParFxChildKind::reverse_grain, 0x74, 1);
                break;
            case 51:
                parse_known_child(ParFxChildKind::transpose_stretch, 0x75, 1);
                break;
            case 52:
                parse_known_child(ParFxChildKind::super_fast_100, 0x76, 0x10);
                break;
            case 53:
                parse_known_child(ParFxChildKind::chainsaw, 0x77, 0x10);
                break;
            case 54:
                parse_known_child(ParFxChildKind::skreamer_dlx, 0x78, 0x10);
                break;
            case 55:
                parse_known_child(ParFxChildKind::kolor, 0x79, 0x10);
                break;
            case 56:
                parse_known_child(ParFxChildKind::reverb_delight, 0x7a, 0x10);
                break;
            case 59:
                parse_known_child(ParFxChildKind::phaser, 0x14, 0x51);
                break;
            case 60:
                parse_known_child(ParFxChildKind::flanger, 0x12, 0x51);
                break;
            case 61:
                parse_known_child(ParFxChildKind::chorus, 0x11, 0x51);
                break;
            case 62:
                parse_known_child(ParFxChildKind::reverb, 0x15, 0x50);
                break;
            case 63:
                parse_known_child(ParFxChildKind::galois_reverb, 0x59, 0x10);
                break;
            case 64:
                parse_known_child(ParFxChildKind::plate_reverb, 0x57, 0x10);
                break;
            case 65:
                parse_known_child(ParFxChildKind::raum, 0x65, 0x10);
                break;
            case 66:
                parse_known_child(ParFxChildKind::replika_delay, 0x5a, 0x12);
                break;
            case 67:
                parse_known_child(ParFxChildKind::delay, 0x10, 0x51);
                break;
            case 68:
                parse_known_child(ParFxChildKind::psyche_delay, 0x63, 0x10);
                break;
            case 69:
                parse_known_child(ParFxChildKind::twin_delay, 0x6b, 0x10);
                break;
            case 70:
                parse_known_child(ParFxChildKind::irc, 0x16, 0x70);
                break;
            case 71:
                parse_known_child(ParFxChildKind::gainer, 0x13, 0x50);
                break;
            default:
                break;
        }
    }
    if (pos != chunk_end)
        throw std::runtime_error("BParFX chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

ParameterArrayPayload parse_parameter_array(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    ParameterArrayPayload out;
    out.prefix =
            parse_parameter_array_prefix(bytes, offset, context_ids_enabled);
    auto pos = out.prefix.entries_offset;
    out.entries.reserve(static_cast<std::size_t>(out.prefix.entry_count));
    for (std::int32_t i = 0; i < out.prefix.entry_count; ++i) {
        if (!has(bytes, pos, 1))
            throw std::runtime_error("truncated parameter-array entry");
        ParameterArrayEntry entry;
        entry.present = u8(bytes, pos++) != 0;
        if (out.prefix.version_0x11_context_ids) {
            if (!has(bytes, pos, 4))
                throw std::runtime_error(
                        "truncated parameter-array context id");
            entry.context_id = static_cast<std::int32_t>(u32le(bytes, pos));
            pos += 4;
        }
        if (entry.present) {
            if (!has(bytes, pos, 6))
                throw std::runtime_error("truncated BParFX chunk header");
            ChunkHeader chunk{ pos, u16le(bytes, pos), u32le(bytes, pos + 2),
                pos + 6 };
            if (chunk.payload_size > bytes.size() - chunk.payload_offset) {
                throw std::runtime_error(
                        "BParFX chunk size is out of bounds at " +
                        std::to_string(pos) + " (type " +
                        std::to_string(chunk.type) + ", size " +
                        std::to_string(chunk.payload_size) + ", remaining " +
                        std::to_string(bytes.size() - chunk.payload_offset) +
                        ")");
            }
            entry.chunk = chunk;
            entry.par_fx = parse_par_fx(bytes, chunk, runtime_type_mappings);
            pos = entry.par_fx->end_offset;
        }
        out.entries.push_back(std::move(entry));
    }
    out.end_offset = pos;
    return out;
}

ParameterArrayPayload parse_internal_modulator_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings);

ParameterArrayPayload parse_external_modulator_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled);

InternalModulatorPayload parse_internal_modulator_array_entry(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings,
        std::optional<std::uint32_t> creator_version_packed) {
    if (chunk.type != 0x0d) {
        throw std::invalid_argument("BParInternalMod chunk type must be 0x0d");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BParInternalMod chunk is out of bounds");
    }

    // same payload as a preset, so wrap it, reuse the preset reader and fix
    // the offsets up afterwards
    std::vector<std::byte> framed(
            static_cast<std::size_t>(chunk.payload_size) + 11);
    auto store_u16 = [&](std::size_t offset, std::uint16_t value) {
        framed[offset] = std::byte(value & 0xffU);
        framed[offset + 1] = std::byte(value >> 8U);
    };
    auto store_u32 = [&](std::size_t offset, std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) {
            framed[offset + i] = std::byte((value >> (i * 8U)) & 0xffU);
        }
    };
    store_u16(0, 0x30);
    store_u32(2, chunk.payload_size + 5U);
    framed[6] = std::byte{ 0 }; // preset payload is unstructured
    store_u16(7, 1);
    framed[9] = std::byte{ 0 };
    framed[10] = std::byte{ static_cast<std::uint8_t>(
            PresetKind::internal_modulator) };
    std::copy_n(
            bytes.begin() + static_cast<std::ptrdiff_t>(chunk.payload_offset),
            chunk.payload_size, framed.begin() + 11);
    const ChunkHeader wrapper{ 0, 0x30, chunk.payload_size + 5U, 6 };
    auto preset = parse_preset(framed, wrapper, context_ids_enabled,
            runtime_type_mappings, creator_version_packed);
    if (!preset.internal_modulator) {
        throw std::runtime_error(
                "internal-modulator Preset adapter produced no payload");
    }
    auto value = std::move(*preset.internal_modulator);
    const auto original_base = chunk.payload_offset;
    auto rebase = [original_base](std::size_t &offset) {
        if (offset < 11)
            throw std::runtime_error("invalid adapted modulator offset");
        offset = original_base + offset - 11;
    };
    auto rebase_serializable = [&](SerializableHeader &serializable) {
        rebase(serializable.offset);
        rebase(serializable.payload_offset);
    };
    auto rebase_chunk = [&](ChunkHeader &child) {
        rebase(child.offset);
        rebase(child.payload_offset);
    };
    auto rebase_child = [&](InternalModChildPayload &child) {
        rebase_chunk(child.chunk);
        rebase_serializable(child.serializable);
        rebase(child.end_offset);
    };
    rebase_serializable(value.serializable);
    for (auto &target : value.targets)
        rebase(target.transformation.end_offset);
    if (value.lfo) {
        rebase_chunk(value.lfo->chunk);
        rebase_serializable(value.lfo->serializable);
        rebase(value.lfo->end_offset);
    }
    if (value.envelope) {
        rebase_chunk(value.envelope->chunk);
        rebase_serializable(value.envelope->serializable);
        rebase_child(value.envelope->child);
        rebase(value.envelope->end_offset);
    }
    if (value.arp)
        rebase_child(*value.arp);
    if (value.env_f)
        rebase_child(*value.env_f);
    if (value.glide)
        rebase_child(*value.glide);
    rebase(value.end_offset);
    if (value.end_offset != chunk.payload_offset + chunk.payload_size) {
        throw std::runtime_error(
                "BParInternalMod does not consume its entry chunk");
    }
    return value;
}

ParameterArrayPayload parse_internal_modulator_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    ParameterArrayPayload out;
    out.prefix =
            parse_parameter_array_prefix(bytes, offset, context_ids_enabled);
    if (out.prefix.serializable.version < 0x13)
        out.prefix.entry_count = 16;
    auto pos = out.prefix.entries_offset;
    out.entries.reserve(static_cast<std::size_t>(out.prefix.entry_count));
    for (std::int32_t i = 0; i < out.prefix.entry_count; ++i) {
        if (!has(bytes, pos, 1)) {
            throw std::runtime_error(
                    "truncated internal-modulator array entry");
        }
        ParameterArrayEntry entry;
        entry.present = u8(bytes, pos++) != 0;
        if (out.prefix.version_0x11_context_ids) {
            if (!has(bytes, pos, 4)) {
                throw std::runtime_error(
                        "truncated internal-modulator context id");
            }
            entry.context_id = static_cast<std::int32_t>(u32le(bytes, pos));
            pos += 4;
        }
        if (entry.present) {
            if (!has(bytes, pos, 6)) {
                throw std::runtime_error(
                        "truncated BParInternalMod chunk header");
            }
            ChunkHeader chunk{ pos, u16le(bytes, pos), u32le(bytes, pos + 2),
                pos + 6 };
            if (chunk.payload_size > bytes.size() - chunk.payload_offset) {
                throw std::runtime_error(
                        "BParInternalMod chunk size is out of bounds");
            }
            entry.chunk = chunk;
            entry.internal_modulator =
                    std::make_shared<InternalModulatorPayload>(
                            parse_internal_modulator_array_entry(bytes, chunk,
                                    context_ids_enabled,
                                    runtime_type_mappings));
            pos = entry.internal_modulator->end_offset;
        }
        out.entries.push_back(std::move(entry));
    }
    out.end_offset = pos;
    return out;
}

bool mod_target_reads_s8(std::string_view name) {
    static constexpr std::array explicit_names{
        std::string_view{ "filterCutoff" },
        std::string_view{ "filterQ" },
        std::string_view{ "filterBandwidth" },
        std::string_view{ "formantTalk" },
        std::string_view{ "formantSize" },
        std::string_view{ "formantSharp" },
        std::string_view{ "cutoffLP" },
        std::string_view{ "cutoffHP" },
        std::string_view{ "resoLP" },
        std::string_view{ "resoHP" },
        std::string_view{ "filterFeedback" },
        std::string_view{ "filterFM" },
        std::string_view{ "intensity" },
        std::string_view{ "intensity_nc" },
        std::string_view{ "intensity_upper" },
        std::string_view{ "frequency" },
        std::string_view{ "pulseWidth" },
        std::string_view{ "startPhase" },
        std::string_view{ "eqFreq1" },
        std::string_view{ "eqBandWidth1" },
        std::string_view{ "eqGain1" },
        std::string_view{ "eqFreq2" },
        std::string_view{ "eqBandWidth2" },
        std::string_view{ "eqGain2" },
        std::string_view{ "eqFreq3" },
        std::string_view{ "eqBandWidth3" },
        std::string_view{ "eqGain3" },
        std::string_view{ "vfShift" },
        std::string_view{ "vfType" },
        std::string_view{ "vfBypass" },
        std::string_view{ "sendLevelDelay" },
        std::string_view{ "sendLevelChorus" },
        std::string_view{ "sendLevelFlanger" },
        std::string_view{ "sendLevelPhaser" },
        std::string_view{ "sendLevelReverb" },
        std::string_view{ "scLevelPGM" },
        std::string_view{ "distortionIntensity" },
        std::string_view{ "crywahPedal" },
        std::string_view{ "dyx_morph" },
        std::string_view{ "dyx_dry" },
        std::string_view{ "skr_tone" },
        std::string_view{ "skr_drive" },
        std::string_view{ "sslgeq_hp_freq" },
        std::string_view{ "sslgeq_lf_gain" },
        std::string_view{ "sslgeq_lf_freq" },
        std::string_view{ "sslgeq_lmf_gain" },
        std::string_view{ "sslgeq_lmf_freq" },
        std::string_view{ "sslgeq_lmf_q" },
        std::string_view{ "sslgeq_hmf_gain" },
        std::string_view{ "sslgeq_hmf_freq" },
        std::string_view{ "sslgeq_hmf_q" },
        std::string_view{ "sslgeq_hf_gain" },
        std::string_view{ "sslgeq_hf_freq" },
        std::string_view{ "sslgeq_lp_freq" },
        std::string_view{ "tape_gain" },
        std::string_view{ "tape_warmth" },
        std::string_view{ "tape_hfrolloff" },
        std::string_view{ "stereoSpreadIntensity" },
        std::string_view{ "stereoPan" },
        std::string_view{ "shaper" },
        std::string_view{ "bitdepth" },
        std::string_view{ "downsample" },
        std::string_view{ "noiselevel" },
        std::string_view{ "noisecolor" },
        std::string_view{ "off_distance" },
        std::string_view{ "off_azimuth" },
        std::string_view{ "off_x" },
        std::string_view{ "off_y" },
        std::string_view{ "ahdsr_attack" },
        std::string_view{ "ahdsr_hold" },
        std::string_view{ "ahdsr_decay" },
        std::string_view{ "ahdsr_sustain" },
        std::string_view{ "ahdsr_release" },
        std::string_view{ "dbd_decay1" },
        std::string_view{ "dbd_break" },
        std::string_view{ "dbd_decay2" },
    };
    if (std::find(explicit_names.begin(), explicit_names.end(), name) !=
            explicit_names.end())
        return true;
    auto decimal_in_range = [](std::string_view text, unsigned low,
                                    unsigned high) {
        if (text.empty())
            return false;
        unsigned value = 0;
        for (const char c : text) {
            if (c < '0' || c > '9')
                return false;
            value = value * 10U + static_cast<unsigned>(c - '0');
        }
        return value >= low && value <= high;
    };
    if (name.starts_with("sendLevel")) {
        return decimal_in_range(name.substr(9), 0, 7);
    }
    if (name.starts_with("scLevelB")) {
        const auto suffix = name.substr(8);
        return suffix.size() == 2 && decimal_in_range(suffix, 0, 15);
    }
    for (const auto prefix :
            { std::string_view{ "fm7_level" }, std::string_view{ "fm7_time" },
                    std::string_view{ "fm7_slope" } }) {
        if (name.starts_with(prefix)) {
            return decimal_in_range(name.substr(prefix.size()), 1, 8);
        }
    }
    constexpr std::string_view arp_prefix{ "arp32step_v" };
    return name.starts_with(arp_prefix) &&
           decimal_in_range(name.substr(arp_prefix.size()), 1, 32);
}

ExternalModulatorPayload parse_external_modulator_array_entry(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::optional<std::uint32_t> creator_version_packed) {
    if (chunk.type != 0x0c) {
        throw std::invalid_argument("BParExternalMod chunk type must be 0x0c");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BParExternalMod chunk is out of bounds");
    }
    const auto end = chunk.payload_offset + chunk.payload_size;
    ExternalModulatorPayload out;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, end), chunk.payload_offset, true, 0x104);
    const auto version = out.serializable.version;
    if (version < 0x100 || version > 0x104) {
        throw std::runtime_error("unsupported BParExternalMod version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count, const char *what) {
        if (pos > end || count > end - pos) {
            throw std::runtime_error(std::string("truncated ") + what);
        }
    };
    auto read_s32 = [&]() {
        need(4, "BParExternalMod S32");
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    auto read_s16 = [&]() {
        need(2, "BParExternalMod S16");
        const auto value = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
        return value;
    };
    auto read_f32 = [&]() {
        need(4, "BParExternalMod F32");
        const auto bits = u32le(bytes, pos);
        pos += 4;
        float value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    };
    auto read_bool = [&]() {
        need(1, "BParExternalMod Boolean");
        return u8(bytes, pos++) != 0;
    };
    auto read_string = [&](bool nullable,
                               const char *what) -> std::optional<std::string> {
        const auto length = read_s32();
        if (nullable && length < 0)
            return std::nullopt;
        if (length < 0)
            throw std::runtime_error(
                    std::string(what) + " has negative length");
        need(static_cast<std::size_t>(length), what);
        std::string value(reinterpret_cast<const char *>(bytes.data() + pos),
                static_cast<std::size_t>(length));
        pos += static_cast<std::size_t>(length);
        return value;
    };

    out.phase_markers[0] = read_s32();
    const bool v100_new_layout =
            version == 0x100 &&
            creator_version_packed.value_or(0) == 0x060400ffU;
    out.base_layout_version = static_cast<std::uint16_t>(
            (version >= 0x101 || v100_new_layout) ? 2 : 1);
    out.target_count = read_s32();
    if (out.target_count < 0 || out.target_count > 16) {
        throw std::runtime_error(
                "BParExternalMod target count is outside [0, 16]");
    }
    out.targets.reserve(static_cast<std::size_t>(out.target_count));
    for (std::int32_t i = 0; i < out.target_count; ++i) {
        InternalModTargetPayload target;
        target.target_xml_name = *read_string(false, "BModTarget XML name");
        target.amount = read_f32();
        need(5, "BModTarget scalar fields");
        target.s16_a = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
        target.u8 = u8(bytes, pos++);
        target.s16_b = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
        if (auto assignment = read_string(
                    out.base_layout_version == 1, "BModTarget assignment")) {
            target.assignment = std::move(*assignment);
        }
        if (mod_target_reads_s8(target.target_xml_name)) {
            need(1, "BModTarget conditional S8");
            target.target_s8 = static_cast<std::int8_t>(u8(bytes, pos++));
        }
        target.flag = read_bool();
        out.targets.push_back(std::move(target));
    }
    for (auto &target : out.targets) {
        need(1, "BModTarget transformation kind");
        auto &transform = target.transformation;
        transform.serialized_kind = u8(bytes, pos++);
        if (transform.serialized_kind <= 2) {
            transform.kind = static_cast<ModulationTransformationKind>(
                    transform.serialized_kind);
        }
        if (transform.serialized_kind == 1) {
            transform.enabled = read_bool();
            transform.values.reserve(128);
            for (int i = 0; i < 128; ++i)
                transform.values.push_back(read_f32());
        } else if (transform.serialized_kind == 2) {
            transform.enabled = read_bool();
            need(1, "BModCurve point count");
            const auto point_count = static_cast<std::int8_t>(u8(bytes, pos++));
            if (point_count > 0) {
                if (static_cast<std::size_t>(point_count) > (end - pos) / 12U) {
                    throw std::runtime_error(
                            "BModCurve point count is out of bounds");
                }
                for (int i = 0; i < point_count * 3; ++i) {
                    transform.values.push_back(read_f32());
                }
            }
        }
        transform.end_offset = pos;
    }

    out.name = *read_string(false, "BParExternalMod name");
    out.mode = read_s32();
    if (out.mode < 0 || out.mode > 2) {
        throw std::runtime_error("BParExternalMod mode is outside [0, 2]");
    }
    if (out.mode == 1) {
        out.serialized_source = read_s32();
        const auto source = *out.serialized_source;
        if (source >= 0 && source <= 3)
            out.source = source;
        else if (source == 4) {
            out.source = 4;
            need(1, "BParExternalMod controller");
            out.controller = u8(bytes, pos++);
        } else if (source >= 5 && source <= 11)
            out.source = source + 2;
        else if (source == 12)
            out.source = 5;
        else
            throw std::runtime_error("BParExternalMod source is out of range");
        if (version >= 0x102 && *out.source == 5) {
            out.source_parameter = read_s32();
        }
        out.s16 = read_s16();
    }
    out.flags[out.flag_count++] = read_bool();
    out.flags[out.flag_count++] = read_bool();
    out.s32 = read_s32();
    if (version >= 0x103)
        out.flags[out.flag_count++] = read_bool();
    if (version >= 0x104)
        out.flags[out.flag_count++] = read_bool();
    out.phase_markers[1] = read_s32();
    out.phase_markers[2] = read_s32();
    if (pos != end) {
        throw std::runtime_error("BParExternalMod chunk has trailing bytes: " +
                                 hex(bytes.subspan(pos, end - pos)));
    }
    out.end_offset = pos;
    return out;
}

ParameterArrayPayload parse_external_modulator_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled) {
    ParameterArrayPayload out;
    out.prefix =
            parse_parameter_array_prefix(bytes, offset, context_ids_enabled);
    if (out.prefix.serializable.version < 0x13)
        out.prefix.entry_count = 32;
    auto pos = out.prefix.entries_offset;
    out.entries.reserve(static_cast<std::size_t>(out.prefix.entry_count));
    for (std::int32_t i = 0; i < out.prefix.entry_count; ++i) {
        if (!has(bytes, pos, 1)) {
            throw std::runtime_error(
                    "truncated external-modulator array entry");
        }
        ParameterArrayEntry entry;
        entry.present = u8(bytes, pos++) != 0;
        if (out.prefix.version_0x11_context_ids) {
            if (!has(bytes, pos, 4)) {
                throw std::runtime_error(
                        "truncated external-modulator context id");
            }
            entry.context_id = static_cast<std::int32_t>(u32le(bytes, pos));
            pos += 4;
        }
        if (entry.present) {
            if (!has(bytes, pos, 6)) {
                throw std::runtime_error(
                        "truncated BParExternalMod chunk header");
            }
            const ChunkHeader chunk{ pos, u16le(bytes, pos),
                u32le(bytes, pos + 2), pos + 6 };
            if (chunk.type != 0x0c) {
                throw std::runtime_error(
                        "external-modulator array child is not type 0x0c");
            }
            if (chunk.payload_size > bytes.size() - chunk.payload_offset) {
                throw std::runtime_error(
                        "BParExternalMod chunk size is out of bounds");
            }
            entry.chunk = chunk;
            entry.external_modulator =
                    std::make_shared<ExternalModulatorPayload>(
                            parse_external_modulator_array_entry(bytes, chunk));
            pos = entry.external_modulator->end_offset;
        }
        out.entries.push_back(std::move(entry));
    }
    out.end_offset = pos;
    return out;
}

ParScriptPayload detail::patch::parse_par_script_bounded(
        std::span<const std::byte> bytes, std::size_t offset, std::size_t end) {
    ParScriptPayload out;
    if (offset > end || end > bytes.size()) {
        throw std::invalid_argument("BParScript bounds are invalid");
    }
    out.serializable = parse_serializable_header(
            bytes.subspan(0, end), offset, false, 0x60);
    if (supports_par_script_version(out.serializable.version) !=
            Support::supported) {
        throw std::runtime_error("unsupported BParScript version");
    }
    auto pos = out.serializable.payload_offset;
    out.source_text = read_bstring(bytes, pos, end, "BParScript source text");
    if (end - std::min(end, pos) < 3) {
        throw std::runtime_error("truncated BParScript flags");
    }
    out.source_editor_open = u8(bytes, pos++) != 0;
    out.touched_but_not_applied = u8(bytes, pos++) != 0;
    out.bypass = u8(bytes, pos++) != 0;
    if (out.serializable.version == 0x50) {
        out.version_0x50_password =
                read_bstring(bytes, pos, end, "BParScript v0x50 password");
    } else {
        if (end - std::min(end, pos) < 4) {
            throw std::runtime_error("truncated BParScript byte-array count");
        }
        const auto count = static_cast<std::size_t>(u32le(bytes, pos));
        pos += 4;
        if (count > end - pos) {
            throw std::runtime_error(
                    "BParScript byte-array count is out of bounds");
        }
        out.password_hash.assign(
                bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                bytes.begin() + static_cast<std::ptrdiff_t>(pos + count));
        pos += count;
    }
    out.description = read_bstring(bytes, pos, end, "BParScript description");
    out.text_file_name =
            read_bstring(bytes, pos, end, "BParScript text filename");
    if (end - std::min(end, pos) < 4) {
        throw std::runtime_error("truncated BParScript BString-array count");
    }
    const auto count = static_cast<std::size_t>(u32le(bytes, pos));
    pos += 4;
    if (count > end - pos) {
        throw std::runtime_error(
                "BParScript BString-array count is out of bounds");
    }
    out.persistent_variables.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        out.persistent_variables.push_back(
                read_bstring(bytes, pos, end, "BParScript array BString"));
    }
    out.end_offset = pos;
    return out;
}

ParScriptPayload parse_par_script(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 6)
        throw std::invalid_argument("BParScript chunk type must be 6");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BParScript chunk is out of bounds");
    }
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    auto out = parse_par_script_bounded(bytes, chunk.payload_offset, chunk_end);
    out.chunk = chunk;
    if (out.end_offset != chunk_end) {
        throw std::runtime_error("BParScript chunk has trailing bytes");
    }
    return out;
}

ParScriptPayload parse_par_script_payload(
        std::span<const std::byte> bytes, std::size_t offset) {
    return parse_par_script_bounded(bytes, offset, bytes.size());
}

QuickBrowseDataPayload parse_quick_browse_data(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x4e) {
        throw std::invalid_argument("QuickBrowseData chunk type must be 0x4e");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("QuickBrowseData chunk is out of bounds");
    }
    QuickBrowseDataPayload out;
    out.chunk = chunk;
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, chunk_end), chunk.payload_offset, false, 1);
    if (out.serializable.version != 1) {
        throw std::runtime_error("unsupported QuickBrowseData version");
    }
    const auto pos = out.serializable.payload_offset;
    if (chunk_end - std::min(chunk_end, pos) != 4) {
        throw std::runtime_error(
                "QuickBrowseData payload size must be four bytes");
    }
    out.value = static_cast<std::int32_t>(u32le(bytes, pos));
    out.end_offset = pos + 4;
    return out;
}

} // namespace libnki
