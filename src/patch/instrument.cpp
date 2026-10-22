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

GroupSnapshotPayload parse_group_snapshot(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    GroupSnapshotPayload out;
    out.prefix = parse_group_snapshot_prefix(bytes, offset);
    auto pos = out.prefix.child_serializables_offset;

    out.effect_array = parse_parameter_array(
            bytes, pos, context_ids_enabled, runtime_type_mappings);
    pos = out.effect_array.end_offset;
    out.source_mode = parse_source_mode(bytes, pos);
    pos = out.source_mode.end_offset;

    if (!has(bytes, pos, 2)) {
        throw std::runtime_error("truncated BGroupSnapshot post-source flags");
    }
    out.flags_after_source_mode[0] = u8(bytes, pos++) != 0;
    out.flags_after_source_mode[1] = u8(bytes, pos++) != 0;

    out.internal_modulator_array = parse_internal_modulator_array(
            bytes, pos, context_ids_enabled, runtime_type_mappings);
    pos = out.internal_modulator_array.end_offset;
    out.external_modulator_array =
            parse_external_modulator_array(bytes, pos, context_ids_enabled);
    pos = out.external_modulator_array.end_offset;

    // versions 2 and 3 both carry the trailing purge bool
    if (out.prefix.serializable.version >= 2) {
        if (!has(bytes, pos, 1)) {
            throw std::runtime_error("truncated BGroupSnapshot purge flag");
        }
        out.samples_purged = u8(bytes, pos++) != 0;
    }
    if (out.prefix.serializable.version == 4) {
        if (!has(bytes, pos, 8)) {
            throw std::runtime_error(
                    "truncated BGroupSnapshot version-4 fields");
        }
        out.version_4_s32.push_back(
                static_cast<std::int32_t>(u32le(bytes, pos)));
        pos += 4;
        out.version_4_s32.push_back(
                static_cast<std::int32_t>(u32le(bytes, pos)));
        pos += 4;
    }
    out.end_offset = pos;
    return out;
}

InsertBusPayload parse_insert_bus(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    InsertBusPayload out;
    out.serializable = parse_serializable_header(bytes, offset, true, 0x12);
    const auto version = out.serializable.version;
    if (version != 1 && (version < 0x10 || version > 0x12)) {
        throw std::runtime_error("unsupported BInsertBus version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count) {
        if (!has(bytes, pos, count))
            throw std::runtime_error("truncated BInsertBus");
    };
    auto read_s32 = [&]() {
        need(4);
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    auto read_f32 = [&]() {
        need(4);
        const auto bits = u32le(bytes, pos);
        pos += 4;
        float value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    };
    auto read_utf16 = [&]() {
        need(4);
        const auto count = static_cast<std::size_t>(u32le(bytes, pos));
        pos += 4;
        if (count > (bytes.size() - pos) / 2) {
            throw std::runtime_error("BInsertBus name length is out of bounds");
        }
        std::string value;
        for (std::size_t i = 0; i < count; ++i) {
            std::uint32_t cp = u16le(bytes, pos + i * 2);
            if (cp >= 0xd800 && cp <= 0xdbff) {
                if (i + 1 >= count) {
                    throw std::runtime_error(
                            "truncated BInsertBus UTF-16 surrogate");
                }
                const auto low = static_cast<std::uint32_t>(
                        u16le(bytes, pos + (i + 1) * 2));
                if (low < 0xdc00 || low > 0xdfff) {
                    throw std::runtime_error(
                            "invalid BInsertBus UTF-16 surrogate");
                }
                cp = 0x10000 + ((cp - 0xd800) << 10U) + (low - 0xdc00);
                ++i;
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                throw std::runtime_error(
                        "unexpected BInsertBus UTF-16 low surrogate");
            }
            value += utf8_from_codepoint(cp);
        }
        pos += count * 2;
        return value;
    };

    out.phase_markers[0] = read_s32(); // private phase has no fields
    out.phase_markers[1] = read_s32();
    out.name = read_utf16();
    out.level_pan[0] = read_f32();
    out.level_pan[1] = read_f32();
    if (version >= 0x11)
        out.version_0x11_s32 = read_s32();
    if (version == 0x12) {
        need(2);
        out.version_0x12_flags.push_back(u8(bytes, pos++) != 0);
        out.version_0x12_flags.push_back(u8(bytes, pos++) != 0);
    }
    out.phase_markers[2] = read_s32();

    if (version == 1) {
        out.effect_array = parse_parameter_array(
                bytes, pos, context_ids_enabled, runtime_type_mappings);
        pos = out.effect_array.end_offset;
    } else {
        need(6);
        ChunkHeader child{ pos, u16le(bytes, pos), u32le(bytes, pos + 2),
            pos + 6 };
        if (child.type != 0x3a) {
            throw std::runtime_error(
                    "BInsertBus effect-array chunk type mismatch");
        }
        if (child.payload_size > bytes.size() - child.payload_offset) {
            throw std::runtime_error(
                    "BInsertBus effect-array chunk is out of bounds");
        }
        out.effect_array_chunk = child;
        out.effect_array = parse_parameter_array(bytes, child.payload_offset,
                context_ids_enabled, runtime_type_mappings);
        const auto child_end = child.payload_offset + child.payload_size;
        if (out.effect_array.end_offset != child_end) {
            throw std::runtime_error(
                    "BInsertBus effect-array chunk has trailing bytes");
        }
        pos = child_end;
    }
    out.end_offset = pos;
    return out;
}

SnapshotPayload parse_snapshot(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    SnapshotPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 3);
    if (out.serializable.version < 1) {
        throw std::runtime_error("unsupported BSnapshot version");
    }
    auto pos = out.serializable.payload_offset;
    bool read_main_objects = true;
    if (out.serializable.version == 3) {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BSnapshot discriminator");
        const auto discriminator = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        out.version_3_discriminator = discriminator;
        // only 0 and 1 carry groups and program objects; every other bit
        // pattern skips straight to the string arrays
        read_main_objects = static_cast<std::uint32_t>(discriminator) <= 1U;
    }

    if (read_main_objects) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error("truncated BSnapshot group chunk");
        ChunkHeader group_chunk{ pos, u16le(bytes, pos), u32le(bytes, pos + 2),
            pos + 6 };
        const auto group_header =
                parse_snapshot_group_array_header(bytes, group_chunk);
        out.group_array = group_header;
        auto group_pos = group_header.groups_offset;
        const auto group_end =
                group_chunk.payload_offset + group_chunk.payload_size;
        out.groups.reserve(static_cast<std::size_t>(group_header.group_count));
        for (std::int32_t i = 0; i < group_header.group_count; ++i) {
            auto group = parse_group_snapshot(bytes.subspan(0, group_end),
                    group_pos, context_ids_enabled, runtime_type_mappings);
            group_pos = group.end_offset;
            out.groups.push_back(std::move(group));
        }
        if (group_pos != group_end) {
            throw std::runtime_error(
                    "BSnapshot group chunk has trailing bytes");
        }
        pos = group_end;

        out.master_effect_array = parse_parameter_array(
                bytes, pos, context_ids_enabled, runtime_type_mappings);
        pos = out.master_effect_array->end_offset;
        out.program_effect_array = parse_parameter_array(
                bytes, pos, context_ids_enabled, runtime_type_mappings);
        pos = out.program_effect_array->end_offset;
        out.insert_buses.reserve(16);
        for (std::size_t i = 0; i < 16; ++i) {
            auto bus = parse_insert_bus(
                    bytes, pos, context_ids_enabled, runtime_type_mappings);
            pos = bus.end_offset;
            out.insert_buses.push_back(std::move(bus));
        }
        if (out.serializable.version == 3) {
            out.third_effect_array = parse_parameter_array(
                    bytes, pos, context_ids_enabled, runtime_type_mappings);
            pos = out.third_effect_array->end_offset;
        }
    }

    auto read_bstring_array =
            [&](std::vector<std::optional<std::string>> &values) {
                if (!has(bytes, pos, 4))
                    throw std::runtime_error(
                            "truncated BSnapshot string-array count");
                const auto count = static_cast<std::size_t>(u32le(bytes, pos));
                pos += 4;
                if (count > (bytes.size() - pos) / 4) {
                    throw std::runtime_error(
                            "BSnapshot string-array count is out of bounds");
                }
                values.reserve(count);
                for (std::size_t i = 0; i < count; ++i) {
                    const auto length =
                            static_cast<std::int32_t>(u32le(bytes, pos));
                    pos += 4;
                    if (length < 0) {
                        values.push_back(std::nullopt);
                        continue;
                    }
                    const auto size = static_cast<std::size_t>(length);
                    if (!has(bytes, pos, size)) {
                        throw std::runtime_error(
                                "BSnapshot BString length is out of bounds");
                    }
                    values.emplace_back(std::string(
                            reinterpret_cast<const char *>(bytes.data() + pos),
                            size));
                    pos += size;
                }
            };

    for (auto &values : out.string_arrays)
        read_bstring_array(values);
    if (out.serializable.version == 2) {
        out.third_effect_array = parse_parameter_array(
                bytes, pos, context_ids_enabled, runtime_type_mappings);
        pos = out.third_effect_array->end_offset;
    }
    out.end_offset = pos;
    return out;
}

SnapshotMetadataPayload parse_snapshot_metadata(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x51) {
        throw std::invalid_argument(
                "BSnapshotMetaData chunk type must be 0x51");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BSnapshotMetaData chunk is out of bounds");
    }
    SnapshotMetadataPayload out;
    out.chunk = chunk;
    const auto end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, end), chunk.payload_offset, false, 1);
    if (out.serializable.version != 1) {
        throw std::runtime_error("unsupported BSnapshotMetaData version");
    }
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 4) || pos + 4 > end) {
        throw std::runtime_error("truncated BSnapshotMetaData filename index");
    }
    out.translated_filename_table_index =
            static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    Document string_errors;
    auto string_0 = read_wstring(bytes, pos, end, string_errors);
    auto string_1 = read_wstring(bytes, pos, end, string_errors);
    if (!string_0 || !string_1 || !string_errors.errors.empty()) {
        throw std::runtime_error("invalid BSnapshotMetaData WString");
    }
    out.wide_string_0 = std::move(*string_0);
    out.wide_string_1 = std::move(*string_1);
    if (pos != end) {
        throw std::runtime_error("BSnapshotMetaData chunk has trailing bytes");
    }
    out.end_offset = pos;
    return out;
}

SnapshotPresetPayload parse_snapshot_preset_impl(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    SnapshotPresetPayload out;
    out.preset_prefix = parse_preset_impl_prefix(bytes, chunk);
    out.snapshot = parse_snapshot(bytes,
            out.preset_prefix.implementation_payload_offset,
            context_ids_enabled, runtime_type_mappings);
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    if (out.snapshot.end_offset != chunk_end) {
        throw std::runtime_error(
                "Snapshot PresetImpl chunk has trailing bytes");
    }
    out.end_offset = out.snapshot.end_offset;
    return out;
}

PresetPayload parse_preset(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings,
        std::optional<std::uint32_t> creator_version_packed) {
    PresetPayload out;
    out.prefix = parse_preset_impl_prefix(bytes, chunk);
    if (out.prefix.saved_preset_kind >
            static_cast<std::uint8_t>(PresetKind::snapshot)) {
        throw std::runtime_error(
                "PresetImpl kind is outside Preset::presetFactory range");
    }
    out.kind = static_cast<PresetKind>(out.prefix.saved_preset_kind);
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    auto pos = out.prefix.implementation_payload_offset;

    switch (out.kind) {
        case PresetKind::insert_fx:
        case PresetKind::send_fx: {
            // we read effect presets directly, without a nested CHUNKED header
            const ChunkHeader direct{ pos, 0x25,
                static_cast<std::uint32_t>(chunk_end - pos), pos };
            out.par_fx = parse_par_fx(bytes, direct, runtime_type_mappings);
            pos = out.par_fx->end_offset;
            break;
        }
        case PresetKind::source_mode:
            out.source_mode =
                    parse_source_mode(bytes.subspan(0, chunk_end), pos);
            pos = out.source_mode->end_offset;
            break;
        case PresetKind::insert_fx_chain:
        case PresetKind::send_fx_chain:
            out.effect_chain =
                    parse_parameter_array(bytes.subspan(0, chunk_end), pos,
                            context_ids_enabled, runtime_type_mappings);
            pos = out.effect_chain->end_offset;
            break;
        case PresetKind::script:
        case PresetKind::multi_script:
            out.script =
                    parse_par_script_payload(bytes.subspan(0, chunk_end), pos);
            pos = out.script->end_offset;
            break;
        case PresetKind::snapshot:
            out.snapshot = parse_snapshot(bytes.subspan(0, chunk_end), pos,
                    context_ids_enabled, runtime_type_mappings);
            pos = out.snapshot->end_offset;
            break;
        case PresetKind::modulation_table: {
            if (!has(bytes, pos, 1) || pos >= chunk_end) {
                throw std::runtime_error(
                        "truncated TablePreset transformation kind");
            }
            ModulationTransformationPayload value;
            const auto serialized_kind = u8(bytes, pos++);
            value.serialized_kind = serialized_kind;
            if (serialized_kind <= 2) {
                value.kind = static_cast<ModulationTransformationKind>(
                        serialized_kind);
            }
            auto read_float = [&]() {
                if (pos > chunk_end || chunk_end - pos < 4) {
                    throw std::runtime_error(
                            "truncated TablePreset transformation float");
                }
                const auto bits = u32le(bytes, pos);
                pos += 4;
                float result;
                std::memcpy(&result, &bits, sizeof(result));
                return result;
            };
            if (serialized_kind == 1) {
                if (pos >= chunk_end)
                    throw std::runtime_error("truncated BModTable flag");
                value.enabled = u8(bytes, pos++) != 0;
                value.values.reserve(128);
                for (std::size_t i = 0; i < 128; ++i) {
                    value.values.push_back(read_float());
                }
            } else if (serialized_kind == 2) {
                if (chunk_end - pos < 2)
                    throw std::runtime_error("truncated BModCurve header");
                value.enabled = u8(bytes, pos++) != 0;
                const auto point_count =
                        static_cast<std::int8_t>(u8(bytes, pos++));
                if (point_count > 0) {
                    const auto scalar_count =
                            static_cast<std::size_t>(point_count) * 3;
                    if (scalar_count > (chunk_end - pos) / 4) {
                        throw std::runtime_error(
                                "BModCurve point count is out of bounds");
                    }
                    value.values.reserve(scalar_count);
                    for (std::size_t i = 0; i < scalar_count; ++i) {
                        value.values.push_back(read_float());
                    }
                }
            }
            value.end_offset = pos;
            out.transformation = std::move(value);
            break;
        }
        case PresetKind::internal_modulator: {
            InternalModulatorPayload value;
            value.serializable = parse_serializable_header(
                    bytes.subspan(0, chunk_end), pos, true, 0x81);
            const auto version = value.serializable.version;
            if (version != 0x80 && version != 0x81) {
                throw std::runtime_error("unsupported BParInternalMod version");
            }
            pos = value.serializable.payload_offset;
            auto need = [&](std::size_t n, const char *what) {
                if (pos > chunk_end || n > chunk_end - pos) {
                    throw std::runtime_error(std::string("truncated ") + what);
                }
            };
            auto read_s32 = [&]() {
                need(4, "BParInternalMod S32");
                const auto result =
                        static_cast<std::int32_t>(u32le(bytes, pos));
                pos += 4;
                return result;
            };
            auto read_f32 = [&]() {
                need(4, "BParLFO F32");
                const auto bits = u32le(bytes, pos);
                pos += 4;
                float result;
                std::memcpy(&result, &bits, sizeof(result));
                return result;
            };
            auto read_bool = [&]() {
                need(1, "BParInternalMod Boolean");
                return u8(bytes, pos++) != 0;
            };
            auto read_string =
                    [&](bool nullable,
                            const char *what) -> std::optional<std::string> {
                const auto length = read_s32();
                if (nullable && length < 0)
                    return std::nullopt;
                if (length < 0)
                    throw std::runtime_error(
                            std::string(what) + " has negative length");
                need(static_cast<std::size_t>(length), what);
                std::string result(
                        reinterpret_cast<const char *>(bytes.data() + pos),
                        static_cast<std::size_t>(length));
                pos += static_cast<std::size_t>(length);
                return result;
            };

            value.phase_markers[0] = read_s32();
            const bool v80_uses_new_layout =
                    version == 0x80 &&
                    creator_version_packed.value_or(0) == 0x060400ffU;
            value.base_layout_version = static_cast<std::uint16_t>(
                    (version == 0x81 || v80_uses_new_layout) ? 2 : 1);
            value.target_count = read_s32();
            if (value.target_count < 0 || value.target_count > 16) {
                throw std::runtime_error(
                        "BParInternalMod target count is outside [0, 16]");
            }
            static constexpr std::array kConditionalTargetNames = {
                std::string_view{ "filterCutoff" },
                std::string_view{ "filterQ" },
                std::string_view{ "filterBandwidth" },
                std::string_view{ "formantTalk" },
                std::string_view{ "formantSize" },
                std::string_view{ "formantSharp" },
                std::string_view{ "cutoffLP" }, std::string_view{ "cutoffHP" },
                std::string_view{ "resoLP" }, std::string_view{ "resoHP" },
                std::string_view{ "filterFeedback" },
                std::string_view{ "filterFM" }, std::string_view{ "intensity" },
                std::string_view{ "intensity_nc" },
                std::string_view{ "intensity_upper" },
                std::string_view{ "frequency" },
                std::string_view{ "pulseWidth" },
                std::string_view{ "startPhase" }, std::string_view{ "eqFreq1" },
                std::string_view{ "eqBandWidth1" },
                std::string_view{ "eqGain1" }, std::string_view{ "eqFreq2" },
                std::string_view{ "eqBandWidth2" },
                std::string_view{ "eqGain2" }, std::string_view{ "eqFreq3" },
                std::string_view{ "eqBandWidth3" },
                std::string_view{ "eqGain3" }, std::string_view{ "vfShift" },
                std::string_view{ "vfType" }, std::string_view{ "vfBypass" },
                std::string_view{ "sendLevel0" },
                std::string_view{ "sendLevel1" },
                std::string_view{ "sendLevel2" },
                std::string_view{ "sendLevel3" },
                std::string_view{ "sendLevel4" },
                std::string_view{ "sendLevel5" },
                std::string_view{ "sendLevel6" },
                std::string_view{ "sendLevel7" },
                std::string_view{ "sendLevelDelay" },
                std::string_view{ "sendLevelChorus" },
                std::string_view{ "sendLevelFlanger" },
                std::string_view{ "sendLevelPhaser" },
                std::string_view{ "sendLevelReverb" },
                std::string_view{ "scLevelB00" },
                std::string_view{ "scLevelB01" },
                std::string_view{ "scLevelB02" },
                std::string_view{ "scLevelB03" },
                std::string_view{ "scLevelB04" },
                std::string_view{ "scLevelB05" },
                std::string_view{ "scLevelB06" },
                std::string_view{ "scLevelB07" },
                std::string_view{ "scLevelB08" },
                std::string_view{ "scLevelB09" },
                std::string_view{ "scLevelB10" },
                std::string_view{ "scLevelB11" },
                std::string_view{ "scLevelB12" },
                std::string_view{ "scLevelB13" },
                std::string_view{ "scLevelB14" },
                std::string_view{ "scLevelB15" },
                std::string_view{ "scLevelPGM" },
                std::string_view{ "distortionIntensity" },
                std::string_view{ "crywahPedal" },
                std::string_view{ "dyx_morph" }, std::string_view{ "dyx_dry" },
                std::string_view{ "skr_tone" }, std::string_view{ "skr_drive" },
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
                std::string_view{ "stereoPan" }, std::string_view{ "shaper" },
                std::string_view{ "bitdepth" },
                std::string_view{ "downsample" },
                std::string_view{ "noiselevel" },
                std::string_view{ "noisecolor" },
                std::string_view{ "off_distance" },
                std::string_view{ "off_azimuth" }, std::string_view{ "off_x" },
                std::string_view{ "off_y" }, std::string_view{ "ahdsr_attack" },
                std::string_view{ "ahdsr_hold" },
                std::string_view{ "ahdsr_decay" },
                std::string_view{ "ahdsr_sustain" },
                std::string_view{ "ahdsr_release" },
                std::string_view{ "dbd_decay1" },
                std::string_view{ "dbd_break" },
                std::string_view{ "dbd_decay2" },
                std::string_view{ "fm7_level1" },
                std::string_view{ "fm7_level2" },
                std::string_view{ "fm7_level3" },
                std::string_view{ "fm7_level4" },
                std::string_view{ "fm7_level5" },
                std::string_view{ "fm7_level6" },
                std::string_view{ "fm7_level7" },
                std::string_view{ "fm7_level8" },
                std::string_view{ "fm7_time1" },
                std::string_view{ "fm7_time2" },
                std::string_view{ "fm7_time3" },
                std::string_view{ "fm7_time4" },
                std::string_view{ "fm7_time5" },
                std::string_view{ "fm7_time6" },
                std::string_view{ "fm7_time7" },
                std::string_view{ "fm7_time8" },
                std::string_view{ "fm7_slope1" },
                std::string_view{ "fm7_slope2" },
                std::string_view{ "fm7_slope3" },
                std::string_view{ "fm7_slope4" },
                std::string_view{ "fm7_slope5" },
                std::string_view{ "fm7_slope6" },
                std::string_view{ "fm7_slope7" },
                std::string_view{ "fm7_slope8" },
                std::string_view{ "arp32step_v1" },
                std::string_view{ "arp32step_v2" },
                std::string_view{ "arp32step_v3" },
                std::string_view{ "arp32step_v4" },
                std::string_view{ "arp32step_v5" },
                std::string_view{ "arp32step_v6" },
                std::string_view{ "arp32step_v7" },
                std::string_view{ "arp32step_v8" },
                std::string_view{ "arp32step_v9" },
                std::string_view{ "arp32step_v10" },
                std::string_view{ "arp32step_v11" },
                std::string_view{ "arp32step_v12" },
                std::string_view{ "arp32step_v13" },
                std::string_view{ "arp32step_v14" },
                std::string_view{ "arp32step_v15" },
                std::string_view{ "arp32step_v16" },
                std::string_view{ "arp32step_v17" },
                std::string_view{ "arp32step_v18" },
                std::string_view{ "arp32step_v19" },
                std::string_view{ "arp32step_v20" },
                std::string_view{ "arp32step_v21" },
                std::string_view{ "arp32step_v22" },
                std::string_view{ "arp32step_v23" },
                std::string_view{ "arp32step_v24" },
                std::string_view{ "arp32step_v25" },
                std::string_view{ "arp32step_v26" },
                std::string_view{ "arp32step_v27" },
                std::string_view{ "arp32step_v28" },
                std::string_view{ "arp32step_v29" },
                std::string_view{ "arp32step_v30" },
                std::string_view{ "arp32step_v31" },
                std::string_view{ "arp32step_v32" }
            };
            value.targets.reserve(static_cast<std::size_t>(value.target_count));
            for (std::int32_t i = 0; i < value.target_count; ++i) {
                InternalModTargetPayload target;
                target.target_xml_name =
                        *read_string(false, "BModTarget XML name");
                target.amount = read_f32();
                need(5, "BModTarget scalar fields");
                target.s16_a = static_cast<std::int16_t>(u16le(bytes, pos));
                pos += 2;
                target.u8 = u8(bytes, pos++);
                target.s16_b = static_cast<std::int16_t>(u16le(bytes, pos));
                pos += 2;
                if (auto assignment =
                                read_string(value.base_layout_version == 1,
                                        "BModTarget assignment")) {
                    target.assignment = std::move(*assignment);
                }
                if (std::find(kConditionalTargetNames.begin(),
                            kConditionalTargetNames.end(),
                            target.target_xml_name) !=
                        kConditionalTargetNames.end()) {
                    need(1, "BModTarget conditional S8");
                    target.target_s8 =
                            static_cast<std::int8_t>(u8(bytes, pos++));
                }
                target.flag = read_bool();
                value.targets.push_back(std::move(target));
            }
            for (auto &target : value.targets) {
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
                    const auto point_count =
                            static_cast<std::int8_t>(u8(bytes, pos++));
                    if (point_count > 0) {
                        for (int i = 0; i < point_count * 3; ++i) {
                            transform.values.push_back(read_f32());
                        }
                    }
                }
                transform.end_offset = pos;
            }
            for (auto &flag : value.flags)
                flag = read_bool();
            value.s32 = read_s32();
            value.name = read_string(version == 0x80 && !v80_uses_new_layout,
                    "BParInternalMod name");
            value.modulator_type = read_s32();
            if (value.modulator_type < 0 || value.modulator_type >= 7) {
                throw std::runtime_error(
                        "BParInternalMod type is outside [0, 7)");
            }
            value.phase_markers[1] = read_s32();
            value.phase_markers[2] = read_s32();

            if (value.modulator_type == 1) {
                need(6, "BParLFO chunk header");
                ChunkHeader child{ pos, u16le(bytes, pos),
                    u32le(bytes, pos + 2), pos + 6 };
                if (child.type != 8 ||
                        child.payload_size > chunk_end - child.payload_offset) {
                    throw std::runtime_error("invalid BParLFO child chunk");
                }
                const auto child_end =
                        child.payload_offset + child.payload_size;
                InternalModLfoPayload lfo;
                lfo.chunk = child;
                lfo.serializable =
                        parse_serializable_header(bytes.subspan(0, child_end),
                                child.payload_offset, false, 0x73);
                const auto lfo_version = lfo.serializable.version;
                if (lfo_version < 0x70 || lfo_version > 0x73) {
                    throw std::runtime_error("unsupported BParLFO version");
                }
                pos = lfo.serializable.payload_offset;
                lfo.waveform = read_s32();
                if (lfo.waveform < 0 || lfo.waveform >= 7) {
                    throw std::runtime_error(
                            "BParLFO waveform is outside [0, 7)");
                }
                for (int i = 0; i < 4; ++i)
                    lfo.values.push_back(read_f32());
                lfo.flags.push_back(read_bool());
                if (lfo_version == 0x70) {
                    lfo.values.push_back(read_f32());
                    lfo.values.push_back(read_f32());
                } else {
                    for (int i = 0; i < 3; ++i)
                        lfo.values.push_back(read_f32());
                    lfo.flags.push_back(read_bool());
                    for (int i = 0; i < 3; ++i)
                        lfo.values.push_back(read_f32());
                    lfo.flags.push_back(read_bool());
                }
                if ((lfo_version == 0x70 && lfo.waveform == 5) ||
                        (lfo_version >= 0x71 &&
                                (lfo.waveform == 5 || lfo.waveform == 6))) {
                    for (int i = 0; i < 5; ++i)
                        lfo.values.push_back(read_f32());
                }
                if (lfo_version == 0x73)
                    lfo.flags.push_back(read_bool());
                if (pos != child_end)
                    throw std::runtime_error(
                            "BParLFO chunk has trailing bytes");
                lfo.end_offset = pos;
                value.lfo = std::move(lfo);
            } else if (value.modulator_type == 3 || value.modulator_type == 4 ||
                       value.modulator_type == 5) {
                need(6, "BParInternalMod child chunk header");
                const std::uint16_t expected_type =
                        value.modulator_type == 3
                                ? 9
                                : (value.modulator_type == 4 ? 10 : 11);
                ChunkHeader child{ pos, u16le(bytes, pos),
                    u32le(bytes, pos + 2), pos + 6 };
                if (child.type != expected_type ||
                        child.payload_size > chunk_end - child.payload_offset) {
                    throw std::runtime_error(
                            "invalid BParInternalMod child chunk");
                }
                const auto child_end =
                        child.payload_offset + child.payload_size;
                InternalModChildPayload child_value;
                child_value.chunk = child;
                const std::uint16_t max_version =
                        value.modulator_type == 3
                                ? 0x81
                                : (value.modulator_type == 4 ? 0x60 : 0x51);
                child_value.serializable =
                        parse_serializable_header(bytes.subspan(0, child_end),
                                child.payload_offset, false, max_version);
                const auto child_version = child_value.serializable.version;
                pos = child_value.serializable.payload_offset;
                if (value.modulator_type == 3) {
                    if (child_version != 0x80 && child_version != 0x81) {
                        throw std::runtime_error("unsupported BParArp version");
                    }
                    const auto sentinel = read_s32();
                    if (sentinel != 0)
                        throw std::runtime_error(
                                "BParArp sentinel is not zero");
                    child_value.s32.push_back(sentinel);
                    child_value.flags.push_back(read_bool());
                    child_value.s32.push_back(read_s32());
                    child_value.flags.push_back(read_bool());
                    need(4, "BParArp step count");
                    const auto serialized_count = u32le(bytes, pos);
                    pos += 4;
                    child_value.u32.push_back(serialized_count);
                    const auto stored_count =
                            std::min<std::uint32_t>(serialized_count, 32);
                    for (std::uint32_t i = 0; i < stored_count; ++i) {
                        child_value.f32.push_back(read_f32());
                    }
                    child_value.f32.push_back(read_f32());
                    child_value.f32.push_back(read_f32());
                    if (child_version == 0x81) {
                        child_value.f32.push_back(read_f32());
                        child_value.f32.push_back(read_f32());
                        child_value.flags.push_back(read_bool());
                    }
                } else if (value.modulator_type == 4) {
                    if (child_version != 0x60) {
                        throw std::runtime_error(
                                "unsupported BParEnvF version");
                    }
                    for (int i = 0; i < 4; ++i)
                        child_value.f32.push_back(read_f32());
                } else {
                    if (child_version != 0x50 && child_version != 0x51) {
                        throw std::runtime_error(
                                "unsupported BParGlide version");
                    }
                    const auto serialized_mode = read_s32();
                    if (serialized_mode != 1 && serialized_mode != 2) {
                        throw std::runtime_error(
                                "BParGlide mode is not 1 or 2");
                    }
                    child_value.s32.push_back(serialized_mode);
                    child_value.f32.push_back(read_f32());
                    child_value.f32.push_back(read_f32());
                    if (child_version == 0x51) {
                        child_value.f32.push_back(read_f32());
                        child_value.f32.push_back(read_f32());
                        child_value.flags.push_back(read_bool());
                    }
                }
                if (pos != child_end) {
                    throw std::runtime_error(
                            "BParInternalMod child chunk has trailing bytes");
                }
                child_value.end_offset = pos;
                if (value.modulator_type == 3)
                    value.arp = std::move(child_value);
                else if (value.modulator_type == 4)
                    value.env_f = std::move(child_value);
                else
                    value.glide = std::move(child_value);
            } else if (value.modulator_type == 2) {
                need(6, "BParEnv chunk header");
                ChunkHeader env_chunk{ pos, u16le(bytes, pos),
                    u32le(bytes, pos + 2), pos + 6 };
                if (env_chunk.type != 7 ||
                        env_chunk.payload_size >
                                chunk_end - env_chunk.payload_offset) {
                    throw std::runtime_error("invalid BParEnv child chunk");
                }
                const auto env_end =
                        env_chunk.payload_offset + env_chunk.payload_size;
                InternalModEnvelopePayload env;
                env.chunk = env_chunk;
                env.serializable =
                        parse_serializable_header(bytes.subspan(0, env_end),
                                env_chunk.payload_offset, true, 0x90);
                if (env.serializable.version != 0x90) {
                    throw std::runtime_error("unsupported BParEnv version");
                }
                pos = env.serializable.payload_offset;
                env.phase_markers[0] = read_s32();
                env.phase_markers[1] = read_s32();
                env.envelope_type = read_s32();
                if (env.envelope_type < 0 || env.envelope_type >= 3) {
                    throw std::runtime_error("BParEnv type is outside [0, 3)");
                }
                env.phase_markers[2] = read_s32();
                need(6, "BParEnv variant chunk header");
                const std::uint16_t expected_env_type =
                        static_cast<std::uint16_t>(0x3f + env.envelope_type);
                ChunkHeader variant_chunk{ pos, u16le(bytes, pos),
                    u32le(bytes, pos + 2), pos + 6 };
                if (variant_chunk.type != expected_env_type ||
                        variant_chunk.payload_size >
                                env_end - variant_chunk.payload_offset) {
                    throw std::runtime_error("invalid BParEnv variant chunk");
                }
                const auto variant_end = variant_chunk.payload_offset +
                                         variant_chunk.payload_size;
                InternalModChildPayload variant;
                variant.chunk = variant_chunk;
                const std::uint16_t max_env_version =
                        env.envelope_type == 0 ? 0x11 : 0x12;
                variant.serializable = parse_serializable_header(
                        bytes.subspan(0, variant_end),
                        variant_chunk.payload_offset, false, max_env_version);
                const auto env_version = variant.serializable.version;
                pos = variant.serializable.payload_offset;
                if (env.envelope_type == 0) {
                    if (env_version != 0x10 && env_version != 0x11) {
                        throw std::runtime_error(
                                "unsupported BParEnv_AHDSR version");
                    }
                    for (int i = 0; i < 6; ++i)
                        variant.f32.push_back(read_f32());
                    variant.flags.push_back(read_bool());
                    if (env_version == 0x10) {
                        for (int i = 0; i < 4; ++i)
                            variant.f32.push_back(read_f32());
                    } else {
                        for (int stage = 0; stage < 4; ++stage) {
                            for (int i = 0; i < 3; ++i)
                                variant.f32.push_back(read_f32());
                            variant.flags.push_back(read_bool());
                        }
                    }
                } else if (env.envelope_type == 1) {
                    if (env_version < 0x10 || env_version > 0x12) {
                        throw std::runtime_error(
                                "unsupported BParEnv_FM7 version");
                    }
                    const auto point_last_index = read_s32();
                    variant.s32.push_back(point_last_index);
                    variant.s32.push_back(read_s32());
                    variant.s32.push_back(read_s32());
                    if (point_last_index < -1 || point_last_index > 31) {
                        throw std::runtime_error(
                                "BParEnv_FM7 point index is outside [-1, 31]");
                    }
                    for (std::int32_t i = 0; i <= point_last_index; ++i) {
                        for (int lane = 0; lane < 3; ++lane)
                            variant.f32.push_back(read_f32());
                    }
                    const bool v10_short =
                            env_version == 0x10 &&
                            creator_version_packed.value_or(0) != 0x050500ffU;
                    if (v10_short) {
                        variant.f32.push_back(read_f32());
                    } else {
                        if (env_version == 0x12) {
                            variant.flags.push_back(read_bool());
                            variant.flags.push_back(read_bool());
                        }
                        for (int i = 0; i < 3; ++i)
                            variant.f32.push_back(read_f32());
                        variant.flags.push_back(read_bool());
                    }
                } else {
                    if (env_version < 0x10 || env_version > 0x12) {
                        throw std::runtime_error(
                                "unsupported BParEnv_DBD version");
                    }
                    for (int i = 0; i < 3; ++i)
                        variant.f32.push_back(read_f32());
                    if (env_version == 0x12) {
                        for (int stage = 0; stage < 2; ++stage) {
                            for (int i = 0; i < 3; ++i)
                                variant.f32.push_back(read_f32());
                            variant.flags.push_back(read_bool());
                        }
                    } else {
                        variant.f32.push_back(read_f32());
                        variant.f32.push_back(read_f32());
                    }
                    if (env_version >= 0x11)
                        variant.flags.push_back(read_bool());
                }
                if (pos != variant_end)
                    throw std::runtime_error(
                            "BParEnv variant has trailing bytes");
                variant.end_offset = pos;
                env.child = std::move(variant);
                if (pos != env_end)
                    throw std::runtime_error(
                            "BParEnv chunk has trailing bytes");
                env.end_offset = pos;
                value.envelope = std::move(env);
            }
            value.end_offset = pos;
            out.internal_modulator = std::move(value);
            break;
        }
    }
    if (pos != chunk_end)
        throw std::runtime_error("PresetImpl chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

VoiceLimitPayload parse_voice_limit(
        std::span<const std::byte> bytes, std::size_t offset) {
    VoiceLimitPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x60);
    if (out.serializable.version != 0x60) {
        throw std::runtime_error("unsupported BVoiceLimit version");
    }
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 4))
        throw std::runtime_error("truncated BVoiceLimit name length");
    const auto count = static_cast<std::size_t>(u32le(bytes, pos));
    pos += 4;
    if (count > (bytes.size() - pos) / 2) {
        throw std::runtime_error("BVoiceLimit name length is out of bounds");
    }
    for (std::size_t i = 0; i < count; ++i) {
        std::uint32_t cp = u16le(bytes, pos + i * 2);
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 >= count)
                throw std::runtime_error("truncated BVoiceLimit surrogate");
            const auto low =
                    static_cast<std::uint32_t>(u16le(bytes, pos + (i + 1) * 2));
            if (low < 0xdc00 || low > 0xdfff) {
                throw std::runtime_error("invalid BVoiceLimit surrogate");
            }
            cp = 0x10000 + ((cp - 0xd800) << 10U) + (low - 0xdc00);
            ++i;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) {
            throw std::runtime_error("unexpected BVoiceLimit low surrogate");
        }
        out.name += utf8_from_codepoint(cp);
    }
    pos += count * 2;
    if (!has(bytes, pos, 15))
        throw std::runtime_error("truncated BVoiceLimit fields");
    out.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.flag = u8(bytes, pos++) != 0;
    for (auto &value : out.s32) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    out.end_offset = pos;
    return out;
}

VoiceGroupChunkPayload parse_voice_group_chunk(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x32)
        throw std::invalid_argument("voice-group chunk type must be 0x32");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("voice-group chunk is out of bounds");
    }
    VoiceGroupChunkPayload out;
    out.chunk = chunk;
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    auto pos = chunk.payload_offset;
    out.global_limit = parse_voice_limit(bytes.subspan(0, chunk_end), pos);
    pos = out.global_limit.end_offset;
    if (out.presence_mask.size() > chunk_end - std::min(chunk_end, pos)) {
        throw std::runtime_error("truncated voice-group presence mask");
    }
    for (auto &byte : out.presence_mask)
        byte = u8(bytes, pos++);
    for (std::uint16_t index = 0; index < 128; ++index) {
        if (((out.presence_mask[index >> 3] >> (index & 7)) & 1U) == 0)
            continue;
        auto value = parse_voice_limit(bytes.subspan(0, chunk_end), pos);
        pos = value.end_offset;
        out.active_limits.push_back(
                { static_cast<std::uint8_t>(index), std::move(value) });
    }
    if (pos != chunk_end)
        throw std::runtime_error("voice-group chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

GroupPublicPayload parse_group_public_payload(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t group_version) {
    if (supports_group_struct_version(group_version) != Support::supported) {
        throw std::runtime_error("unsupported BGroup version");
    }
    GroupPublicPayload out;
    auto pos = offset;
    out.name = read_utf16_string(bytes, pos, bytes.size(), "BGroup name");
    constexpr std::size_t kScalarBytes = 3 * 4 + 4 + 4 + 2 + 2 * 4 + 2 + 4;
    if (!has(bytes, pos, kScalarBytes)) {
        throw std::runtime_error("truncated BGroup public fields");
    }
    for (auto &value : out.f32) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    for (auto &flag : out.flags)
        flag = u8(bytes, pos++) != 0;
    out.s32_before_s16 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    for (auto &value : out.s32_after_s16) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    for (auto &flag : out.trailing_flags)
        flag = u8(bytes, pos++) != 0;
    out.enum_0_to_2 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.enum_0_to_2 < 0 || out.enum_0_to_2 >= 3) {
        throw std::runtime_error("BGroup public enum is outside [0, 3)");
    }
    out.end_offset = pos;
    return out;
}

StartCriteriaPayload parse_start_criteria(
        std::span<const std::byte> bytes, std::size_t offset) {
    StartCriteriaPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x70);
    if (out.serializable.version != 0x70) {
        throw std::runtime_error("unsupported BParStartCriteria version");
    }
    auto pos = out.serializable.payload_offset;
    constexpr std::size_t kPayloadBytes = 4 + 4 + 5 * 2 + 3 * 4 + 1;
    if (!has(bytes, pos, kPayloadBytes)) {
        throw std::runtime_error("truncated BParStartCriteria payload");
    }
    out.enum_0_to_5 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.enum_0_to_2 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.enum_0_to_5 < 0 || out.enum_0_to_5 >= 6 || out.enum_0_to_2 < 0 ||
            out.enum_0_to_2 >= 3) {
        throw std::runtime_error("BParStartCriteria enum is out of range");
    }
    for (auto &value : out.s16) {
        value = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
    }
    for (auto &value : out.s32) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    out.flag = u8(bytes, pos++) != 0;
    out.end_offset = pos;
    return out;
}

GroupDynamicsPayload parse_group_dynamics(
        std::span<const std::byte> bytes, std::size_t offset) {
    GroupDynamicsPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x10);
    if (out.serializable.version != 0x10) {
        throw std::runtime_error("unsupported BParGroupDynamics version");
    }
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, out.values.size() * sizeof(float))) {
        throw std::runtime_error("truncated BParGroupDynamics payload");
    }
    for (auto &value : out.values) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    out.end_offset = pos;
    return out;
}

GroupChildrenPayload parse_group_children(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t group_version,
        bool has_group_dynamics, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (supports_group_struct_version(group_version) != Support::supported) {
        throw std::runtime_error("unsupported BGroup version");
    }
    if (group_version < 0x93 && has_group_dynamics) {
        throw std::invalid_argument(
                "BGroup versions before 0x93 cannot contain group dynamics");
    }
    GroupChildrenPayload out;
    auto pos = offset;
    auto read_chunk = [&](std::uint16_t expected_type) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error("truncated BGroup child chunk");
        ChunkHeader chunk;
        chunk.type = u16le(bytes, pos);
        chunk.offset = pos;
        chunk.payload_size = u32le(bytes, pos + 2);
        chunk.payload_offset = pos + 6;
        if (chunk.type != expected_type) {
            throw std::runtime_error(
                    "unexpected BGroup child chunk type " +
                    std::to_string(chunk.type) + " at offset " +
                    std::to_string(chunk.offset) + ", expected " +
                    std::to_string(expected_type));
        }
        if (chunk.payload_size > bytes.size() - chunk.payload_offset) {
            throw std::runtime_error("BGroup child chunk is out of bounds");
        }
        return chunk;
    };
    // children store internal then external modulators (0x3b/0x3c); the effect
    // array (0x3a) belongs to the private phase
    static constexpr std::array<std::uint16_t, 2> kParameterArrayChunkTypes{
        0x3b, 0x3c
    };
    for (std::size_t i = 0; i < out.parameter_arrays.size(); ++i) {
        out.parameter_array_chunks[i] =
                read_chunk(kParameterArrayChunkTypes[i]);
        const auto chunk_end = out.parameter_array_chunks[i].payload_offset +
                               out.parameter_array_chunks[i].payload_size;
        if (i == 0) {
            out.parameter_arrays[i] =
                    parse_internal_modulator_array(bytes.subspan(0, chunk_end),
                            out.parameter_array_chunks[i].payload_offset,
                            context_ids_enabled, runtime_type_mappings);
        } else {
            out.parameter_arrays[i] =
                    parse_external_modulator_array(bytes.subspan(0, chunk_end),
                            out.parameter_array_chunks[i].payload_offset,
                            context_ids_enabled);
        }
        if (out.parameter_arrays[i].end_offset != chunk_end) {
            throw std::runtime_error(
                    "BGroup parameter-array " + std::to_string(i) +
                    " ends at " +
                    std::to_string(out.parameter_arrays[i].end_offset) +
                    ", expected " + std::to_string(chunk_end) + ", trailing " +
                    hex(bytes.subspan(out.parameter_arrays[i].end_offset,
                            chunk_end - out.parameter_arrays[i].end_offset)));
        }
        pos = chunk_end;
    }
    out.start_criteria_chunk = read_chunk(0x38);
    const auto criteria_end = out.start_criteria_chunk.payload_offset +
                              out.start_criteria_chunk.payload_size;
    pos = out.start_criteria_chunk.payload_offset;
    if (pos == criteria_end)
        throw std::runtime_error("truncated BGroup criteria mask");
    out.start_criteria_presence_mask = u8(bytes, pos++);
    for (std::uint8_t index = 0; index < 4; ++index) {
        if (((out.start_criteria_presence_mask >> index) & 1U) == 0)
            continue;
        auto value = parse_start_criteria(bytes.subspan(0, criteria_end), pos);
        pos = value.end_offset;
        out.start_criteria.emplace_back(index, std::move(value));
    }
    if (pos != criteria_end) {
        throw std::runtime_error(
                "BGroup start-criteria chunk has trailing bytes");
    }
    if (has_group_dynamics) {
        out.dynamics_chunk = read_chunk(0x4a);
        const auto dynamics_end = out.dynamics_chunk->payload_offset +
                                  out.dynamics_chunk->payload_size;
        out.dynamics = parse_group_dynamics(bytes.subspan(0, dynamics_end),
                out.dynamics_chunk->payload_offset);
        if (out.dynamics->end_offset != dynamics_end) {
            throw std::runtime_error(
                    "BGroup dynamics chunk has trailing bytes");
        }
        pos = dynamics_end;
    }
    out.end_offset = pos;
    return out;
}

AutomationObjectPayload parse_automation_object(
        std::span<const std::byte> bytes, std::size_t offset) {
    AutomationObjectPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x71);
    if (out.serializable.version != 0x70 && out.serializable.version != 0x71) {
        throw std::runtime_error("unsupported BAutomationObject version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count) {
        if (!has(bytes, pos, count)) {
            throw std::runtime_error("truncated BAutomationObject payload");
        }
    };
    need(5);
    out.enum_0_to_2 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.enum_0_to_2 < 0 || out.enum_0_to_2 >= 3) {
        throw std::runtime_error("BAutomationObject enum is outside [0, 3)");
    }
    out.flag = u8(bytes, pos++) != 0;
    if (out.serializable.version == 0x70) {
        need(1);
        out.version_0x70_boolean = u8(bytes, pos++) != 0;
    }
    need(2 + 4 + (out.serializable.version == 0x71 ? 4 : 0) + 8 + 4);
    out.u16 = u16le(bytes, pos);
    pos += 2;
    out.first_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.serializable.version == 0x71) {
        out.version_0x71_second_s32 =
                static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    for (auto &value : out.f32) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    const auto string_size = static_cast<std::size_t>(u32le(bytes, pos));
    pos += 4;
    if (string_size > bytes.size() - pos) {
        throw std::runtime_error(
                "BAutomationObject parameter-tag string is out of bounds");
    }
    out.parameter_tag.assign(
            reinterpret_cast<const char *>(bytes.data() + pos), string_size);
    pos += string_size;
    out.end_offset = pos;
    return out;
}

GroupPrivatePayload parse_group_private_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t group_version, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (supports_group_struct_version(group_version) != Support::supported) {
        throw std::runtime_error("unsupported BGroup version");
    }
    GroupPrivatePayload out;
    auto pos = offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count))
            throw std::runtime_error(std::string("truncated ") + what);
    };
    for (auto &run : out.byte_runs) {
        need(4, "BGroup byte-run count");
        run.declared_count = u32le(bytes, pos);
        pos += 4;
        const auto stored_count = std::min<std::size_t>(run.declared_count, 8);
        need(stored_count, "BGroup byte run");
        run.values.reserve(stored_count);
        for (std::size_t i = 0; i < stored_count; ++i)
            run.values.push_back(u8(bytes, pos++));
    }
    need(3 + 3 * 4 + 1 + 2 * 4, "BGroup private scalar prefix");
    for (auto &flag : out.leading_flags)
        flag = u8(bytes, pos++) != 0;
    for (auto &value : out.leading_s32) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    out.flag_before_s32_pair = u8(bytes, pos++) != 0;
    for (auto &value : out.s32_pair) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    out.parameter_array = parse_parameter_array(
            bytes, pos, context_ids_enabled, runtime_type_mappings);
    pos = out.parameter_array.end_offset;
    need(1, "BGroup flag after parameter array");
    out.flag_after_parameter_array = u8(bytes, pos++) != 0;
    out.source_mode = parse_source_mode(bytes, pos);
    pos = out.source_mode.end_offset;
    need(4, "BGroup automation capacity");
    out.automation_capacity = u32le(bytes, pos);
    pos += 4;
    if (out.automation_capacity != 0) {
        need(4, "BGroup automation serialized count");
        out.automation_serialized_count = u32le(bytes, pos);
        pos += 4;
        const auto count = std::min(
                out.automation_capacity, *out.automation_serialized_count);
        out.automation_objects.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto value = parse_automation_object(bytes, pos);
            pos = value.end_offset;
            out.automation_objects.push_back(std::move(value));
        }
    }
    if (group_version >= 0x91) {
        need(4, "BGroup v0x91 field");
        out.version_0x91_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    if (group_version >= 0x92) {
        need(2, "BGroup v0x92 flags");
        for (auto &flag : out.version_0x92_flags)
            flag = u8(bytes, pos++) != 0;
    }
    if (group_version >= 0x93) {
        need(1, "BGroup v0x93 flag");
        out.version_0x93_flag = u8(bytes, pos++) != 0;
    }
    if (group_version >= 0x94) {
        need(8, "BGroup v0x94 fields");
        for (auto &value : out.version_0x94_s32) {
            value = static_cast<std::int32_t>(u32le(bytes, pos));
            pos += 4;
        }
    }
    if (group_version >= 0x95) {
        need(1, "BGroup v0x95 field");
        out.version_0x95_u8 = u8(bytes, pos++);
    }
    need(4, "BGroup final S32");
    out.final_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.end_offset = pos;
    return out;
}

GroupPayload parse_group(std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    GroupPayload out;
    out.serializable = parse_serializable_header(bytes, offset, true, 0x96);
    if (supports_group_struct_version(out.serializable.version) !=
            Support::supported) {
        throw std::runtime_error("unsupported BGroup version");
    }
    auto pos = out.serializable.payload_offset;
    auto read_marker = [&](std::size_t index) {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BGroup phase marker");
        out.phase_markers[index] = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    };
    read_marker(0);
    out.private_payload =
            parse_group_private_payload(bytes, pos, out.serializable.version,
                    context_ids_enabled, runtime_type_mappings);
    pos = out.private_payload.end_offset;
    read_marker(1);
    out.public_payload =
            parse_group_public_payload(bytes, pos, out.serializable.version);
    pos = out.public_payload.end_offset;
    read_marker(2);
    const bool has_group_dynamics =
            out.serializable.version >= 0x93 &&
            out.private_payload.version_0x93_flag.value_or(false);
    out.children = parse_group_children(bytes, pos, out.serializable.version,
            has_group_dynamics, context_ids_enabled, runtime_type_mappings);
    out.end_offset = out.children.end_offset;
    return out;
}

ProgramGroupChunkPayload parse_program_group_chunk(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 0x33) {
        throw std::invalid_argument("program group chunk type must be 0x33");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("program group chunk is out of bounds");
    }
    ProgramGroupChunkPayload out;
    out.chunk = chunk;
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    auto pos = chunk.payload_offset;
    if (chunk_end - pos < 4)
        throw std::runtime_error("truncated program group count");
    out.group_count = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.group_count < 0 ||
            static_cast<std::uint32_t>(out.group_count) > chunk_end - pos) {
        throw std::runtime_error("program group count is out of bounds");
    }
    out.groups.reserve(static_cast<std::size_t>(out.group_count));
    for (std::int32_t i = 0; i < out.group_count; ++i) {
        auto group = parse_group(bytes.subspan(0, chunk_end), pos,
                context_ids_enabled, runtime_type_mappings);
        pos = group.end_offset;
        out.groups.push_back(std::move(group));
    }
    if (pos != chunk_end)
        throw std::runtime_error("program group chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

SampleSettingsPayload parse_sample_settings(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t zone_version) {
    if (supports_zone_struct_version(zone_version) != Support::supported) {
        throw std::runtime_error(
                "unsupported BZone version for BSampleSettings");
    }
    SampleSettingsPayload out;
    auto pos = offset;
    const auto required = static_cast<std::size_t>(
            2 * 4 + 1 + 2 * 4 + (zone_version < 0x96 ? 4 : 0) + 4 + 4 + 1 + 4);
    if (!has(bytes, pos, required)) {
        throw std::runtime_error("truncated BSampleSettings payload");
    }
    for (auto &value : out.leading_s32) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    out.u8 = u8(bytes, pos++);
    for (auto &value : out.middle_s32) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    if (zone_version < 0x96) {
        out.pre_0x96_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    out.trailing_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    auto bits = u32le(bytes, pos);
    pos += 4;
    std::memcpy(&out.f32, &bits, sizeof(out.f32));
    out.flag = u8(bytes, pos++) != 0;
    out.final_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.end_offset = pos;
    return out;
}

ZonePublicPayload parse_zone_public_payload(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t zone_version) {
    if (supports_zone_struct_version(zone_version) != Support::supported) {
        throw std::runtime_error("unsupported BZone version");
    }
    ZonePublicPayload out;
    auto pos = offset;
    constexpr std::size_t kCommonBytes = 3 * 4 + 9 * 2 + 3 * 4;
    if (!has(bytes, pos, kCommonBytes))
        throw std::runtime_error("truncated BZone public payload");
    out.sample_start = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.sample_end = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.sample_start_modulation_range =
            static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.low_velocity = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.high_velocity = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.low_key = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.high_key = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.fade_low_velocity = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.fade_high_velocity = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.fade_low_key = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.fade_high_key = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.root_key = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    auto read_f32 = [&] {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        float value{};
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    };
    out.volume = read_f32();
    out.pan = read_f32();
    out.tune = read_f32();
    bool has_sample_payload = true;
    if (zone_version >= 0x9a) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error("truncated BZone v0x9a fields");
        out.version_0x9a_flags[0] = u8(bytes, pos++) != 0;
        out.version_0x9a_flags[1] = u8(bytes, pos++) != 0;
        has_sample_payload = *out.version_0x9a_flags[1];
        out.version_0x9a_s32 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    if (zone_version < 0x96 || has_sample_payload) {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BZone sample reference");
        out.sample_file_table_index =
                static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        out.sample_settings = parse_sample_settings(bytes, pos, zone_version);
        pos = out.sample_settings->end_offset;
    }
    out.end_offset = pos;
    return out;
}

ZoneLevelEnvPayload parse_zone_level_env(
        std::span<const std::byte> bytes, std::size_t offset) {
    ZoneLevelEnvPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 1);
    if (out.serializable.version != 1) {
        throw std::runtime_error("unsupported BZoneLevelEnv version");
    }
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 1))
        throw std::runtime_error("truncated BZoneLevelEnv flag");
    out.has_data = u8(bytes, pos++) != 0;
    if (!out.has_data) {
        out.end_offset = pos;
        return out;
    }
    if (!has(bytes, pos, 2 + 8 + 2 + 4)) {
        throw std::runtime_error("truncated BZoneLevelEnv prefix");
    }
    out.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    for (auto &value : out.s32) {
        value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    }
    for (auto &value : out.flags)
        value = u8(bytes, pos++) != 0;
    const auto string_size = static_cast<std::size_t>(u32le(bytes, pos));
    pos += 4;
    if (!has(bytes, pos, string_size)) {
        throw std::runtime_error(
                "BZoneLevelEnv target string is out of bounds");
    }
    out.target_xml_name = std::string(
            reinterpret_cast<const char *>(bytes.data() + pos), string_size);
    pos += string_size;
    if (!has(bytes, pos, 3))
        throw std::runtime_error("truncated BZoneLevelEnv segment header");
    out.s8 = static_cast<std::int8_t>(u8(bytes, pos++));
    const auto segment_count = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    if (segment_count < 0 || static_cast<std::size_t>(segment_count) >
                                     (bytes.size() - pos) / 12) {
        throw std::runtime_error(
                "BZoneLevelEnv segment count is out of bounds");
    }
    out.segments.reserve(static_cast<std::size_t>(segment_count));
    for (std::int16_t i = 0; i < segment_count; ++i) {
        ZoneLevelEnvSegment segment;
        segment.s32 = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        for (auto &value : segment.f32) {
            const auto bits = u32le(bytes, pos);
            pos += 4;
            std::memcpy(&value, &bits, sizeof(value));
        }
        out.segments.push_back(segment);
    }
    out.end_offset = pos;
    return out;
}

ZonePrivatePayload parse_zone_private_payload(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t zone_version) {
    if (supports_zone_struct_version(zone_version) != Support::supported) {
        throw std::runtime_error("unsupported BZone version");
    }
    ZonePrivatePayload out;
    auto pos = offset;
    auto need = [&](std::size_t n, const char *what) {
        if (!has(bytes, pos, n))
            throw std::runtime_error(std::string("truncated ") + what);
    };
    auto read_s32 = [&]() {
        need(4, "BZone S32");
        auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    auto read_f32 = [&]() {
        need(4, "BZone F32");
        auto bits = u32le(bytes, pos);
        pos += 4;
        float value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    };
    out.leading_s32 = read_s32();
    out.enum_0_to_2 = read_s32();
    if (out.enum_0_to_2 < 0 || out.enum_0_to_2 >= 3) {
        throw std::runtime_error("BZone private enum is outside [0, 3)");
    }
    need(4, "BZone U8 array");
    for (auto &v : out.u8)
        v = u8(bytes, pos++);
    for (auto &v : out.f32)
        v = read_f32();
    need(2, "BZone flags");
    out.first_flag = u8(bytes, pos++) != 0;
    out.second_flag = u8(bytes, pos++) != 0;
    out.s32_after_flags = read_s32();
    out.f32_after_s32 = read_f32();
    need(4, "BZone S16 array");
    for (auto &v : out.s16) {
        v = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
    }
    for (auto &v : out.s32)
        v = read_s32();
    need(2 + 8, "BZone private suffix");
    out.trailing_u8 = u8(bytes, pos++);
    out.trailing_flag = u8(bytes, pos++) != 0;
    out.u64 = u64le(bytes, pos);
    pos += 8;
    need(2, "BZone level-envelope mask");
    out.level_env_presence_mask[0] = u8(bytes, pos++);
    out.level_env_presence_mask[1] = u8(bytes, pos++);
    for (std::uint8_t index = 0; index < 16; ++index) {
        if (((out.level_env_presence_mask[index / 8] >> (index % 8)) & 1U) == 0)
            continue;
        auto env = parse_zone_level_env(bytes, pos);
        pos = env.end_offset;
        out.level_envs.push_back({ index, std::move(env) });
    }
    if (zone_version >= 0x93)
        for (auto &v : out.version_0x93_f32)
            v = read_f32();
    if (zone_version >= 0x95) {
        need(1, "BZone v0x95 flag");
        out.version_0x95_flag = u8(bytes, pos++) != 0;
        out.version_0x95_s32 = read_s32();
        for (auto &v : out.version_0x95_f32)
            v = read_f32();
    }
    if (zone_version >= 0x99)
        out.version_0x99_s32 = read_s32();
    out.final_s32 = read_s32();
    out.end_offset = pos;
    return out;
}

LoopPayload parse_loop(std::span<const std::byte> bytes, std::size_t offset) {
    LoopPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x60);
    if (out.serializable.version != 0x60)
        throw std::runtime_error("unsupported BLoop version");
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 4 * 4 + 1 + 4 + 4))
        throw std::runtime_error("truncated BLoop payload");
    const auto mode = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (mode < 0 || mode >= 4)
        throw std::runtime_error("BLoop mode is outside [0, 4)");
    out.mode = static_cast<LoopPayload::Mode>(mode);
    out.start = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.length = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.count = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.alternating = u8(bytes, pos++) != 0;
    const auto bits = u32le(bytes, pos);
    pos += 4;
    std::memcpy(&out.tuning, &bits, sizeof(out.tuning));
    out.crossfade_length = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.end_offset = pos;
    return out;
}

SamplePayload parse_sample(
        std::span<const std::byte> bytes, std::size_t offset) {
    SamplePayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x10);
    if (out.serializable.version != 0x10)
        throw std::runtime_error("unsupported BSample version");
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 5))
        throw std::runtime_error("truncated BSample payload");
    out.flag = u8(bytes, pos++) != 0;
    out.original_file_table_index =
            static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.end_offset = pos;
    return out;
}

SampleSlicesPayload parse_sample_slices(std::span<const std::byte> bytes,
        std::size_t offset, bool stores_float_positions) {
    SampleSlicesPayload out;
    auto pos = offset;
    if (!has(bytes, pos, 4))
        throw std::runtime_error("truncated BSampleInfo slice count");
    out.count = u32le(bytes, pos);
    pos += 4;
    if (out.count == 0) {
        out.end_offset = pos;
        return out;
    }
    if (!has(bytes, pos, 4))
        throw std::runtime_error("truncated BSampleInfo slice header");
    out.header_value = u32le(bytes, pos);
    pos += 4;
    const auto bytes_per_slice = stores_float_positions ? 12U : 8U;
    if (out.count > (bytes.size() - pos) / bytes_per_slice) {
        throw std::runtime_error("BSampleInfo slice count is out of bounds");
    }
    out.slices.reserve(out.count);
    for (std::uint32_t i = 0; i < out.count; ++i) {
        SampleSlicePayload slice;
        slice.position = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        if (stores_float_positions) {
            const auto bits = u32le(bytes, pos);
            pos += 4;
            float value;
            std::memcpy(&value, &bits, sizeof(value));
            slice.position_f32 = value;
        }
        slice.value = u32le(bytes, pos);
        pos += 4;
        out.slices.push_back(slice);
    }
    out.end_offset = pos;
    return out;
}

ZoneChildrenPayload parse_zone_children(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t zone_version,
        bool has_sample_payload) {
    if (supports_zone_struct_version(zone_version) != Support::supported)
        throw std::runtime_error("unsupported BZone version");
    ZoneChildrenPayload out;
    auto pos = offset;
    if (!has(bytes, pos, 6))
        throw std::runtime_error("truncated BZone loop chunk");
    out.loop_chunk.offset = pos;
    out.loop_chunk.type = u16le(bytes, pos);
    out.loop_chunk.payload_size = u32le(bytes, pos + 2);
    out.loop_chunk.payload_offset = pos + 6;
    if (out.loop_chunk.type != 0x39)
        throw std::runtime_error("unexpected BZone loop chunk type");
    const auto loop_end =
            out.loop_chunk.payload_offset + out.loop_chunk.payload_size;
    if (loop_end < out.loop_chunk.payload_offset || loop_end > bytes.size())
        throw std::runtime_error("BZone loop chunk is out of bounds");
    pos = out.loop_chunk.payload_offset;
    if (pos == loop_end)
        throw std::runtime_error("truncated BZone loop mask");
    out.loop_presence_mask = u8(bytes, pos++);
    for (std::uint8_t index = 0; index < 8; ++index) {
        if (((out.loop_presence_mask >> index) & 1U) == 0)
            continue;
        auto loop = parse_loop(bytes.subspan(0, loop_end), pos);
        pos = loop.end_offset;
        out.loops.push_back({ index, std::move(loop) });
    }
    if (pos != loop_end)
        throw std::runtime_error("BZone loop chunk has trailing bytes");
    pos = loop_end;
    if (zone_version >= 0x98) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error("truncated BZone QuickBrowseData chunk");
        ChunkHeader chunk;
        chunk.offset = pos;
        chunk.type = u16le(bytes, pos);
        chunk.payload_size = u32le(bytes, pos + 2);
        chunk.payload_offset = pos + 6;
        if (chunk.type != 0x4e)
            throw std::runtime_error(
                    "unexpected BZone QuickBrowseData chunk type");
        out.quick_browse = parse_quick_browse_data(bytes, chunk);
        pos = out.quick_browse->end_offset;
    }
    if (has_sample_payload) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error("truncated BZone sample chunk");
        ChunkHeader chunk;
        chunk.offset = pos;
        chunk.type = u16le(bytes, pos);
        chunk.payload_size = u32le(bytes, pos + 2);
        chunk.payload_offset = pos + 6;
        if (chunk.type != 0x35)
            throw std::runtime_error("unexpected BZone sample chunk type");
        const auto chunk_end = chunk.payload_offset + chunk.payload_size;
        if (chunk_end < chunk.payload_offset || chunk_end > bytes.size()) {
            throw std::runtime_error("BZone sample chunk is out of bounds");
        }
        out.sample_chunk = chunk;
        out.sample =
                parse_sample(bytes.subspan(0, chunk_end), chunk.payload_offset);
        out.slices = parse_sample_slices(bytes.subspan(0, chunk_end),
                out.sample->end_offset, zone_version > 0x93);
        if (out.slices->end_offset != chunk_end) {
            throw std::runtime_error("BZone sample chunk has trailing bytes");
        }
        pos = chunk_end;
    }
    out.end_offset = pos;
    return out;
}

ZonePayload parse_zone(std::span<const std::byte> bytes, std::size_t offset) {
    ZonePayload out;
    out.serializable = parse_serializable_header(bytes, offset, true, 0x9c);
    const auto version = out.serializable.version;
    if (supports_zone_struct_version(version) != Support::supported) {
        throw std::runtime_error("unsupported BZone version");
    }
    auto pos = out.serializable.payload_offset;
    auto read_marker = [&](std::size_t index) {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BZone phase marker");
        out.phase_markers[index] = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    };
    read_marker(0);
    out.private_payload = parse_zone_private_payload(bytes, pos, version);
    pos = out.private_payload.end_offset;
    read_marker(1);
    out.public_payload = parse_zone_public_payload(bytes, pos, version);
    pos = out.public_payload.end_offset;
    read_marker(2);
    bool has_sample_payload = true;
    if (version >= 0x9a) {
        has_sample_payload =
                out.public_payload.version_0x9a_flags[1].value_or(false);
    }
    out.children = parse_zone_children(bytes, pos, version, has_sample_payload);
    out.end_offset = out.children.end_offset;
    return out;
}

ZoneArrayPayload parse_zone_array(
        std::span<const std::byte> bytes, std::size_t offset) {
    ZoneArrayPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x10);
    if (out.serializable.version != 0x10) {
        throw std::runtime_error("unsupported BZoneArraySer version");
    }
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 4))
        throw std::runtime_error("truncated BZoneArraySer count");
    out.zone_count = u32le(bytes, pos);
    pos += 4;
    if (out.zone_count > bytes.size() - pos) {
        throw std::runtime_error("BZoneArraySer count is out of bounds");
    }
    out.zones.reserve(out.zone_count);
    for (std::uint32_t i = 0; i < out.zone_count; ++i) {
        auto zone = parse_zone(bytes, pos);
        pos = zone.end_offset;
        out.zones.push_back(std::move(zone));
    }
    out.end_offset = pos;
    return out;
}

GroupCompletePayload parse_group_complete(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 0x2f)
        throw std::invalid_argument("group-complete chunk type must be 0x2f");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("group-complete chunk is out of bounds");
    }
    GroupCompletePayload out;
    out.chunk = chunk;
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, chunk_end), chunk.payload_offset, false, 0x10);
    if (out.serializable.version != 0x10) {
        throw std::runtime_error("unsupported BGroupCompleteSer version");
    }
    out.group = parse_group(bytes.subspan(0, chunk_end),
            out.serializable.payload_offset, context_ids_enabled,
            runtime_type_mappings);
    out.zone_array =
            parse_zone_array(bytes.subspan(0, chunk_end), out.group.end_offset);
    if (out.zone_array.end_offset != chunk_end) {
        throw std::runtime_error("group-complete chunk has trailing bytes");
    }
    out.end_offset = chunk_end;
    return out;
}

ProgramZoneChunkPayload parse_program_zone_chunk(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x34)
        throw std::invalid_argument("program zone chunk type must be 0x34");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("program zone chunk is out of bounds");
    }
    ProgramZoneChunkPayload out;
    out.chunk = chunk;
    const auto chunk_end = chunk.payload_offset + chunk.payload_size;
    auto pos = chunk.payload_offset;
    if (!has(bytes, pos, 4))
        throw std::runtime_error("truncated program zone count");
    out.zone_count = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.zone_count < 0 ||
            static_cast<std::uint32_t>(out.zone_count) > chunk_end - pos) {
        throw std::runtime_error("program zone count is out of bounds");
    }
    out.zones.reserve(static_cast<std::size_t>(out.zone_count));
    for (std::int32_t i = 0; i < out.zone_count; ++i) {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated program zone selector");
        ProgramZoneEntry entry;
        entry.factory_selector = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        entry.zone = parse_zone(bytes.subspan(0, chunk_end), pos);
        pos = entry.zone.end_offset;
        out.zones.push_back(std::move(entry));
    }
    if (pos != chunk_end)
        throw std::runtime_error("program zone chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

ProgramChildrenPayload parse_program_children(std::span<const std::byte> bytes,
        std::size_t offset, std::uint16_t program_version,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (supports_program_struct_version(program_version) !=
            Support::supported) {
        throw std::runtime_error("unsupported BProgram version");
    }
    ProgramChildrenPayload out;
    auto pos = offset;
    auto read_chunk = [&](std::uint16_t expected_type, const char *what) {
        if (!has(bytes, pos, 6))
            throw std::runtime_error(std::string("truncated ") + what);
        ChunkHeader chunk;
        chunk.offset = pos;
        chunk.type = u16le(bytes, pos);
        chunk.payload_size = u32le(bytes, pos + 2);
        chunk.payload_offset = pos + 6;
        if (chunk.type != expected_type)
            throw std::runtime_error(
                    std::string("unexpected ") + what + " type");
        if (chunk.payload_size > bytes.size() - chunk.payload_offset) {
            throw std::runtime_error(std::string(what) + " is out of bounds");
        }
        return chunk;
    };
    auto read_effect_array = [&]() {
        auto chunk = read_chunk(0x3a, "BProgram effect-array chunk");
        const auto end = chunk.payload_offset + chunk.payload_size;
        auto value = parse_parameter_array(bytes.subspan(0, end),
                chunk.payload_offset, context_ids_enabled,
                runtime_type_mappings);
        if (value.end_offset != end)
            throw std::runtime_error(
                    "BProgram effect-array chunk has trailing bytes");
        pos = end;
        out.effect_array_chunks.push_back(chunk);
        out.effect_arrays.push_back(std::move(value));
    };
    read_effect_array();
    read_effect_array();
    const bool has_insert_buses =
            program_version != 0x80 && program_version != 0x91;
    if (has_insert_buses) {
        out.insert_bus_chunks.reserve(16);
        out.insert_buses.reserve(16);
        for (std::size_t i = 0; i < 16; ++i) {
            auto chunk = read_chunk(0x45, "BProgram insert-bus chunk");
            const auto end = chunk.payload_offset + chunk.payload_size;
            auto bus = parse_insert_bus(bytes.subspan(0, end),
                    chunk.payload_offset, context_ids_enabled,
                    runtime_type_mappings);
            if (bus.end_offset != end)
                throw std::runtime_error(
                        "BProgram insert-bus chunk has trailing bytes");
            pos = end;
            out.insert_bus_chunks.push_back(chunk);
            out.insert_buses.push_back(std::move(bus));
        }
    }
    if (program_version >= 0x91) {
        out.scripts.reserve(5);
        for (std::size_t i = 0; i < 5; ++i) {
            auto chunk = read_chunk(6, "BProgram script chunk");
            auto script = parse_par_script(bytes, chunk);
            pos = script.end_offset;
            out.scripts.push_back(std::move(script));
        }
    }
    if (program_version >= 0xa3) {
        auto chunk = read_chunk(0x4e, "BProgram QuickBrowseData chunk");
        out.quick_browse = parse_quick_browse_data(bytes, chunk);
        pos = out.quick_browse->end_offset;
    }
    if (program_version >= 0xae)
        read_effect_array();
    auto voice_chunk = read_chunk(0x32, "BProgram voice-group chunk");
    out.voice_groups = parse_voice_group_chunk(bytes, voice_chunk);
    pos = out.voice_groups.end_offset;
    auto group_chunk = read_chunk(0x33, "BProgram group chunk");
    out.groups = parse_program_group_chunk(
            bytes, group_chunk, context_ids_enabled, runtime_type_mappings);
    pos = out.groups.end_offset;
    auto zone_chunk = read_chunk(0x34, "BProgram zone chunk");
    out.zones = parse_program_zone_chunk(bytes, zone_chunk);
    pos = out.zones.end_offset;
    out.end_offset = pos;
    return out;
}

NISoundDataPayload parse_nisound_data(
        std::span<const std::byte> bytes, std::size_t offset) {
    NISoundDataPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 1);
    if (out.serializable.version != 1)
        throw std::runtime_error("unsupported BNISoundData version");
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 1))
        throw std::runtime_error("truncated BNISoundData presence flag");
    out.present = u8(bytes, pos++) != 0;
    if (!out.present) {
        out.end_offset = pos;
        return out;
    }
    auto need = [&](std::size_t n, const char *what) {
        if (!has(bytes, pos, n))
            throw std::runtime_error(std::string("truncated ") + what);
    };
    auto read_u32 = [&]() {
        need(4, "BNISoundData U32");
        auto value = u32le(bytes, pos);
        pos += 4;
        return value;
    };
    auto read_wstr = [&](const char *what) {
        return read_utf16_string(bytes, pos, bytes.size(), what);
    };
    auto bounded_count = [&](const char *what) {
        const auto count = read_u32();
        if (count > bytes.size() - pos)
            throw std::runtime_error(
                    std::string(what) + " count is out of bounds");
        return count;
    };
    if (read_u32() != 2)
        throw std::runtime_error("unsupported BNISoundData SoundInfo version");
    for (auto &value : out.sound_info_u32_prefix)
        value = read_u32();
    for (auto &value : out.sound_info_strings)
        value = read_wstr("BNISoundData SoundInfo string");
    for (auto &value : out.sound_info_u32)
        value = read_u32();
    out.sound_info_s32 = static_cast<std::int32_t>(read_u32());
    const auto bank_group_count =
            bounded_count("BNISoundData bank-chain group");
    out.bank_chain_strings.reserve(bank_group_count);
    for (std::uint32_t group = 0; group < bank_group_count; ++group) {
        const auto string_count =
                bounded_count("BNISoundData bank-chain string");
        std::vector<std::string> values;
        values.reserve(string_count);
        for (std::uint32_t i = 0; i < string_count; ++i)
            values.push_back(read_wstr("BNISoundData bank-chain string"));
        out.bank_chain_strings.push_back(std::move(values));
    }
    const auto tag_count = bounded_count("BNISoundData tag");
    out.tags.reserve(tag_count);
    for (std::uint32_t i = 0; i < tag_count; ++i)
        out.tags.push_back(read_wstr("BNISoundData tag"));
    auto read_pairs =
            [&](std::vector<std::pair<std::string, std::string>> &values,
                    const char *what) {
                const auto count = bounded_count(what);
                values.reserve(count);
                for (std::uint32_t i = 0; i < count; ++i) {
                    auto key = read_wstr(what);
                    auto value = read_wstr(what);
                    values.emplace_back(std::move(key), std::move(value));
                }
            };
    read_pairs(out.user_attributes, "BNISoundData user attribute");
    read_pairs(out.string_map, "BNISoundData string map");
    if (read_u32() != 1)
        throw std::runtime_error(
                "unsupported controller-group collection version");
    const auto controller_group_count =
            bounded_count("BNISoundData controller group");
    out.controller_groups.reserve(controller_group_count);
    for (std::uint32_t group_index = 0; group_index < controller_group_count;
            ++group_index) {
        if (read_u32() != 1)
            throw std::runtime_error("unsupported controller-group version");
        const auto assignment_count =
                bounded_count("BNISoundData controller assignment");
        NISoundDataPayload::ControllerGroup group;
        group.name = read_wstr("BNISoundData controller-group name");
        group.assignments.reserve(assignment_count);
        for (std::uint32_t i = 0; i < assignment_count; ++i) {
            if (read_u32() != 1)
                throw std::runtime_error(
                        "unsupported controller-assignment version");
            NISoundDataPayload::ControllerAssignment assignment;
            assignment.name =
                    read_wstr("BNISoundData controller-assignment name");
            need(16, "BNISoundData controller-assignment fields");
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
        out.controller_groups.push_back(std::move(group));
    }
    need(1, "BNISoundData UUID flag");
    if (u8(bytes, pos++) != 0) {
        need(16, "BNISoundData UUID");
        std::array<std::byte, 16> uuid{};
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(pos), 16,
                uuid.begin());
        pos += 16;
        out.item_uuid = uuid;
    }
    out.end_offset = pos;
    return out;
}

ProgramPublicPayload parse_program_public_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t program_version) {
    if (supports_program_struct_version(program_version) !=
            Support::supported) {
        throw std::runtime_error("unsupported BProgram version");
    }
    ProgramPublicPayload out;
    auto pos = offset;
    auto need = [&](std::size_t n, const char *what) {
        if (!has(bytes, pos, n))
            throw std::runtime_error(std::string("truncated ") + what);
    };
    auto read_s32 = [&]() {
        need(4, "BProgram S32");
        auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    auto read_u32 = [&]() {
        need(4, "BProgram U32");
        auto value = u32le(bytes, pos);
        pos += 4;
        return value;
    };
    auto read_wstr = [&](const char *what) {
        return read_utf16_string(bytes, pos, bytes.size(), what);
    };
    auto read_gp_string = [&]() {
        const auto count = static_cast<std::size_t>(read_u32());
        need(count, "BProgram GP String");
        std::string value(
                reinterpret_cast<const char *>(bytes.data() + pos), count);
        pos += count;
        return value;
    };
    out.name = read_wstr("BProgram name");
    need(8 + 1 + 3 * 4 + 4 + 2 + 4 + 3 * 4 + 1 + 4, "BProgram public prefix");
    const auto f64_bits = u64le(bytes, pos);
    pos += 8;
    std::memcpy(&out.f64, &f64_bits, sizeof(out.f64));
    out.s8 = static_cast<std::int8_t>(u8(bytes, pos++));
    for (auto &value : out.f32) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    for (auto &value : out.u8)
        value = u8(bytes, pos++);
    out.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.s32 = read_s32();
    for (auto &value : out.u32)
        value = read_u32();
    out.flag = u8(bytes, pos++) != 0;
    out.s32_after_flag = read_s32();
    for (std::size_t i = 0; i < out.strings.size(); ++i)
        out.strings[i] = read_wstr("BProgram public string");
    need(6, "BProgram public S16 tail");
    for (auto &value : out.s16_tail) {
        value = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
    }

    if (program_version >= 0x91)
        out.content_file_table_index = read_s32();
    if (program_version == 0xa6) {
        for (std::size_t i = 0; i < 3; ++i)
            out.version_strings.push_back(read_wstr("BProgram v0xa6 string"));
        out.version_0xa6_filename_index = read_s32();
    } else if (program_version == 0xa7) {
        out.version_strings.push_back(read_wstr("BProgram v0xa7 string"));
    } else if (program_version >= 0xa8) {
        out.version_strings.push_back(read_wstr("BProgram version string"));
        out.version_strings.push_back(read_wstr("BProgram version string"));
    }
    if (program_version >= 0xaf)
        out.version_0xaf_u32 = read_u32();
    if (program_version == 0xb0) {
        auto value = parse_nisound_data(bytes, pos);
        pos = value.end_offset;
        out.nisound_data.push_back(std::move(value));
    } else if (program_version >= 0xb1) {
        auto first = parse_nisound_data(bytes, pos);
        pos = first.end_offset;
        out.nisound_data.push_back(std::move(first));
        need(1, "BProgram v0xb1 flag");
        out.version_0xb1_flag = u8(bytes, pos++) != 0;
        auto second = parse_nisound_data(bytes, pos);
        pos = second.end_offset;
        out.nisound_data.push_back(std::move(second));
    }
    if (program_version >= 0xb2)
        out.version_0xb2_s32 = read_s32();
    if (program_version >= 0xb3)
        out.version_0xb3_string = read_gp_string();
    if (program_version >= 0xb4)
        out.version_0xb4_s32 = read_s32();

    if (program_version > 0xa6)
        out.trailing_special_filename_indices.push_back(read_s32());
    if (program_version > 0xa1)
        out.trailing_special_filename_indices.push_back(read_s32());
    out.end_offset = pos;
    return out;
}

DyxMorphGroupPayload parse_dyx_morph_group(
        std::span<const std::byte> bytes, std::size_t offset) {
    DyxMorphGroupPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x50);
    if (out.serializable.version != 0x50) {
        throw std::runtime_error("unsupported BDyxMorphGroup version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count)) {
            throw std::runtime_error(
                    std::string("truncated BDyxMorphGroup ") + what);
        }
    };
    need(4, "S32");
    out.s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.name =
            read_utf16_string(bytes, pos, bytes.size(), "BDyxMorphGroup name");
    need(3 * 4 + 1 + 2, "fields");
    for (auto &value : out.f32) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    out.flag = u8(bytes, pos++) != 0;
    out.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.end_offset = pos;
    return out;
}

DyxMorphMapPayload parse_dyx_morph_map(
        std::span<const std::byte> bytes, std::size_t offset) {
    DyxMorphMapPayload out;
    out.serializable = parse_serializable_header(bytes, offset, false, 0x50);
    if (out.serializable.version != 0x50) {
        throw std::runtime_error("unsupported BDyxMorphMap version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count)) {
            throw std::runtime_error(
                    std::string("truncated BDyxMorphMap ") + what);
        }
    };
    need(8, "prefix");
    out.enum_1_to_2 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    if (out.enum_1_to_2 < 1 || out.enum_1_to_2 > 2) {
        throw std::runtime_error("BDyxMorphMap enum is outside [1, 2]");
    }
    out.s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.name = read_utf16_string(bytes, pos, bytes.size(), "BDyxMorphMap name");
    need(4, "value count");
    out.declared_value_count = u32le(bytes, pos);
    pos += 4;
    // the clamped last index is 63, so we can read up to 64 entries
    const auto stored_count =
            std::min<std::uint32_t>(out.declared_value_count, 64);
    if (stored_count > (bytes.size() - pos) / 4) {
        throw std::runtime_error("BDyxMorphMap values are out of bounds");
    }
    out.values.reserve(stored_count);
    for (std::uint32_t i = 0; i < stored_count; ++i) {
        out.values.push_back(static_cast<std::int32_t>(u32le(bytes, pos)));
        pos += 4;
    }
    out.end_offset = pos;
    return out;
}

ProgramPrivatePayload parse_program_private_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t program_version) {
    if (supports_program_struct_version(program_version) !=
            Support::supported) {
        throw std::runtime_error("unsupported BProgram version");
    }
    ProgramPrivatePayload out;
    auto pos = offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count)) {
            throw std::runtime_error(
                    std::string("truncated BProgram private ") + what);
        }
    };
    auto read_s32 = [&]() {
        need(4, "S32");
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    auto read_u32 = [&]() {
        need(4, "U32");
        const auto value = u32le(bytes, pos);
        pos += 4;
        return value;
    };
    auto read_bool = [&]() {
        need(1, "Bool");
        return u8(bytes, pos++) != 0;
    };
    out.enum_0_to_2 = read_s32();
    if (out.enum_0_to_2 < 0 || out.enum_0_to_2 >= 3) {
        throw std::runtime_error("BProgram private enum is outside [0, 3)");
    }
    for (auto &value : out.leading_flags)
        value = read_bool();
    out.first_s32 = read_s32();
    out.flag_before_s32_pair = read_bool();
    for (auto &value : out.s32_pair)
        value = read_s32();
    out.flag_before_second_s32 = read_bool();
    out.second_s32 = read_s32();
    for (auto &value : out.flags_before_third_s32)
        value = read_bool();
    out.third_s32 = read_s32();
    for (auto &value : out.middle_flags)
        value = read_bool();
    for (auto &value : out.s32_triplet)
        value = read_s32();
    for (auto &value : out.flags_before_s16)
        value = read_bool();
    need(2, "S16");
    out.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    out.flag_after_s16 = read_bool();

    if (program_version < 0x91) {
        out.legacy_filename_table_index = read_s32();
        out.legacy_scripts.reserve(5);
        for (std::size_t i = 0; i < 5; ++i) {
            auto script = parse_par_script_payload(bytes, pos);
            pos = script.end_offset;
            out.legacy_scripts.push_back(std::move(script));
        }
        out.automation_capacity = read_u32();
        if (out.automation_capacity != 0) {
            out.automation_count = read_u32();
            const auto stored_count =
                    std::min(out.automation_capacity, *out.automation_count);
            if (stored_count > bytes.size() - pos) {
                throw std::runtime_error(
                        "legacy BProgram automation count is out of bounds");
            }
            out.automation_objects.reserve(stored_count);
            for (std::uint32_t i = 0; i < stored_count; ++i) {
                auto value = parse_automation_object(bytes, pos);
                pos = value.end_offset;
                out.automation_objects.push_back(std::move(value));
            }
        }
        const auto morph_group_count = read_u32();
        if (morph_group_count > bytes.size() - pos) {
            throw std::runtime_error(
                    "legacy BProgram morph-group count is out of bounds");
        }
        out.morph_groups.reserve(morph_group_count);
        for (std::uint32_t i = 0; i < morph_group_count; ++i) {
            auto value = parse_dyx_morph_group(bytes, pos);
            pos = value.end_offset;
            out.morph_groups.push_back(std::move(value));
        }
        const auto morph_map_count = read_u32();
        if (morph_map_count > bytes.size() - pos) {
            throw std::runtime_error(
                    "legacy BProgram morph-map count is out of bounds");
        }
        out.morph_maps.reserve(morph_map_count);
        for (std::uint32_t i = 0; i < morph_map_count; ++i) {
            auto value = parse_dyx_morph_map(bytes, pos);
            pos = value.end_offset;
            out.morph_maps.push_back(std::move(value));
        }
        if (program_version != 0x80) {
            out.tail_flag = read_bool();
            std::array<std::int32_t, 2> pair{};
            for (auto &value : pair)
                value = read_s32();
            out.tail_s32_pair = pair;
            std::array<bool, 3> flags{};
            for (auto &value : flags)
                value = read_bool();
            out.tail_flags = flags;
        }
        out.legacy_special_filename_table_index = read_s32();
        out.end_offset = pos;
        return out;
    }

    const auto morph_group_count = read_u32();
    if (morph_group_count > bytes.size() - pos) {
        throw std::runtime_error("BProgram morph-group count is out of bounds");
    }
    out.morph_groups.reserve(morph_group_count);
    for (std::uint32_t i = 0; i < morph_group_count; ++i) {
        auto value = parse_dyx_morph_group(bytes, pos);
        pos = value.end_offset;
        out.morph_groups.push_back(std::move(value));
    }
    const auto morph_map_count = read_u32();
    if (morph_map_count > bytes.size() - pos) {
        throw std::runtime_error("BProgram morph-map count is out of bounds");
    }
    out.morph_maps.reserve(morph_map_count);
    for (std::uint32_t i = 0; i < morph_map_count; ++i) {
        auto value = parse_dyx_morph_map(bytes, pos);
        pos = value.end_offset;
        out.morph_maps.push_back(std::move(value));
    }
    out.automation_capacity = read_u32();
    if (out.automation_capacity != 0) {
        out.automation_count = read_u32();
        if (*out.automation_count > bytes.size() - pos) {
            throw std::runtime_error(
                    "BProgram automation count is out of bounds");
        }
        out.automation_objects.reserve(*out.automation_count);
        for (std::uint32_t i = 0; i < *out.automation_count; ++i) {
            auto value = parse_automation_object(bytes, pos);
            pos = value.end_offset;
            out.automation_objects.push_back(std::move(value));
        }
    }
    if (program_version != 0x91) {
        out.tail_flag = read_bool();
        std::array<std::int32_t, 2> pair{};
        for (auto &value : pair)
            value = read_s32();
        out.tail_s32_pair = pair;
        std::array<bool, 3> flags{};
        for (auto &value : flags)
            value = read_bool();
        out.tail_flags = flags;
    }
    const bool has_active_voice_counts =
            program_version >= 0xa1 && program_version != 0xa4;
    if (has_active_voice_counts) {
        std::array<std::uint32_t, 2> counts{};
        for (auto &value : counts)
            value = read_u32();
        out.active_voice_counts = counts;
    }
    if (program_version >= 0xa4)
        out.tail_s32 = read_s32();
    if (program_version >= 0xa6) {
        std::array<bool, 2> flags{};
        for (auto &value : flags)
            value = read_bool();
        out.tail_flags_2 = flags;
    }
    if (program_version == 0xaa) {
        std::array<std::int32_t, 2> pair{};
        for (auto &value : pair)
            value = read_s32();
        out.version_s32_pair = pair;
    }
    if (program_version >= 0xac)
        out.tail_u32 = read_u32();
    if (program_version >= 0xad) {
        out.filename_table_index = read_s32();
        std::array<bool, 2> flags{};
        for (auto &value : flags)
            value = read_bool();
        out.final_flags = flags;
        out.final_s32 = read_s32();
    }
    if (program_version == 0xb5) {
        out.final_string = read_utf16_string(
                bytes, pos, bytes.size(), "BProgram private final string");
        std::array<std::int32_t, 2> pair{};
        for (auto &value : pair)
            value = read_s32();
        out.version_s32_pair = pair;
    }
    if (program_version < 0xa2) {
        out.legacy_special_filename_table_index = read_s32();
    }
    out.end_offset = pos;
    return out;
}

ProgramPayload parse_program(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    ProgramPayload out;
    out.serializable = parse_serializable_header(bytes, offset, true, 0xb5);
    const auto version = out.serializable.version;
    if (supports_program_struct_version(version) != Support::supported) {
        throw std::runtime_error("unsupported BProgram version");
    }
    auto pos = out.serializable.payload_offset;
    auto read_marker = [&](std::size_t index) {
        if (!has(bytes, pos, 4)) {
            throw std::runtime_error("truncated BProgram phase marker");
        }
        out.phase_markers[index] = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
    };
    read_marker(0);
    out.private_payload = parse_program_private_payload(bytes, pos, version);
    pos = out.private_payload.end_offset;
    read_marker(1);
    out.public_payload = parse_program_public_payload(bytes, pos, version);
    pos = out.public_payload.end_offset;
    read_marker(2);
    out.children = parse_program_children(
            bytes, pos, version, context_ids_enabled, runtime_type_mappings);
    out.end_offset = out.children.end_offset;
    return out;
}

SaveSettingsPayload parse_save_settings(
        std::span<const std::byte> bytes, const ChunkHeader &chunk) {
    if (chunk.type != 0x47) {
        throw std::invalid_argument("SaveSettings chunk type must be 0x47");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("SaveSettings chunk is out of bounds");
    }
    SaveSettingsPayload out;
    out.chunk = chunk;
    const auto end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, end), chunk.payload_offset, false, 0x10);
    if (out.serializable.version != 0x10) {
        throw std::runtime_error("unsupported SaveSettings version");
    }
    auto pos = out.serializable.payload_offset;
    if (!has(bytes, pos, 8 + 4 + 3) || pos + 15 > end) {
        throw std::runtime_error("truncated SaveSettings payload");
    }
    out.translated_filename_table_index =
            static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.original_filename_table_index =
            static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    out.s32 = static_cast<std::int32_t>(u32le(bytes, pos));
    pos += 4;
    for (auto &flag : out.flags)
        flag = u8(bytes, pos++) != 0;
    if (pos != end)
        throw std::runtime_error("SaveSettings chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

} // namespace libnki
