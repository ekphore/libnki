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

ProgramContainerPayload parse_program_container(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 0x29) {
        throw std::invalid_argument(
                "BProgramContainer chunk type must be 0x29");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BProgramContainer chunk is out of bounds");
    }
    ProgramContainerPayload out;
    out.chunk = chunk;
    const auto container_end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, container_end), chunk.payload_offset, true, 0x51);
    const auto version = out.serializable.version;
    if (version != 0x50 && version != 0x51) {
        throw std::runtime_error("unsupported BProgramContainer version");
    }
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count) || pos + count > container_end) {
            throw std::runtime_error(
                    std::string("truncated BProgramContainer ") + what);
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
    auto read_chunk = [&](std::uint16_t expected, const char *what) {
        need(6, what);
        ChunkHeader value;
        value.offset = pos;
        value.type = u16le(bytes, pos);
        value.payload_size = u32le(bytes, pos + 2);
        value.payload_offset = pos + 6;
        if (value.type != expected) {
            throw std::runtime_error(
                    std::string("unexpected BProgramContainer ") + what +
                    " type");
        }
        if (value.payload_size > container_end - value.payload_offset) {
            throw std::runtime_error(std::string("BProgramContainer ") + what +
                                     " is out of bounds");
        }
        return value;
    };

    out.phase_markers[0] = read_s32();
    auto &private_payload = out.private_payload;
    private_payload.s32 = read_s32();
    for (auto &flag : private_payload.flags)
        flag = read_bool();
    need(2, "private S16");
    private_payload.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
    pos += 2;
    if (version == 0x50) {
        private_payload.version_0x50_original_filename_table_index = read_s32();
        private_payload.version_0x50_s32 = read_s32();
        std::array<bool, 2> flags{};
        for (auto &flag : flags)
            flag = read_bool();
        private_payload.version_0x50_flags = flags;
    }
    private_payload.automation_capacity = read_u32();
    if (private_payload.automation_capacity != 0) {
        private_payload.automation_count = read_u32();
        const auto count = std::min(private_payload.automation_capacity,
                *private_payload.automation_count);
        if (count > container_end - pos) {
            throw std::runtime_error(
                    "BProgramContainer automation count is out of bounds");
        }
        private_payload.automation_objects.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto value = parse_automation_object(
                    bytes.subspan(0, container_end), pos);
            pos = value.end_offset;
            private_payload.automation_objects.push_back(std::move(value));
        }
    }
    if (version == 0x50) {
        private_payload.version_0x50_trailing_flag = read_bool();
    }
    private_payload.output_mask = read_u32();
    private_payload.end_offset = pos;

    out.phase_markers[1] = read_s32();
    out.public_payload.name = read_utf16_string(
            bytes, pos, container_end, "BProgramContainer name");
    need(8, "public F32 values");
    for (auto &value : out.public_payload.f32) {
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    out.public_payload.end_offset = pos;

    out.phase_markers[2] = read_s32();
    out.children.voice_limit_chunk = read_chunk(0x2b, "voice-limit chunk");
    auto voice_end = out.children.voice_limit_chunk.payload_offset +
                     out.children.voice_limit_chunk.payload_size;
    out.children.voice_limit = parse_voice_limit(bytes.subspan(0, voice_end),
            out.children.voice_limit_chunk.payload_offset);
    if (out.children.voice_limit.end_offset != voice_end) {
        throw std::runtime_error(
                "BProgramContainer voice-limit chunk has trailing bytes");
    }
    pos = voice_end;
    if (version == 0x51) {
        auto save_chunk = read_chunk(0x47, "SaveSettings chunk");
        out.children.save_settings = parse_save_settings(bytes, save_chunk);
        pos = out.children.save_settings->end_offset;
    }
    out.children.programs_chunk = read_chunk(0x36, "program-list chunk");
    const auto programs_end = out.children.programs_chunk.payload_offset +
                              out.children.programs_chunk.payload_size;
    pos = out.children.programs_chunk.payload_offset;
    if (!has(bytes, pos, 2) || pos + 2 > programs_end) {
        throw std::runtime_error("truncated BProgramContainer program count");
    }
    out.children.program_count = u16le(bytes, pos);
    pos += 2;
    if (out.children.program_count > programs_end - pos) {
        throw std::runtime_error(
                "BProgramContainer program count is out of bounds");
    }
    out.children.programs.reserve(out.children.program_count);
    for (std::uint16_t i = 0; i < out.children.program_count; ++i) {
        if (!has(bytes, pos, 2) || pos + 2 > programs_end) {
            throw std::runtime_error(
                    "truncated BProgramContainer relative slot");
        }
        ProgramContainerEntry entry;
        entry.relative_slot = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
        entry.program = parse_program(bytes.subspan(0, programs_end), pos,
                context_ids_enabled, runtime_type_mappings);
        pos = entry.program.end_offset;
        out.children.programs.push_back(std::move(entry));
    }
    if (pos != programs_end) {
        throw std::runtime_error(
                "BProgramContainer program-list chunk has trailing bytes");
    }
    out.children.end_offset = pos;
    if (pos != container_end) {
        throw std::runtime_error("BProgramContainer chunk has trailing bytes");
    }
    out.end_offset = pos;
    return out;
}

BankSlotListPayload parse_bank_slot_list(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 0x37) {
        throw std::invalid_argument("BBank slot-list chunk type must be 0x37");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BBank slot-list chunk is out of bounds");
    }
    BankSlotListPayload out;
    out.chunk = chunk;
    const auto end = chunk.payload_offset + chunk.payload_size;
    auto pos = chunk.payload_offset;
    if (!has(bytes, pos, out.presence_mask.size()) ||
            pos + out.presence_mask.size() > end) {
        throw std::runtime_error("truncated BBank slot-list presence mask");
    }
    for (auto &value : out.presence_mask)
        value = u8(bytes, pos++);
    for (std::uint8_t slot = 0; slot < 64; ++slot) {
        if ((out.presence_mask[slot >> 3U] & (1U << (slot & 7U))) == 0)
            continue;
        ++out.serialized_count;
        if (!has(bytes, pos, 6) || pos + 6 > end) {
            throw std::runtime_error(
                    "truncated BBank slot program-container chunk");
        }
        ChunkHeader child;
        child.offset = pos;
        child.type = u16le(bytes, pos);
        child.payload_size = u32le(bytes, pos + 2);
        child.payload_offset = pos + 6;
        if (child.type != 0x29) {
            throw std::runtime_error(
                    "BBank slot-list child is not BProgramContainer");
        }
        if (child.payload_size > end - child.payload_offset) {
            throw std::runtime_error(
                    "BBank slot program-container is out of bounds");
        }
        BankSlotEntry entry;
        entry.serialized_slot = slot;
        entry.program_container = parse_program_container(
                bytes.subspan(0, child.payload_offset + child.payload_size),
                child, context_ids_enabled, runtime_type_mappings);
        out.entries.push_back(std::move(entry));
        pos = child.payload_offset + child.payload_size;
    }
    if (pos != end)
        throw std::runtime_error("BBank slot-list has trailing bytes");
    out.end_offset = pos;
    return out;
}

OutputConfigurationPayload parse_output_configuration(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 0x3e) {
        throw std::invalid_argument(
                "BOutputConfiguration chunk type must be 0x3e");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument(
                "BOutputConfiguration chunk is out of bounds");
    }
    OutputConfigurationPayload out;
    out.chunk = chunk;
    const auto end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, end), chunk.payload_offset, false, 0);
    auto pos = out.serializable.payload_offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count) || pos + count > end) {
            throw std::runtime_error(
                    std::string("truncated BOutputConfiguration ") + what);
        }
    };
    need(4, "S32-array count");
    const auto declared_count = u32le(bytes, pos);
    pos += 4;
    const auto count = std::min<std::uint32_t>(declared_count, 128);
    out.s32_array.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        need(4, "S32-array value");
        out.s32_array.push_back(static_cast<std::int32_t>(u32le(bytes, pos)));
        pos += 4;
    }
    need(out.presence_mask.size(), "partition presence mask");
    for (auto &value : out.presence_mask)
        value = u8(bytes, pos++);

    auto direct_par_fx_end = [&](std::size_t fx_offset) {
        auto fx_pos = fx_offset;
        const auto header = parse_serializable_header(
                bytes.subspan(0, end), fx_pos, true, 0x50);
        if (header.version != 0x50) {
            throw std::runtime_error("unsupported direct BParFX version");
        }
        fx_pos = header.payload_offset;
        if (!has(bytes, fx_pos, 8) || fx_pos + 8 > end) {
            throw std::runtime_error("truncated direct BParFX prefix");
        }
        fx_pos += 4; // private phase size
        const auto fix_type = static_cast<std::int32_t>(u32le(bytes, fx_pos));
        fx_pos += 4;
        static constexpr std::array<std::int32_t, 51> built_in = { 0, 0, 2, 3,
            4, 6, 7, 8, 9, 10, 11, 12, 0, 0, 59, 60, 61, 62, 67, 70, 71, 13, 14,
            17, 29, 5, 30, 32, 34, 35, 33, 18, 19, 20, 21, 25, 27, 28, 64, 63,
            66, 36, 37, 39, 40, 42, 43, 22, 41, 0, 16 };
        static constexpr std::uint64_t built_in_mask = 0x5ffffffffcffdULL;
        std::optional<std::int32_t> internal_type;
        if (fix_type >= 0 && fix_type < 51 &&
                ((built_in_mask >> fix_type) & 1U) != 0) {
            internal_type = built_in[static_cast<std::size_t>(fix_type)];
        } else {
            for (const auto &mapping : runtime_type_mappings) {
                if (mapping.serialized_fix_type == fix_type) {
                    internal_type = mapping.internal_type;
                    break;
                }
            }
            if (!internal_type) {
                for (const auto &mapping :
                        kontakt8_runtime_par_fx_type_mappings()) {
                    if (mapping.serialized_fix_type == fix_type) {
                        internal_type = mapping.internal_type;
                        break;
                    }
                }
            }
        }
        if (!internal_type)
            throw std::runtime_error("unknown direct BParFX fix type");
        if (*internal_type != 0) {
            if (!has(bytes, fx_pos, 18) || fx_pos + 18 > end) {
                throw std::runtime_error(
                        "truncated direct BParFX private fields");
            }
            fx_pos += 18;
        }
        if (!has(bytes, fx_pos, 8) || fx_pos + 8 > end) {
            throw std::runtime_error("truncated direct BParFX phase sizes");
        }
        fx_pos += 8;
        if (*internal_type != 0) {
            if (!has(bytes, fx_pos, 6) || fx_pos + 6 > end) {
                throw std::runtime_error("truncated direct BParFX child chunk");
            }
            const auto child_size =
                    static_cast<std::size_t>(u32le(bytes, fx_pos + 2));
            fx_pos += 6;
            if (child_size > end - fx_pos) {
                throw std::runtime_error(
                        "direct BParFX child is out of bounds");
            }
            fx_pos += child_size;
        }
        return fx_pos;
    };

    for (std::uint8_t index = 0; index < 128; ++index) {
        if ((out.presence_mask[index >> 3U] & (1U << (index & 7U))) == 0)
            continue;
        OutputPartitionPayload partition;
        partition.serializable = parse_serializable_header(
                bytes.subspan(0, end), pos, false, 0x70);
        if (partition.serializable.version != 0x70) {
            throw std::runtime_error("unsupported OutputPartition version");
        }
        pos = partition.serializable.payload_offset;
        partition.name =
                read_utf16_string(bytes, pos, end, "OutputPartition name");
        need(12, "OutputPartition scalars");
        for (auto &value : partition.s16) {
            value = static_cast<std::int16_t>(u16le(bytes, pos));
            pos += 2;
        }
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&partition.level, &bits, sizeof(partition.level));
        const auto effect_count = std::min<std::uint32_t>(u32le(bytes, pos), 4);
        pos += 4;
        partition.effects.reserve(effect_count);
        for (std::uint32_t i = 0; i < effect_count; ++i) {
            const auto fx_end = direct_par_fx_end(pos);
            ChunkHeader direct;
            direct.offset = pos;
            direct.type = 0x25;
            direct.payload_offset = pos;
            direct.payload_size = static_cast<std::uint32_t>(fx_end - pos);
            auto effect = parse_par_fx(
                    bytes.subspan(0, fx_end), direct, runtime_type_mappings);
            pos = fx_end;
            partition.effects.push_back(std::move(effect));
        }
        partition.end_offset = pos;
        out.partitions.push_back({ index, std::move(partition) });
    }
    if (pos != end)
        throw std::runtime_error("BOutputConfiguration has trailing bytes");
    out.end_offset = pos;
    return out;
}

BankMidiRoutingPayload parse_bank_midi_routing(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, std::uint16_t bank_version) {
    if (chunk.type != 0x48) {
        throw std::invalid_argument(
                "BBank MIDI-routing chunk type must be 0x48");
    }
    if (bank_version < 0x73 || bank_version > 0x77) {
        throw std::invalid_argument(
                "BBank MIDI routing requires version 0x73..0x77");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument(
                "BBank MIDI-routing chunk is out of bounds");
    }
    BankMidiRoutingPayload out;
    out.chunk = chunk;
    const auto end = chunk.payload_offset + chunk.payload_size;
    auto pos = chunk.payload_offset;
    auto need = [&](std::size_t count, const char *what) {
        if (!has(bytes, pos, count) || pos + count > end) {
            throw std::runtime_error(
                    std::string("truncated BBank MIDI routing ") + what);
        }
    };
    auto read_s32 = [&]() {
        need(4, "S32");
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };
    for (auto &record : out.records) {
        need(2, "S16");
        record.s16 = static_cast<std::int16_t>(u16le(bytes, pos));
        pos += 2;
        if (bank_version >= 0x75)
            record.version_0x75_s32 = read_s32();
        need(2, "flags");
        for (auto &flag : record.flags)
            flag = u8(bytes, pos++) != 0;
        need(4, "F32-vector count");
        const auto count = std::min<std::uint32_t>(u32le(bytes, pos), 4);
        pos += 4;
        record.f32_values.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            need(4, "F32-vector value");
            const auto bits = u32le(bytes, pos);
            pos += 4;
            float value;
            std::memcpy(&value, &bits, sizeof(value));
            record.f32_values.push_back(value);
        }
    }
    if (pos != end)
        throw std::runtime_error("BBank MIDI-routing chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

BankAudioRoutingPayload parse_bank_audio_routing(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::uint16_t bank_version) {
    if (chunk.type != 0x49) {
        throw std::invalid_argument(
                "BBank audio-routing chunk type must be 0x49");
    }
    if (bank_version < 0x73 || bank_version > 0x77) {
        throw std::invalid_argument(
                "BBank audio routing requires version 0x73..0x77");
    }
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument(
                "BBank audio-routing chunk is out of bounds");
    }
    BankAudioRoutingPayload out;
    out.chunk = chunk;
    const auto end = chunk.payload_offset + chunk.payload_size;
    auto pos = chunk.payload_offset;
    const std::size_t list_count = bank_version < 0x77 ? 4 : 1;
    const std::uint32_t value_cap = bank_version < 0x77 ? 16 : 64;
    out.s32_lists.reserve(list_count);
    for (std::size_t list_index = 0; list_index < list_count; ++list_index) {
        if (!has(bytes, pos, 4) || pos + 4 > end) {
            throw std::runtime_error(
                    "truncated BBank audio-routing list count");
        }
        const auto count = std::min(u32le(bytes, pos), value_cap);
        pos += 4;
        std::vector<std::int32_t> values;
        values.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            if (!has(bytes, pos, 4) || pos + 4 > end) {
                throw std::runtime_error(
                        "truncated BBank audio-routing S32 value");
            }
            values.push_back(static_cast<std::int32_t>(u32le(bytes, pos)));
            pos += 4;
        }
        out.s32_lists.push_back(std::move(values));
    }
    if (pos != end)
        throw std::runtime_error(
                "BBank audio-routing chunk has trailing bytes");
    out.end_offset = pos;
    return out;
}

BankPayload parse_bank(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings) {
    if (chunk.type != 3)
        throw std::invalid_argument("BBank chunk type must be 3");
    if (chunk.payload_offset > bytes.size() ||
            chunk.payload_size > bytes.size() - chunk.payload_offset) {
        throw std::invalid_argument("BBank chunk is out of bounds");
    }
    BankPayload out;
    out.chunk = chunk;
    const auto bank_end = chunk.payload_offset + chunk.payload_size;
    out.serializable = parse_serializable_header(
            bytes.subspan(0, bank_end), chunk.payload_offset, true, 0x77);
    const auto version = out.serializable.version;
    if (version != 0x60 && (version < 0x70 || version > 0x77)) {
        throw std::runtime_error("unsupported BBank version");
    }
    auto pos = out.serializable.payload_offset;
    auto read_phase_size = [&](std::size_t index) {
        if (!has(bytes, pos, 4) || pos + 4 > bank_end) {
            throw std::runtime_error("truncated BBank phase size");
        }
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        if (value < 0)
            throw std::runtime_error("negative BBank phase size");
        out.phase_sizes[index] = value;
        pos += 4;
        const auto size = static_cast<std::size_t>(value);
        if (size > bank_end - pos)
            throw std::runtime_error("BBank phase is out of bounds");
        return pos + size;
    };
    auto read_bool = [&]() {
        if (!has(bytes, pos, 1))
            throw std::runtime_error("truncated BBank Bool");
        return u8(bytes, pos++) != 0;
    };
    auto read_s32 = [&]() {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BBank S32");
        const auto value = static_cast<std::int32_t>(u32le(bytes, pos));
        pos += 4;
        return value;
    };

    const auto private_end = read_phase_size(0);
    for (auto &flag : out.private_payload.flags)
        flag = read_bool();
    if (version <= 0x72) {
        auto read_capped_count = [&](std::uint32_t cap, const char *what) {
            if (!has(bytes, pos, 4) || pos + 4 > private_end) {
                throw std::runtime_error(
                        std::string("truncated BBank ") + what + " count");
            }
            const auto declared = u32le(bytes, pos);
            pos += 4;
            return std::min(declared, cap);
        };
        const auto slot_count = read_capped_count(64, "legacy slot-number");
        out.private_payload.legacy_slot_numbers.reserve(slot_count);
        for (std::uint32_t i = 0; i < slot_count; ++i) {
            if (!has(bytes, pos, 2) || pos + 2 > private_end) {
                throw std::runtime_error("truncated BBank legacy slot number");
            }
            out.private_payload.legacy_slot_numbers.push_back(
                    static_cast<std::int16_t>(u16le(bytes, pos)));
            pos += 2;
        }
        for (auto &flag : out.private_payload.legacy_slot_flags_0)
            flag = read_bool();
        for (auto &flag : out.private_payload.legacy_slot_flags_1)
            flag = read_bool();
        for (auto &values : out.private_payload.legacy_slot_f32) {
            const auto count = read_capped_count(4, "legacy slot-F32");
            values.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                if (!has(bytes, pos, 4) || pos + 4 > private_end) {
                    throw std::runtime_error("truncated BBank legacy slot F32");
                }
                const auto bits = u32le(bytes, pos);
                pos += 4;
                float value;
                std::memcpy(&value, &bits, sizeof(value));
                values.push_back(value);
            }
        }
        for (auto &values : out.private_payload.legacy_s32_arrays) {
            const auto count = read_capped_count(16, "legacy S32-array");
            values.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i)
                values.push_back(read_s32());
        }
        if (version <= 0x71) {
            // the original filename is one signed table index, not an inline
            // path
            out.private_payload.legacy_original_filename_table_index =
                    read_s32();
            out.private_payload.legacy_s32 = read_s32();
            out.private_payload.legacy_flags =
                    std::array<bool, 2>{ read_bool(), read_bool() };
            out.private_payload.legacy_scripts.reserve(5);
            for (std::size_t i = 0; i < 5; ++i) {
                auto script = parse_par_script_bounded(bytes, pos, private_end);
                pos = script.end_offset;
                out.private_payload.legacy_scripts.push_back(std::move(script));
            }
            if (version == 0x60) {
                ChunkHeader embedded_output;
                embedded_output.offset = pos;
                embedded_output.type = 0x3e;
                embedded_output.payload_offset = pos;
                embedded_output.payload_size = private_end - pos;
                out.output_configuration = parse_output_configuration(
                        bytes.subspan(0, private_end), embedded_output,
                        runtime_type_mappings);
                out.output_configuration_in_private_phase = true;
                pos = out.output_configuration->end_offset;
            }
        }
    } else if (version >= 0x74) {
        out.private_payload.version_0x74_s32 =
                std::array<std::int32_t, 2>{ read_s32(), read_s32() };
    }
    if (version >= 0x76) {
        auto value = read_bstring(bytes, pos, private_end, "BBank UUID");
        out.private_payload.version_0x76_uuid = value.value_or(std::string{});
    }
    if (pos != private_end)
        throw std::runtime_error("BBank private phase size mismatch");
    out.private_payload.end_offset = pos;

    const auto public_end = read_phase_size(1);
    for (auto &value : out.public_payload.f32) {
        if (!has(bytes, pos, 4))
            throw std::runtime_error("truncated BBank F32");
        const auto bits = u32le(bytes, pos);
        pos += 4;
        std::memcpy(&value, &bits, sizeof(value));
    }
    out.public_payload.s32 = read_s32();
    out.public_payload.name =
            read_utf16_string(bytes, pos, public_end, "BBank name");
    if (pos != public_end)
        throw std::runtime_error("BBank public phase size mismatch");
    out.public_payload.end_offset = pos;

    const auto children_end = read_phase_size(2);
    while (pos < children_end) {
        if (!has(bytes, pos, 6) || pos + 6 > children_end) {
            throw std::runtime_error("truncated BBank child chunk");
        }
        ChunkHeader child;
        child.offset = pos;
        child.type = u16le(bytes, pos);
        child.payload_size = u32le(bytes, pos + 2);
        child.payload_offset = pos + 6;
        if (child.payload_size > children_end - child.payload_offset) {
            throw std::runtime_error("BBank child chunk is out of bounds");
        }
        out.child_chunks.push_back(child);
        pos = child.payload_offset + child.payload_size;
    }
    const auto slot = std::find_if(out.child_chunks.begin(),
            out.child_chunks.end(),
            [](const ChunkHeader &child) { return child.type == 0x37; });
    if (slot != out.child_chunks.end()) {
        out.slot_list = parse_bank_slot_list(
                bytes.subspan(0, slot->payload_offset + slot->payload_size),
                *slot, context_ids_enabled, runtime_type_mappings);
    }
    const auto output = std::find_if(out.child_chunks.begin(),
            out.child_chunks.end(),
            [](const ChunkHeader &child) { return child.type == 0x3e; });
    if (output != out.child_chunks.end()) {
        if (out.output_configuration_in_private_phase) {
            throw std::runtime_error("BBank has output configurations in both "
                                     "private and children phases");
        }
        out.output_configuration = parse_output_configuration(
                bytes.subspan(0, output->payload_offset + output->payload_size),
                *output, runtime_type_mappings);
    }
    const auto midi_routing = std::find_if(out.child_chunks.begin(),
            out.child_chunks.end(),
            [](const ChunkHeader &child) { return child.type == 0x48; });
    const auto audio_routing = std::find_if(out.child_chunks.begin(),
            out.child_chunks.end(),
            [](const ChunkHeader &child) { return child.type == 0x49; });
    if (version >= 0x73) {
        if (midi_routing == out.child_chunks.end() ||
                audio_routing == out.child_chunks.end()) {
            throw std::runtime_error(
                    "BBank v0x73..0x77 is missing routing chunks");
        }
        out.midi_routing = parse_bank_midi_routing(
                bytes.subspan(0, midi_routing->payload_offset +
                                         midi_routing->payload_size),
                *midi_routing, version);
        out.audio_routing = parse_bank_audio_routing(
                bytes.subspan(0, audio_routing->payload_offset +
                                         audio_routing->payload_size),
                *audio_routing, version);
    }
    if (children_end != bank_end)
        throw std::runtime_error("BBank has trailing bytes");
    out.end_offset = pos;
    return out;
}

} // namespace libnki
