// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "libnki/model.h"
#include "libnki/nki.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <functional>
#include <iterator>
#include <sstream>
#include <stdexcept>

namespace libnki {

std::uint32_t resolve_k1_group_output(const K1GroupOutputResolution &request,
        std::span<const std::int16_t> live_output_types) {
    auto ordinal = static_cast<std::uint32_t>(request.requested_ordinal);
    const auto count = std::min<std::size_t>(live_output_types.size(), 128);
    for (std::size_t index = 0; index < count; ++index) {
        const auto type = live_output_types[index];
        if (type < 1)
            break;
        if (static_cast<std::uint16_t>(type) != request.requested_output_type)
            continue;
        if (ordinal == 0)
            return static_cast<std::uint32_t>(index);
        --ordinal;
    }
    return 0;
}

namespace {

template <class Source>
SliceMachineSourceInfo legacy_slice_source_info(const Source &source) {
    return { source.slice_attack, source.slice_release, source.slice_auto_play,
        std::nullopt };
}

SliceMachineSourceInfo modern_slice_source_info(
        const SourceModePayload &source) {
    SliceMachineSourceInfo out;
    if (!source.variant_f32.empty())
        out.attack_ms = source.variant_f32[0];
    if (source.variant_f32.size() > 1)
        out.release_ms = source.variant_f32[1];
    if (!source.variant_bool.empty())
        out.legacy_playback_mode = source.variant_bool[0];
    // older versions default autoplay to true; in v0x106 only the tail bool
    // controls it, so don't reuse the playback-mode flag
    const auto version = source.prefix.serializable.version;
    if (version >= 0x100 && version < 0x106)
        out.auto_play = true;
    else if (version == 0x106 && source.variant_bool.size() > 1)
        out.auto_play = source.variant_bool[1];
    return out;
}

std::optional<std::int32_t> sample_bit_depth(std::uint32_t type) {
    // zero entries have no known bit depth
    constexpr std::array<std::int32_t, 22> bits{ 32, 8, 16, 24, 32, 16, 24, 32,
        32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8 };
    if (type >= bits.size() || bits[type] == 0)
        return std::nullopt;
    return bits[type];
}

std::optional<TimeMachineSourceInfo> time_machine_source_info(
        const K1SourceModeSemantic &source) {
    if (source.runtime_type != 3U)
        return std::nullopt;
    TimeMachineSourceInfo out;
    out.smooth = source.smooth;
    out.grain_length_ms = source.grain_length;
    out.grain_length_file_value = source.grain_length_file_value;
    out.grain_length_requires_sample_rate_conversion =
            source.grain_length_requires_sample_rate_conversion;
    out.high_quality = source.high_quality;
    out.dc_filter = source.dc_filter;
    out.serialized_retrigger = source.retrigger;
    out.analysis_grain_size = source.analysis_grain_size;
    return out;
}

std::optional<TimeMachineSourceInfo> time_machine_source_info(
        const K2SourceModeSemantic &source) {
    if (source.mode != K2SourceMode::time_machine)
        return std::nullopt;
    TimeMachineSourceInfo out;
    out.smooth = source.smooth;
    out.grain_length_ms = source.grain_length;
    out.high_quality = source.high_quality;
    out.dc_filter = source.dc_filter;
    out.serialized_retrigger = source.serialized_retrigger;
    out.legato = source.legato;
    out.analysis_grain_size = source.analysis_grain_size;
    return out;
}

std::optional<TimeMachineSourceInfo> time_machine_source_info(
        const SourceModePayload &source) {
    if (source.prefix.internal_mode != 3)
        return std::nullopt;
    TimeMachineSourceInfo out;
    // grain length is already in ms; leave clamping to the DSP parameter update
    if (!source.variant_f32.empty())
        out.smooth = source.variant_f32[0];
    if (source.variant_f32.size() > 1)
        out.grain_length_ms = source.variant_f32[1];
    if (!source.variant_bool.empty())
        out.high_quality = source.variant_bool[0];
    return out;
}

std::optional<TimeMachineProSourceInfo> time_machine_pro_source_info(
        const SourceModePayload &source) {
    if (source.prefix.internal_mode != 9)
        return std::nullopt;
    TimeMachineProSourceInfo out;
    // v0x100 has a discarded S32 where later versions store formant-follow,
    // so that version can't supply the second bool
    if (!source.variant_bool.empty())
        out.strategy = source.variant_bool[0] ? 1U : 0U;
    if (source.prefix.serializable.version >= 0x101 &&
            source.variant_bool.size() > 1)
        out.formant_follow_pitch = source.variant_bool[1];
    if (!source.variant_f32.empty())
        out.formant_amount = source.variant_f32[0];
    if (source.variant_f32.size() > 1)
        out.envelope_amount = source.variant_f32[1];
    return out;
}

std::optional<std::uint32_t> wavetable_warp_mode(std::int32_t serialized) {
    // selectors 18 and 19 are swapped; subtracting one only works for the rest
    if (serialized < 1 || serialized > 34)
        return std::nullopt;
    if (serialized == 18)
        return 18;
    if (serialized == 19)
        return 17;
    return static_cast<std::uint32_t>(serialized - 1);
}

std::optional<WavetableSourceInfo> wavetable_source_info(
        const SourceModePayload &source) {
    if (source.prefix.internal_mode != 2)
        return std::nullopt;
    WavetableSourceInfo out;
    // keep values as stored, warp selectors still need converting before
    // they're usable as DSP enums
    const auto version = source.prefix.serializable.version;
    if (version >= 0x103 && source.variant_f32.size() >= 4 &&
            source.variant_s32.size() >= 2) {
        out.position = source.variant_f32[0];
        out.warp1 = source.variant_f32[1];
        out.phase_seed = source.variant_f32[2];
        out.phase_randomization = source.variant_f32[3];
        out.serialized_warp1_mode = source.variant_s32[0];
        out.warp1_mode = wavetable_warp_mode(source.variant_s32[0]);
        if (source.variant_s32[1] >= 1 && source.variant_s32[1] <= 4)
            out.quality = static_cast<std::uint32_t>(source.variant_s32[1] - 1);
    }
    if (version >= 0x104 && source.variant_f32.size() >= 5 &&
            !source.variant_bool.empty()) {
        out.inharmonic_enabled = source.variant_bool[0];
        out.inharmonic_amount = source.variant_f32[4];
    }
    if (version >= 0x105 && source.variant_f32.size() >= 10 &&
            source.variant_s32.size() >= 5 && !source.variant_u32.empty() &&
            source.variant_bool.size() >= 3) {
        out.warp2 = source.variant_f32[5];
        out.serialized_warp2_mode = source.variant_s32[2];
        out.warp2_mode = wavetable_warp_mode(source.variant_s32[2]);
        out.modulation_selector =
                static_cast<std::uint32_t>(source.variant_s32[3]);
        out.fm_waveform = static_cast<std::uint32_t>(source.variant_s32[4]);
        out.modulation_amount = source.variant_f32[6];
        out.modulation_tune = source.variant_f32[7];
        out.modulation_custom_unit = source.variant_u32[0];
        out.modulation_unit_metadata1 = source.variant_f32[8];
        out.modulation_unit_metadata2 = source.variant_f32[9];
        out.modulation_unit_metadata_flag = source.variant_bool[1];
        out.modulation_use_custom_unit = source.variant_bool[2];
    }
    return out;
}

template <class T>
void append_values(std::vector<T> &destination, std::vector<T> &&source) {
    destination.insert(destination.end(),
            std::make_move_iterator(source.begin()),
            std::make_move_iterator(source.end()));
}

void append_model(Model &destination, Model source) {
    append_values(destination.instruments, std::move(source.instruments));
    append_values(destination.products, std::move(source.products));
    append_values(destination.contents, std::move(source.contents));
    append_values(destination.resources, std::move(source.resources));
    if (!destination.audio && source.audio)
        destination.audio = std::move(source.audio);
    append_values(destination.embedded_audio_samples,
            std::move(source.embedded_audio_samples));
    append_values(destination.external_file_references,
            std::move(source.external_file_references));
    append_values(destination.internal_resource_references,
            std::move(source.internal_resource_references));
    append_values(destination.pictures, std::move(source.pictures));
    append_values(
            destination.binary_resources, std::move(source.binary_resources));
    append_values(destination.resource_collections,
            std::move(source.resource_collections));
    append_values(destination.generic_items, std::move(source.generic_items));
    append_values(destination.modules, std::move(source.modules));
    append_values(destination.authorizations, std::move(source.authorizations));
    append_values(destination.repository_base_items,
            std::move(source.repository_base_items));
    append_values(destination.module_banks, std::move(source.module_banks));
    append_values(
            destination.repository_banks, std::move(source.repository_banks));
    append_values(destination.repository_bank_containers,
            std::move(source.repository_bank_containers));
    append_values(destination.repository_preset_containers,
            std::move(source.repository_preset_containers));
    append_values(destination.diagnostics, std::move(source.diagnostics));
}

bool empty_instrument(const InstrumentInfo &instrument) {
    return instrument.programs.empty() && instrument.groups.empty() &&
           instrument.zones.empty() && instrument.samples.empty() &&
           instrument.scripts.empty() && instrument.dyx_morph_groups.empty() &&
           instrument.dyx_morph_maps.empty();
}

std::string_view product_snpid(const Document &document) {
    for (const auto &preset : document.presets) {
        if (!preset.authorization_snpid.empty() &&
                preset.authorization_snpid != "000")
            return preset.authorization_snpid;
    }
    if (document.repository_root) {
        if (!document.repository_root->authorization_snpid.empty() &&
                document.repository_root->authorization_snpid != "000")
            return document.repository_root->authorization_snpid;
        if (!document.repository_root->file_reference.snpid.empty() &&
                document.repository_root->file_reference.snpid != "000")
            return document.repository_root->file_reference.snpid;
    }
    return {};
}

void append_protected_models(Model &model, std::span<const std::byte> bytes,
        const Document &document, std::span<const std::byte> private_key,
        std::size_t depth, std::span<const LocalLibraryInfo> libraries) {
    if (depth >= 64) {
        model.diagnostics.push_back("protected-item nesting exceeds 64 levels");
        return;
    }
    std::vector<std::byte> product_key;
    const auto needs_key = std::any_of(document.protected_items.begin(),
            document.protected_items.end(), [](const ProtectedItem &item) {
                return item.kind == ProtectedItemKind::encryption_item &&
                       item.xor_enabled.value_or(false);
            });
    if (needs_key) {
        const auto snpid = product_snpid(document);
        if (private_key.empty() || snpid.empty()) {
            model.diagnostics.push_back("protected instrument requires private "
                                        "key material and a product SNPID");
            return;
        }
        try {
            product_key = derive_local_product_encryption_key(
                    private_key, libraries, snpid);
        } catch (const std::exception &error) {
            model.diagnostics.push_back(
                    std::string("protected key derivation: ") + error.what());
            return;
        }
    }
    for (const auto &item : document.protected_items) {
        try {
            auto decoded = decode_protected_item(bytes, item, product_key);
            auto child = parse(decoded);
            auto child_model = normalize(child);
            append_protected_models(child_model, decoded, child, private_key,
                    depth + 1, libraries);
            append_model(model, std::move(child_model));
        } catch (const std::exception &error) {
            model.diagnostics.push_back(
                    std::string("protected item: ") + error.what());
        }
    }
}

void append_protected_models_with_product_key(Model &model,
        std::span<const std::byte> bytes, const Document &document,
        std::span<const std::byte> product_key, std::size_t depth) {
    if (depth >= 64) {
        model.diagnostics.push_back("protected-item nesting exceeds 64 levels");
        return;
    }
    for (const auto &item : document.protected_items) {
        try {
            auto decoded = decode_protected_item(bytes, item, product_key);
            auto child = parse(decoded);
            auto child_model = normalize(child);
            append_protected_models_with_product_key(
                    child_model, decoded, child, product_key, depth + 1);
            append_model(model, std::move(child_model));
        } catch (const std::exception &error) {
            model.diagnostics.push_back(
                    std::string("protected item: ") + error.what());
        }
    }
}

std::optional<std::string> legacy_attribute(
        const std::vector<K1TagAttribute> &attributes, std::string_view name) {
    const auto found = std::find_if(attributes.begin(), attributes.end(),
            [name](const K1TagAttribute &attribute) {
                return attribute.name == name;
            });
    if (found == attributes.end())
        return std::nullopt;
    return found->value;
}

StartMode start_mode(std::int32_t value) {
    if (value < 0 || value > 5)
        return StartMode::none;
    return static_cast<StartMode>(value);
}

NextStartCriterion next_criterion(std::int32_t value) {
    if (value < 0 || value > 2)
        return NextStartCriterion::and_also;
    return static_cast<NextStartCriterion>(value);
}

AhdsrEnvelopeInfo ahdsr(const K1EnvelopeParameters &value) {
    return { value.attack_curving, value.attack, value.hold, value.decay,
        value.sustain, value.release, value.note_off_less_mode,
        value.note_value_attack, value.note_value_hold, value.note_value_decay,
        value.note_value_release };
}

AhdsrEnvelopeInfo ahdsr(const K2EnvelopeSemantic &value) {
    return { value.attack_curving, value.attack, value.hold, value.decay,
        value.sustain, value.release, value.note_off_less_mode,
        value.note_value_attack, value.note_value_hold, value.note_value_decay,
        value.note_value_release };
}

Fm7EnvelopeInfo fm7(const K1EnvelopeParameters &value) {
    return { value.release_end, value.loop_start, value.loop_end,
        value.loop_enabled, value.oneshot_mode, value.times, value.levels,
        value.slopes, value.note_value_grid, 0.F, 40000.F, true };
}

Fm7EnvelopeInfo fm7(const K2EnvelopeSemantic &value) {
    return { value.release_end, value.loop_start, value.loop_end,
        value.loop_enabled, value.one_shot_mode, value.times, value.levels,
        value.slopes, value.note_value_grid, 0.F, 40000.F, true };
}

DbdEnvelopeInfo dbd(const K1EnvelopeParameters &value) {
    return { value.decay1, value.break_level, value.decay2,
        value.note_value_decay1, value.note_value_decay2 };
}

DbdEnvelopeInfo dbd(const K2EnvelopeSemantic &value) {
    return { value.decay_1, value.break_level, value.decay_2,
        value.note_value_decay_1, value.note_value_decay_2 };
}

InternalModulatorInfo internal_modulator(const K1ModulatorSemantic &value) {
    InternalModulatorInfo out;
    out.source_slot = value.index;
    if (value.internal_parameters) {
        out.bypass = value.internal_parameters->bypass;
        out.retrigger = value.internal_parameters->retrigger;
    }
    for (const auto &target : value.targets) {
        out.targets.push_back({ target.xml_target, target.target_id,
                target.intensity, target.negative_intensity,
                target.target_mod_index ? std::optional<std::int32_t>{ *target
                                                          .target_mod_index }
                                        : std::nullopt,
                target.slot_index, {}, {}, {}, {}, {}, {} });
    }
    if (value.envelope && value.envelope->type == K1EnvelopeType::ahdsr)
        out.ahdsr = ahdsr(*value.envelope);
    if (value.envelope && value.envelope->type == K1EnvelopeType::fm7)
        out.fm7 = fm7(*value.envelope);
    if (value.envelope && value.envelope->type == K1EnvelopeType::dbd)
        out.dbd = dbd(*value.envelope);
    if (value.lfo) {
        const auto &source = *value.lfo;
        LfoInfo lfo;
        if (source.waveform)
            lfo.waveform = static_cast<std::int32_t>(*source.waveform);
        lfo.delay = source.delay;
        lfo.note_value_delay = source.note_value_delay;
        lfo.levels = { source.level_sine, source.level_rectangle,
            source.level_triangle, source.level_sawtooth, source.level_random };
        if (value.internal_parameters) {
            lfo.frequency = value.internal_parameters->frequency;
            lfo.pulse_width = value.internal_parameters->pulse_width;
            lfo.note_value_frequency =
                    value.internal_parameters->note_value_frequency;
        }
        out.lfo = std::move(lfo);
    }
    return out;
}

InternalModulatorInfo internal_modulator(const K2InternalModSemantic &value) {
    InternalModulatorInfo out;
    out.source_slot = value.serialized_index;
    out.name = value.name;
    out.bypass = value.bypass;
    out.retrigger = value.retrigger;
    for (const auto &target : value.targets) {
        out.targets.push_back({ target.serialized_target, target.target_id,
                target.intensity,
                target.flags
                        ? std::optional<bool>{ (*target.flags & 0x02U) != 0 }
                        : std::nullopt,
                std::nullopt, target.slot_index, {}, {}, {}, {}, {}, {} });
        auto &normalized = out.targets.back();
        normalized.native_flags = target.flags;
        normalized.smoothing_coefficient = target.smoothing_coefficient;
        if (target.has_table) {
            normalized.transformation_kind = 1;
            normalized.transformation_enabled = target.table_active;
            normalized.transformation_values.assign(
                    target.table.begin(), target.table.end());
        } else if (target.has_curve) {
            normalized.transformation_kind = 2;
            normalized.transformation_enabled = target.curve_active;
            for (const auto &point : target.curve) {
                normalized.transformation_values.push_back(point.x);
                normalized.transformation_values.push_back(point.y);
                normalized.transformation_values.push_back(point.curve);
            }
        }
    }
    if (value.envelope && value.envelope->type == K2EnvelopeType::ahdsr)
        out.ahdsr = ahdsr(*value.envelope);
    if (value.envelope && value.envelope->type == K2EnvelopeType::fm7)
        out.fm7 = fm7(*value.envelope);
    if (value.envelope && value.envelope->type == K2EnvelopeType::dbd)
        out.dbd = dbd(*value.envelope);
    if (value.lfo) {
        const auto &source = *value.lfo;
        LfoInfo lfo;
        if (source.waveform)
            lfo.waveform = static_cast<std::int32_t>(*source.waveform);
        lfo.delay = source.delay;
        lfo.frequency = source.frequency;
        lfo.pulse_width = source.pulse_width;
        lfo.start_phase = source.start_phase;
        lfo.normalize_multi_lfo = source.normalize_multi_lfo;
        lfo.note_value_frequency = source.note_value_frequency;
        lfo.note_value_frequency_enabled = source.note_value_frequency_enabled;
        lfo.note_value_delay = source.note_value_delay;
        lfo.note_value_delay_enabled = source.note_value_delay_enabled;
        lfo.levels = { source.sine_level, source.rectangle_level,
            source.triangle_level, source.sawtooth_level, source.random_level };
        lfo.serialized_version = source.parsed_version;
        out.lfo = std::move(lfo);
    }
    return out;
}

InternalModulatorInfo internal_modulator(
        const InternalModulatorPayload &value) {
    InternalModulatorInfo out;
    out.name = value.name;

    out.bypass = value.flags[1];
    out.retrigger = value.flags[2];
    out.source_fourth_flag = value.flags[3];
    for (const auto &target : value.targets) {
        out.targets.push_back({ target.target_xml_name, std::nullopt,
                target.amount, (target.u8 & 0x02U) != 0,
                target.target_s8
                        ? std::optional<std::int32_t>{ *target.target_s8 }
                        : std::nullopt,
                target.s16_a, {}, {}, {}, {}, {}, {} });
        auto &normalized = out.targets.back();
        normalized.native_flags = target.u8;
        if (!target.assignment.empty() && target.assignment != "<none>")
            normalized.assignment_name = target.assignment;
        // the second S16 is smoothing, the first one was the slot
        normalized.smoothing_coefficient = target.s16_b;
        normalized.transformation_kind = target.transformation.serialized_kind;
        normalized.transformation_enabled = target.transformation.enabled;
        normalized.transformation_values = target.transformation.values;
    }
    if (value.modulator_type == 1 && value.lfo) {
        const auto &source = *value.lfo;
        const auto version = source.serializable.version;
        const auto note_count = version == 0x70 ? 6U : 10U;
        if (version >= 0x70 && version <= 0x73 &&
                source.values.size() >= note_count && !source.flags.empty()) {
            LfoInfo lfo;

            lfo.serialized_version = version;
            lfo.waveform = source.waveform;
            lfo.delay = source.values[0];
            lfo.frequency = source.values[1];
            lfo.pulse_width = source.values[2];
            lfo.start_phase = source.values[3];
            lfo.normalize_multi_lfo = source.flags[0];
            lfo.note_value_frequency = source.values[4];
            lfo.note_value_delay = source.values[version == 0x70 ? 5 : 7];
            lfo.note_value_frequency_enabled =
                    *lfo.note_value_frequency > 1.0e-9F;
            lfo.note_value_delay_enabled = *lfo.note_value_delay > 1.0e-9F;
            if (version == 0x70) {
                lfo.note_frequency_mode = true;
                lfo.note_delay_mode = true;
            } else {
                lfo.note_frequency_metadata = { source.values[5],
                    source.values[6] };
                lfo.note_delay_metadata = { source.values[8],
                    source.values[9] };
                if (source.flags.size() >= 3) {
                    lfo.note_frequency_mode = source.flags[1];
                    lfo.note_delay_mode = source.flags[2];
                }
            }
            if ((source.waveform == 5 ||
                        (version >= 0x71 && source.waveform == 6)) &&
                    source.values.size() >= note_count + 5) {
                for (std::size_t index = 0; index < lfo.levels.size(); ++index)
                    lfo.levels[index] = source.values[note_count + index];
            }
            if (version < 0x73)
                lfo.serialized_flag_1d = false;
            else if (source.flags.size() >= 4)
                lfo.serialized_flag_1d = source.flags[3];
            out.lfo = std::move(lfo);
        }
    }
    if (value.modulator_type == 2 && value.envelope &&
            value.envelope->envelope_type == 0) {
        const auto &child = value.envelope->child;
        if (child.f32.size() >= 6) {
            AhdsrEnvelopeInfo env;
            // wire order differs from AHDSR stage order
            env.attack_curving = child.f32[0];
            env.attack = child.f32[1];
            env.decay = child.f32[2];
            env.hold = child.f32[3];
            env.release = child.f32[4];
            env.sustain = child.f32[5];
            if (!child.flags.empty())
                env.note_off_less_mode = child.flags[0];
            out.ahdsr = std::move(env);
        }
    }
    if (value.modulator_type == 2 && value.envelope &&
            value.envelope->envelope_type == 1) {
        const auto &child = value.envelope->child;
        // times, levels and slopes are interleaved; the tempo grid follows them
        if (child.s32.size() >= 3 && child.s32[0] >= -1 && child.s32[0] < 32) {
            const auto count = static_cast<std::size_t>(child.s32[0] + 1);
            if (child.f32.size() >= count * 3 + 1) {
                Fm7EnvelopeInfo env;
                env.release_end = child.s32[0];
                env.loop_start = child.s32[1];
                env.loop_end = child.s32[2];
                for (std::size_t point = 0; point < count; ++point) {
                    env.times[point] = child.f32[point * 3];
                    env.levels[point] = child.f32[point * 3 + 1];
                    env.slopes[point] = child.f32[point * 3 + 2];
                }
                env.note_value_grid = child.f32[count * 3];
                if (child.f32.size() >= count * 3 + 3) {
                    env.note_value_min_ms = child.f32[count * 3 + 1];
                    env.note_value_max_ms = child.f32[count * 3 + 2];
                    // the constructor sets this, it's not in the file
                    env.note_value_clamp_below_one = true;
                } else if (child.serializable.version == 0x10 &&
                           child.f32.size() == count * 3 + 1 &&
                           child.flags.empty()) {
                    // the short v10 layout leaves the constructor limits intact
                    env.note_value_min_ms = 0.F;
                    env.note_value_max_ms = 40000.F;
                    env.note_value_clamp_below_one = true;
                }
                if (child.serializable.version == 0x12 &&
                        child.flags.size() >= 2) {
                    env.loop_enabled = child.flags[0];
                    env.one_shot_mode = child.flags[1];
                }
                out.fm7 = std::move(env);
            }
        }
    }
    if (value.modulator_type == 2 && value.envelope &&
            value.envelope->envelope_type == 2) {
        const auto &child = value.envelope->child;
        const auto version = child.serializable.version;
        // v12 inserts metadata and mode fields between the two note values
        if (child.f32.size() >= (version == 0x12 ? 9U : 5U)) {
            DbdEnvelopeInfo env;
            env.decay_1 = child.f32[0];
            env.break_level = child.f32[1];
            env.decay_2 = child.f32[2];
            env.note_value_decay_1 = child.f32[3];
            env.note_value_decay_2 = child.f32[version == 0x12 ? 6 : 4];
            env.zero_break_and_decay_2 = version >= 0x11 && !child.flags.empty()
                                                 ? child.flags.back()
                                                 : false;
            out.dbd = std::move(env);
        }
    }
    return out;
}

ExternalModulatorInfo external_modulator(const K1ModulatorSemantic &value) {
    ExternalModulatorInfo out;
    out.type = ExternalModulatorType::external;
    // the K1 import leaves K2 envelope-time modulation disabled
    out.simulate_k2_env_time_modulation = false;
    if (value.external_parameters) {
        out.bypass = value.external_parameters->bypass;
        out.delay = value.external_parameters->delay;
        if (value.external_parameters->cc_number &&
                *value.external_parameters->cc_number >= 0) {
            out.controller = static_cast<std::uint8_t>(
                    *value.external_parameters->cc_number);
        }
        if (value.external_parameters->source) {
            out.source = static_cast<ExternalModulatorSource>(
                    *value.external_parameters->source);
        }
    }
    for (const auto &target : value.targets) {
        out.targets.push_back({ target.xml_target, target.target_id,
                target.intensity, target.negative_intensity,
                target.target_mod_index ? std::optional<std::int32_t>{ *target
                                                          .target_mod_index }
                                        : std::nullopt,
                target.slot_index, {}, {}, {}, {}, {}, {} });
    }
    return out;
}

ExternalModulatorInfo external_modulator(const K2ExternalModSemantic &value) {
    ExternalModulatorInfo out;
    out.name = value.name;
    out.bypass = value.bypass;
    if (value.type)
        out.type = static_cast<ExternalModulatorType>(*value.type);
    if (value.source)
        out.source = static_cast<ExternalModulatorSource>(*value.source);
    out.controller = value.cc_number;
    out.delay = value.serialized_delay;
    out.initial_value = value.initial_value;
    out.simulate_k2_env_time_modulation =
            value.simulate_k2_envelope_time_modulation;
    for (const auto &target : value.targets) {
        out.targets.push_back({ target.serialized_target, target.target_id,
                target.intensity,
                target.flags
                        ? std::optional<bool>{ (*target.flags & 0x02U) != 0 }
                        : std::nullopt,
                std::nullopt, target.slot_index, {}, {}, {}, {}, {}, {} });
        auto &normalized = out.targets.back();
        normalized.native_flags = target.flags;
        normalized.smoothing_coefficient = target.smoothing_coefficient;
        if (target.has_table) {
            normalized.transformation_kind = 1;
            normalized.transformation_enabled = target.table_active;
            normalized.transformation_values.assign(
                    target.table.begin(), target.table.end());
        } else if (target.has_curve) {
            normalized.transformation_kind = 2;
            normalized.transformation_enabled = target.curve_active;
            for (const auto &point : target.curve) {
                normalized.transformation_values.push_back(point.x);
                normalized.transformation_values.push_back(point.y);
                normalized.transformation_values.push_back(point.curve);
            }
        }
    }
    return out;
}

ExternalModulatorInfo external_modulator(
        const ExternalModulatorPayload &value) {
    ExternalModulatorInfo out;
    out.name = value.name;
    // mode zero is inactive, so it doesn't select either active type
    if (value.mode == 1 || value.mode == 2)
        out.type = static_cast<ExternalModulatorType>(value.mode);
    // a missing bool tells us nothing about bypass
    if (value.flag_count >= 1)
        out.bypass = value.flags[0];
    // only a complete modern mode-1 source tells us the delay starts at zero,
    // target smoothing is a different field
    const auto required_flags =
            value.serializable.version >= 0x104
                    ? 4U
                    : (value.serializable.version >= 0x103 ? 3U : 2U);
    const bool complete_modern_source = value.serializable.version >= 0x100 &&
                                        value.serializable.version <= 0x104 &&
                                        value.mode == 1 &&
                                        value.flag_count >= required_flags &&
                                        value.serialized_source && value.source;
    if (complete_modern_source)
        out.delay = 0.F;
    // don't turn an absent compatibility flag into false
    if (value.flag_count >= 2)
        out.simulate_k2_env_time_modulation = value.flags[1];
    if (value.source && ((*value.source >= 1 && *value.source <= 4) ||
                                (*value.source >= 7 && *value.source <= 13)))
        out.source = static_cast<ExternalModulatorSource>(*value.source);
    out.controller = value.controller;
    out.initial_value = value.s16;
    for (const auto &target : value.targets) {
        out.targets.push_back({ target.target_xml_name, std::nullopt,
                target.amount, (target.u8 & 0x02U) != 0,
                target.target_s8
                        ? std::optional<std::int32_t>{ *target.target_s8 }
                        : std::nullopt,
                target.s16_a, {}, {}, {}, {}, {}, {} });
        auto &normalized = out.targets.back();
        // volume keeps the -1 receiver index from reset, but we only know that
        // for a complete mode-1 source and target list, not volume2 or
        // modulator/effect destinations
        if (!target.target_s8 && target.target_xml_name == "volume" &&
                complete_modern_source &&
                (value.base_layout_version == 1 ||
                        value.base_layout_version == 2) &&
                value.target_count > 0 &&
                static_cast<std::size_t>(value.target_count) ==
                        value.targets.size())
            normalized.modulator_index = -1;
        normalized.native_flags = target.u8;
        if (!target.assignment.empty() && target.assignment != "<none>")
            normalized.assignment_name = target.assignment;
        normalized.smoothing_coefficient = target.s16_b;
        normalized.transformation_kind = target.transformation.serialized_kind;
        normalized.transformation_enabled = target.transformation.enabled;
        normalized.transformation_values = target.transformation.values;
    }
    return out;
}

std::optional<FilterType> filter_type(std::string_view value) {
    static constexpr std::pair<std::string_view, FilterType> values[] = {
        { "lp1pole", FilterType::low_pass_1_pole },
        { "hp1pole", FilterType::high_pass_1_pole },
        { "bp2pole", FilterType::band_pass_2_pole },
        { "lp2pole", FilterType::low_pass_2_pole },
        { "hp2pole", FilterType::high_pass_2_pole },
        { "lp4pole", FilterType::low_pass_4_pole },
        { "hp4pole", FilterType::high_pass_4_pole },
        { "bp4pole", FilterType::band_pass_4_pole },
        { "br4pole", FilterType::band_reject_4_pole },
        { "lp6pole", FilterType::low_pass_6_pole },
        { "phaser", FilterType::phaser },
        { "vowelA", FilterType::vowel_a },
        { "vowelB", FilterType::vowel_b },
        { "pro52", FilterType::pro_52 },
        { "ladder", FilterType::ladder },
        { "versatile", FilterType::versatile },
        { "eq1band", FilterType::eq_1_band },
        { "eq2band", FilterType::eq_2_band },
        { "eq3band", FilterType::eq_3_band },
    };
    const auto found = std::find_if(std::begin(values), std::end(values),
            [value](const auto &entry) { return entry.first == value; });
    return found == std::end(values)
                   ? std::nullopt
                   : std::optional<FilterType>{ found->second };
}

FilterType filter_type(std::uint32_t value) {
    // 0x16..0x21 select current ladder subtypes; legacy ladder has stable type
    // 17
    if (value >= 0x16U && value <= 0x21U)
        return FilterType::ladder_current;
    if (value == 0x58U)
        return FilterType::simple_lp_hp;
    return static_cast<FilterType>(value);
}

GroupEffectInfo filter_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::filter;
    out.slot_index = value.runtime_slot;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    FilterInfo filter;
    if (value.type)
        filter.type = filter_type(*value.type);
    filter.cutoff = value.cutoff;
    filter.resonance = value.resonance;
    filter.gain = value.gain;
    filter.frequency = value.frequency;
    filter.bandwidth = value.band_width;
    filter.band_gain = value.band_gain;
    filter.shift = value.shift;
    filter.band_resonance = value.band_resonance;
    filter.band_type = value.band_type;
    filter.band_bypass = value.band_bypass;
    out.filter = std::move(filter);
    return out;
}

GroupEffectInfo filter_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::filter;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    FilterInfo filter;
    if (value.filter_type) {
        filter.serialized_type = static_cast<std::uint32_t>(*value.filter_type);
        filter.type = filter_type(*filter.serialized_type);
    }
    filter.cutoff = value.filter_cutoff;
    filter.resonance = value.filter_resonance;
    if (filter.type == FilterType::ladder_current ||
            filter.type == FilterType::daft_low_pass ||
            filter.type == FilterType::daft_high_pass)
        filter.input_gain = value.filter_gain;
    else
        filter.gain = value.filter_gain;
    filter.frequency = value.filter_eq_frequency;
    filter.bandwidth = value.filter_eq_bandwidth;
    filter.band_gain = value.filter_eq_gain;
    filter.shift[1] = value.filter_shift_b;
    filter.shift[2] = value.filter_shift_c;
    filter.band_resonance[1] = value.filter_resonance_b;
    filter.band_resonance[2] = value.filter_resonance_c;
    filter.band_type = value.filter_vowel_type;
    filter.band_bypass = value.filter_vowel_bypass;
    out.filter = std::move(filter);
    return out;
}

std::optional<GroupEffectInfo> filter_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::filter)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::filter;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    // the first private bool is routersOpen; bypass is the second
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    FilterInfo filter;
    if (!value.parsed_child->converted_type.empty()) {
        filter.serialized_type = value.parsed_child->converted_type.front();
        filter.type = filter_type(*filter.serialized_type);
    }
    if (!value.parsed_child->s32.empty() &&
            value.parsed_child->s32.front() >= 0) {
        filter.serialized_fix_type =
                static_cast<std::uint32_t>(value.parsed_child->s32.front());
    }
    if (filter.type == FilterType::simple_lp_hp) {
        // these are separate extended-range cutoffs: ladder LP, then DJ HP
        if (!value.parsed_child->f32.empty())
            filter.low_pass_cutoff = value.parsed_child->f32[0];
        if (value.parsed_child->f32.size() > 1)
            filter.high_pass_cutoff = value.parsed_child->f32[1];
    } else if (filter.type &&
               *filter.type >= FilterType::multi_state_variable_low_pass &&
               *filter.type <= FilterType::multi_state_variable_high_pass) {
        // width comes first on the wire even though the core IDs are 2, 0, 1
        if (!value.parsed_child->f32.empty())
            filter.multi_bandwidth = value.parsed_child->f32[0];
        if (value.parsed_child->f32.size() > 1)
            filter.cutoff = value.parsed_child->f32[1];
        if (value.parsed_child->f32.size() > 2)
            filter.resonance = value.parsed_child->f32[2];
    } else if (filter.type == FilterType::formant_a ||
               filter.type == FilterType::formant_b) {
        // wire order is talk, sharp, size; core parameter IDs are 0, 2, 1
        if (!value.parsed_child->f32.empty())
            filter.formant_position = value.parsed_child->f32[0];
        if (value.parsed_child->f32.size() > 1)
            filter.formant_sharpness = value.parsed_child->f32[1];
        if (value.parsed_child->f32.size() > 2)
            filter.formant_shift = value.parsed_child->f32[2];
    } else if (filter.type == FilterType::daft_low_pass ||
               filter.type == FilterType::daft_high_pass) {
        // Daft's first value is core input gain, before cutoff and resonance
        if (!value.parsed_child->f32.empty())
            filter.input_gain = value.parsed_child->f32[0];
        if (value.parsed_child->f32.size() > 1)
            filter.cutoff = value.parsed_child->f32[1];
        if (value.parsed_child->f32.size() > 2)
            filter.resonance = value.parsed_child->f32[2];
    } else if (filter.type == FilterType::ladder_current) {
        // current ladder subtypes put input gain before cutoff and resonance
        if (!value.parsed_child->f32.empty())
            filter.input_gain = value.parsed_child->f32[0];
        if (value.parsed_child->f32.size() > 1)
            filter.cutoff = value.parsed_child->f32[1];
        if (value.parsed_child->f32.size() > 2)
            filter.resonance = value.parsed_child->f32[2];

        // v0x95 inserts legacy smoothing before the hiQ flag added in v0x92
        const auto version = value.parsed_child->serializable.version;
        if (version >= 0x95 && !value.parsed_child->boolean.empty())
            filter.legacy_smoothing = value.parsed_child->boolean[0];
        const std::size_t hi_q_index = version >= 0x95 ? 1 : 0;
        if (version >= 0x92 && value.parsed_child->boolean.size() > hi_q_index)
            filter.high_quality = value.parsed_child->boolean[hi_q_index];
    } else {
        if (!value.parsed_child->f32.empty())
            filter.cutoff = value.parsed_child->f32[0];
        if (value.parsed_child->f32.size() > 1)
            filter.resonance = value.parsed_child->f32[1];
    }
    if (filter.type == FilterType::versatile &&
            value.parsed_child->f32.size() >= 13) {
        filter.shift[1] = value.parsed_child->f32[2];
        filter.shift[2] = value.parsed_child->f32[3];
        filter.band_resonance[1] = value.parsed_child->f32[4];
        filter.band_resonance[2] = value.parsed_child->f32[5];
        for (std::size_t index = 0; index < 3; ++index) {
            filter.band_type[index] = value.parsed_child->f32[6 + index];
            filter.band_bypass[index] = value.parsed_child->f32[9 + index];
        }
        filter.gain = value.parsed_child->f32[12];
    } else if (filter.type && *filter.type >= FilterType::eq_1_band &&
               *filter.type <= FilterType::eq_3_band) {
        const std::size_t band_count =
                static_cast<std::size_t>(*filter.type) -
                static_cast<std::size_t>(FilterType::eq_1_band) + 1;
        for (std::size_t index = 0; index < band_count; ++index) {
            const std::size_t base = index * 3;
            if (value.parsed_child->f32.size() <= base + 2)
                break;
            filter.frequency[index] = value.parsed_child->f32[base];
            filter.bandwidth[index] = value.parsed_child->f32[base + 1];
            filter.band_gain[index] = value.parsed_child->f32[base + 2];
        }
    }
    out.filter = std::move(filter);
    return out;
}

GroupEffectInfo gainer_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::gainer;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.gain = value.gain;
    return out;
}

std::optional<GroupEffectInfo> gainer_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::gainer)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::gainer;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    if (!value.parsed_child->f32.empty())
        out.gain = value.parsed_child->f32[0];
    return out;
}

GroupEffectInfo inverter_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::inverter;
    out.slot_index = value.runtime_slot;
    out.internal_type = 4;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.phase = value.phase;
    out.panorama = value.panorama;
    return out;
}

GroupEffectInfo inverter_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::inverter;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.phase = value.inverter_phase;
    out.panorama = value.inverter_panorama;
    return out;
}

std::optional<GroupEffectInfo> inverter_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::inverter)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::inverter;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    if (!value.parsed_child->boolean.empty())
        out.phase = value.parsed_child->boolean[0];
    if (value.parsed_child->boolean.size() > 1)
        out.panorama = value.parsed_child->boolean[1];
    return out;
}

GroupEffectInfo stereo_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::stereo_spread;
    out.slot_index = value.runtime_slot;
    out.internal_type = 10;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.spread = value.spread;
    return out;
}

GroupEffectInfo stereo_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::stereo_spread;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.spread = value.stereo_spread;
    out.pan = value.stereo_pan;
    out.pseudo = value.stereo_pseudo;
    return out;
}

std::optional<GroupEffectInfo> stereo_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::stereo_spread)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::stereo_spread;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    if (!value.parsed_child->f32.empty())
        out.spread = value.parsed_child->f32[0];
    if (value.parsed_child->f32.size() > 1)
        out.pan = value.parsed_child->f32[1];
    if (!value.parsed_child->boolean.empty())
        out.pseudo = value.parsed_child->boolean[0];
    return out;
}

GroupEffectInfo shaper_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::shaper;
    out.slot_index = value.runtime_slot;
    out.internal_type = 7;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.shape = value.shape;
    out.shaper_model = ShaperModel::classic;
    return out;
}

GroupEffectInfo shaper_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::shaper;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.shape = value.shaper_shape;
    if (value.shaper_type && *value.shaper_type >= 0 && *value.shaper_type <= 2)
        out.shaper_model = static_cast<ShaperModel>(*value.shaper_type);
    return out;
}

std::optional<GroupEffectInfo> shaper_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::shaper)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::shaper;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    if (!value.parsed_child->f32.empty())
        out.shape = value.parsed_child->f32[0];
    if (!value.parsed_child->s32.empty() && value.parsed_child->s32[0] >= 0 &&
            value.parsed_child->s32[0] <= 2)
        out.shaper_model = static_cast<ShaperModel>(value.parsed_child->s32[0]);
    return out;
}

GroupEffectInfo lo_fi_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::lo_fi;
    out.slot_index = value.runtime_slot;
    out.internal_type = 9;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.lo_fi_bits = value.bits;
    out.lo_fi_down_sample = value.down_sample;
    out.lo_fi_noise_level = value.noise_level;
    out.lo_fi_noise_color = value.noise_color;
    out.lo_fi_down_sample_requires_engine_rate_conversion =
            value.down_sample_requires_engine_sample_rate_conversion;
    return out;
}

GroupEffectInfo lo_fi_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::lo_fi;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.lo_fi_bits = value.lo_fi_bits;
    out.lo_fi_down_sample = value.lo_fi_down_sample;
    out.lo_fi_sample_hold_integer = value.lo_fi_sample_hold_integer;
    out.lo_fi_noise_level = value.lo_fi_noise_level;
    out.lo_fi_noise_color = value.lo_fi_noise_color;
    return out;
}

std::optional<GroupEffectInfo> lo_fi_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::lo_fi)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::lo_fi;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.f32.empty())
        out.lo_fi_bits = child.f32[0];
    if (child.f32.size() > 1)
        out.lo_fi_down_sample = child.f32[1];
    if (!child.boolean.empty())
        out.lo_fi_sample_hold_integer = child.boolean[0];
    if (child.f32.size() > 2)
        out.lo_fi_noise_level = child.f32[2];
    if (child.f32.size() > 3)
        out.lo_fi_noise_color = child.f32[3];
    return out;
}

std::optional<GroupEffectInfo> tape_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child || value.parsed_child->kind != ParFxChildKind::tape)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::tape;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.f32.empty())
        out.tape_gain = child.f32[0];
    if (child.f32.size() > 1)
        out.tape_warmth = child.f32[1];
    if (child.f32.size() > 2)
        out.tape_rolloff = child.f32[2];
    if (!child.boolean.empty())
        out.tape_high_quality = child.boolean[0];
    return out;
}

std::optional<GroupEffectInfo> transient_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::transient_master)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::transient_master;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.f32.empty())
        out.transient_attack = child.f32[0];
    if (child.f32.size() > 1)
        out.transient_sustain = child.f32[1];
    if (child.f32.size() > 2)
        out.transient_gain = child.f32[2];
    if (!child.s32.empty())
        out.transient_mode = child.s32[0];
    return out;
}

GroupEffectInfo distortion_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::distortion;
    out.slot_index = value.runtime_slot;
    out.internal_type = 11;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    if (value.type == "tube")
        out.distortion_model = DistortionModel::tube;
    else if (value.type == "transistor")
        out.distortion_model = DistortionModel::transistor;
    out.distortion_drive = value.drive;
    out.distortion_damping = value.damping;
    return out;
}

GroupEffectInfo distortion_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::distortion;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    if (value.distortion_type)
        out.distortion_model = static_cast<DistortionModel>(
                static_cast<std::uint8_t>(*value.distortion_type));
    out.distortion_drive = value.distortion_drive;
    out.distortion_damping = value.distortion_damping;
    return out;
}

std::optional<GroupEffectInfo> distortion_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::distortion)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::distortion;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.s32.empty() && child.s32[0] >= 0 && child.s32[0] < 2)
        out.distortion_model = static_cast<DistortionModel>(child.s32[0]);
    if (!child.f32.empty())
        out.distortion_drive = child.f32[0];
    if (child.f32.size() > 1)
        out.distortion_damping = child.f32[1];
    return out;
}

GroupEffectInfo compressor_effect(const K1EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::compressor;
    out.slot_index = value.runtime_slot;
    out.internal_type = 2;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    if (value.model == "classic")
        out.compressor_model = CompressorModel::classic;
    else if (value.model == "enhanced")
        out.compressor_model = CompressorModel::enhanced;
    out.compressor_threshold = value.threshold;
    out.compressor_ratio = value.ratio;
    out.compressor_attack = value.attack;
    out.compressor_release = value.release;
    out.compressor_stereo_link = value.stereo_link;
    return out;
}

GroupEffectInfo compressor_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::compressor;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    if (value.compressor_model)
        out.compressor_model = static_cast<CompressorModel>(
                static_cast<std::uint8_t>(*value.compressor_model));
    out.compressor_threshold = value.compressor_threshold;
    out.compressor_ratio = value.compressor_ratio;
    out.compressor_attack = value.compressor_attack;
    out.compressor_release = value.compressor_release;
    out.compressor_stereo_link = value.compressor_stereo_link;
    return out;
}

std::optional<GroupEffectInfo> compressor_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::compressor)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::compressor;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.s32.empty() && child.s32[0] >= 0 && child.s32[0] < 3)
        out.compressor_model = static_cast<CompressorModel>(child.s32[0]);
    if (!child.f32.empty())
        out.compressor_threshold = child.f32[0];
    if (child.f32.size() > 1)
        out.compressor_ratio = child.f32[1];
    if (child.f32.size() > 2)
        out.compressor_attack = child.f32[2];
    if (child.f32.size() > 3)
        out.compressor_release = child.f32[3];
    if (!child.boolean.empty())
        out.compressor_stereo_link = child.boolean[0];
    return out;
}

GroupEffectInfo limiter_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::limiter;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.limiter_input_gain = value.limiter_input_gain;
    out.limiter_release_time = value.limiter_release_time;
    return out;
}

std::optional<GroupEffectInfo> limiter_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::limiter)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::limiter;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    if (!value.parsed_child->f32.empty())
        out.limiter_input_gain = value.parsed_child->f32[0];
    if (value.parsed_child->f32.size() > 1)
        out.limiter_release_time = value.parsed_child->f32[1];
    return out;
}

std::optional<GroupEffectInfo> transparent_limiter_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::hilbert_limiter)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::transparent_limiter;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.f32.empty())
        out.transparent_limiter_input = child.f32[0];
    if (child.f32.size() > 1)
        out.transparent_limiter_release = child.f32[1];
    if (child.f32.size() > 2)
        out.transparent_limiter_ceiling = child.f32[2];
    if (!child.boolean.empty())
        out.transparent_limiter_external_sidechain = child.boolean[0];
    return out;
}

GroupEffectInfo dyx_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::dyx;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.dyx_morph = value.dyx_morph;
    out.dyx_dry = value.dyx_dry;
    out.dyx_morph_map_index = value.dyx_morph_map_index;
    out.dyx_linear_phase = value.dyx_linear_phase;
    return out;
}

std::optional<GroupEffectInfo> dyx_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child || value.parsed_child->kind != ParFxChildKind::dyx)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::dyx;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.f32.empty())
        out.dyx_morph = child.f32[0];
    if (child.f32.size() > 1)
        out.dyx_dry = child.f32[1];
    if (!child.s32.empty())
        out.dyx_morph_map_index = child.s32[0];
    if (!child.boolean.empty())
        out.dyx_linear_phase = child.boolean[0];
    return out;
}

GroupEffectInfo irc_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::irc;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.irc_sample_rate_decimation_factor =
            value.irc_sample_rate_decimation_factor;
    out.irc_serialized_convolution_block_size =
            value.irc_serialized_convolution_block_size;
    out.irc_effective_convolution_block_size =
            value.irc_effective_convolution_block_size;
    out.irc_pre_delay = value.irc_pre_delay;
    out.irc_early_length_ratio = value.irc_early_length_ratio;
    out.irc_early_high_pass_frequency = value.irc_early_high_pass_frequency;
    out.irc_early_low_pass_frequency = value.irc_early_low_pass_frequency;
    out.irc_late_length_ratio = value.irc_late_length_ratio;
    out.irc_late_high_pass_frequency = value.irc_late_high_pass_frequency;
    out.irc_late_low_pass_frequency = value.irc_late_low_pass_frequency;
    out.irc_early_late_crosspoint = value.irc_early_late_crosspoint;
    out.irc_reverse = value.irc_reverse;
    out.irc_auto_gain = value.irc_auto_gain;
    out.irc_preserve_ir_length = value.irc_preserve_ir_length;
    out.irc_bypass_latency_compensation =
            value.irc_effective_bypass_latency_compensation;
    out.irc_envelope_active = value.irc_envelope_active;
    out.irc_envelope_times = value.irc_envelope_times;
    out.irc_envelope_levels = value.irc_envelope_levels;
    return out;
}

GroupEffectInfo send_levels_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::send_levels;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.internal_type = value.internal_type;
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    out.send_levels = value.send_levels;
    return out;
}

GroupEffectInfo surround_panner_effect(const K2EffectSemantic &value) {
    GroupEffectInfo out;
    out.type = GroupEffectType::surround_panner;
    out.internal_type = 6;
    if (value.serialized_index && *value.serialized_index >= 0)
        out.slot_index = static_cast<std::size_t>(*value.serialized_index);
    out.bypass = value.bypass;
    out.output_level = value.output_level;
    out.dry_output_level = value.dry_output_level;
    const auto append_points = [](auto &destination, const auto &source,
                                       std::int32_t requested) {
        const auto count = std::clamp(requested, 0, 16);
        for (std::int32_t index = 0; index < count; ++index) {
            const auto &point = source[static_cast<std::size_t>(index)];
            if (!point.x || !point.y)
                continue;
            destination.push_back(SurroundPannerPoint{ *point.x, *point.y,
                    point.effective_flags_or_role.value_or(0) });
        }
    };
    append_points(out.surround_output_points, value.surround_speakers,
            value.surround_serialized_speaker_count.value_or(0));
    append_points(out.surround_input_points, value.surround_sources,
            value.surround_source_count.value_or(0));
    out.surround_lfe_crossover_frequency =
            value.surround_lfe_crossover_frequency;
    out.surround_lfe_volume = value.surround_lfe_volume;
    out.surround_size = value.surround_size;
    out.surround_divergence = value.surround_divergence;
    out.surround_air_amount = value.surround_air_amount;
    out.surround_delay_amount = value.surround_delay_amount;
    if (value.surround_volume_algorithm)
        out.surround_volume_algorithm =
                static_cast<std::int32_t>(*value.surround_volume_algorithm);
    out.surround_use_speaker_delays = value.surround_use_speaker_delays;
    out.surround_use_air_absorption = value.surround_use_air_absorption;
    out.surround_use_doppler_effect = value.surround_use_doppler_effect;
    out.surround_offset_distance = value.surround_offset_distance;
    out.surround_offset_azimuth = value.surround_offset_azimuth;
    out.surround_offset_x = value.surround_offset_x;
    out.surround_offset_y = value.surround_offset_y;
    out.surround_preset_speaker_setup = value.surround_preset_speaker_setup;
    return out;
}

std::optional<GroupEffectInfo> irc_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child || value.parsed_child->kind != ParFxChildKind::irc)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::irc;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &child = *value.parsed_child;
    if (!child.f32.empty())
        out.irc_sample_rate_decimation_factor = child.f32[0];
    if (!child.s32.empty()) {
        out.irc_serialized_convolution_block_size = child.s32[0];
        // tagged presets handle negative sentinels on their own
        out.irc_effective_convolution_block_size =
                std::clamp(child.s32[0], 0, 1024);
    }
    const auto field = [&](std::size_t index) -> std::optional<float> {
        return child.f32.size() > index
                       ? std::optional<float>{ child.f32[index] }
                       : std::nullopt;
    };
    out.irc_pre_delay = field(1);
    out.irc_early_length_ratio = field(2);
    out.irc_early_high_pass_frequency = field(3);
    out.irc_early_low_pass_frequency = field(4);
    out.irc_late_length_ratio = field(5);
    out.irc_late_high_pass_frequency = field(6);
    out.irc_late_low_pass_frequency = field(7);
    out.irc_early_late_crosspoint = field(8);
    if (!child.boolean.empty())
        out.irc_reverse = child.boolean[0];
    if (child.boolean.size() > 1)
        out.irc_auto_gain = child.boolean[1];
    if (child.boolean.size() > 2)
        out.irc_preserve_ir_length = child.boolean[2];
    if (child.boolean.size() > 3)
        out.irc_bypass_latency_compensation = child.boolean[3];
    if (child.boolean.size() > 4)
        out.irc_envelope_active = child.boolean[4];
    std::size_t source = 9;
    const auto time_count =
            child.u32.empty() ? 0U : std::min<std::uint32_t>(child.u32[0], 8U);
    const auto level_count =
            child.u32.size() < 2 ? 0U
                                 : std::min<std::uint32_t>(child.u32[1], 8U);
    for (std::size_t index = 0; index < time_count && source < child.f32.size();
            ++index, ++source)
        out.irc_envelope_times[index] = child.f32[source];
    for (std::size_t index = 0;
            index < level_count && source < child.f32.size(); ++index, ++source)
        out.irc_envelope_levels[index] = child.f32[source];
    if (child.s32.size() > 1)
        out.irc_filename_table_index = child.s32[1];
    return out;
}

std::optional<GroupEffectInfo> send_levels_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::send_levels)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::send_levels;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    const auto &fields = value.parsed_child->f32;
    for (std::size_t index = 0;
            index < out.send_levels.size() && index < fields.size(); ++index)
        out.send_levels[index] = fields[index];
    for (std::size_t index = 0; index < out.sidechain_send_levels.size() &&
                                index + out.send_levels.size() < fields.size();
            ++index)
        out.sidechain_send_levels[index] =
                fields[index + out.send_levels.size()];
    return out;
}

std::optional<GroupEffectInfo> solid_g_eq_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child ||
            value.parsed_child->kind != ParFxChildKind::solid_g_eq)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = GroupEffectType::solid_g_eq;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];

    const auto &child = *value.parsed_child;
    const auto field = [&](std::size_t index) -> std::optional<float> {
        return child.f32.size() > index
                       ? std::optional<float>{ child.f32[index] }
                       : std::nullopt;
    };
    const auto flag = [&](std::size_t index) -> std::optional<bool> {
        return child.boolean.size() > index
                       ? std::optional<bool>{ child.boolean[index] }
                       : std::nullopt;
    };
    // each tone band stores gain, frequency, then bell/Q
    out.solid_g_eq_low_gain = field(0);
    out.solid_g_eq_low_frequency = field(1);
    out.solid_g_eq_low_bell = flag(0);
    out.solid_g_eq_low_mid_gain = field(2);
    out.solid_g_eq_low_mid_frequency = field(3);
    out.solid_g_eq_low_mid_q = field(4);
    out.solid_g_eq_high_mid_gain = field(5);
    out.solid_g_eq_high_mid_frequency = field(6);
    out.solid_g_eq_high_mid_q = field(7);
    out.solid_g_eq_high_gain = field(8);
    out.solid_g_eq_high_frequency = field(9);
    out.solid_g_eq_high_bell = flag(1);
    out.solid_g_eq_high_pass_frequency = field(10);
    out.solid_g_eq_low_pass_frequency = field(11);
    // v0x11 stores LP-active before HP-active
    out.solid_g_eq_low_pass_active = flag(2);
    out.solid_g_eq_high_pass_active = flag(3);
    out.raw_parameters = child.f32;
    out.raw_boolean_parameters = child.boolean;
    return out;
}

std::optional<GroupEffectInfo> modern_effect(
        const ParFxPayload &value, std::size_t slot) {
    if (!value.parsed_child)
        return std::nullopt;

    using Child = ParFxChildKind;
    using Type = GroupEffectType;
    switch (value.parsed_child->kind) {
        case Child::filter:
            return filter_effect(value, slot);
        case Child::gainer:
            return gainer_effect(value, slot);
        case Child::inverter:
            return inverter_effect(value, slot);
        case Child::stereo_spread:
            return stereo_effect(value, slot);
        case Child::shaper:
            return shaper_effect(value, slot);
        case Child::lo_fi:
            return lo_fi_effect(value, slot);
        case Child::tape:
            return tape_effect(value, slot);
        case Child::transient_master:
            return transient_effect(value, slot);
        case Child::distortion:
            return distortion_effect(value, slot);
        case Child::compressor:
            return compressor_effect(value, slot);
        case Child::limiter:
            return limiter_effect(value, slot);
        case Child::hilbert_limiter:
            return transparent_limiter_effect(value, slot);
        case Child::dyx:
            return dyx_effect(value, slot);
        case Child::send_levels:
            return send_levels_effect(value, slot);
        case Child::irc:
            return irc_effect(value, slot);
        case Child::solid_g_eq:
            return solid_g_eq_effect(value, slot);
        default:
            break;
    }
    const auto generic_type = [](const Child kind) -> std::optional<Type> {
        switch (kind) {
            case Child::delay:
                return Type::delay;
            case Child::chorus:
                return Type::chorus;
            case Child::flanger:
                return Type::flanger;
            case Child::phaser:
                return Type::legacy_phaser;
            case Child::phasis:
                return Type::phasis;
            case Child::flair:
                return Type::flair;
            case Child::supercharger:
                return Type::supercharger;
            case Child::bass_invader:
                return Type::bass_invader;
            case Child::reverb:
                return Type::reverb;
            case Child::galois_reverb:
                return Type::galois_reverb;
            case Child::plate_reverb:
                return Type::plate_reverb;
            case Child::surround_panner:
                return Type::surround_panner;
            case Child::skreamer:
                return Type::skreamer;
            case Child::rotator:
                return Type::rotator;
            case Child::ring_modulator:
                return Type::ring_modulator;
            case Child::twang:
                return Type::twang;
            case Child::jump:
                return Type::jump;
            case Child::van51:
                return Type::van51;
            case Child::ac_box:
                return Type::ac_box;
            case Child::hot_solo:
                return Type::hot_solo;
            case Child::bass_pro:
                return Type::bass_pro;
            case Child::cat:
                return Type::cat;
            case Child::d_stortion:
                return Type::d_stortion;
            case Child::cry_wah:
                return Type::cry_wah;
            case Child::cabinet:
                return Type::cabinet;
            case Child::feedback_compressor:
                return Type::feedback_compressor;
            case Child::solid_g_eq:
                return Type::solid_g_eq;
            case Child::solid_bus_compressor:
                return Type::solid_bus_compressor;
            case Child::choral:
                return Type::choral;
            case Child::replika_delay:
                return Type::replika_delay;
            case Child::psyche_delay:
                return Type::psyche_delay;
            case Child::twin_delay:
                return Type::twin_delay;
            case Child::raum:
                return Type::raum;
            case Child::bite:
                return Type::bite;
            case Child::dirt:
                return Type::dirt;
            case Child::freak:
                return Type::freak;
            case Child::vibrato_chorus:
                return Type::vibrato_chorus;
            case Child::wow_flutter:
                return Type::wow_flutter;
            case Child::ep_preamps:
                return Type::ep_preamps;
            case Child::fuzz:
                return Type::fuzz;
            case Child::big_fuzz:
                return Type::big_fuzz;
            case Child::stereo_tune:
                return Type::stereo_tune;
            case Child::beat_masher:
                return Type::beat_masher;
            case Child::beat_slicer:
                return Type::beat_slicer;
            case Child::gater:
                return Type::gater;
            case Child::reverse_grain:
                return Type::reverse_grain;
            case Child::transpose_stretch:
                return Type::transpose_stretch;
            case Child::super_fast_100:
                return Type::super_fast_100;
            case Child::chainsaw:
                return Type::chainsaw;
            case Child::skreamer_dlx:
                return Type::skreamer_deluxe;
            case Child::kolor:
                return Type::kolor;
            case Child::reverb_delight:
                return Type::reverb_delight;
            default:
                return std::nullopt;
        }
    };
    const auto type = generic_type(value.parsed_child->kind);
    if (!type)
        return std::nullopt;
    GroupEffectInfo out;
    out.type = *type;
    out.slot_index = slot;
    if (value.internal_type && *value.internal_type >= 0)
        out.internal_type = static_cast<std::uint32_t>(*value.internal_type);
    if (value.private_bool.size() > 1)
        out.bypass = value.private_bool[1];
    if (!value.private_f32.empty())
        out.output_level = value.private_f32[0];
    if (value.private_f32.size() > 1)
        out.dry_output_level = value.private_f32[1];
    out.raw_parameters = value.parsed_child->f32;
    out.raw_integer_parameters = value.parsed_child->s32;
    out.raw_unsigned_parameters = value.parsed_child->u32;
    out.raw_byte_parameters = value.parsed_child->u8;
    out.raw_boolean_parameters = value.parsed_child->boolean;
    if (*type == GroupEffectType::surround_panner &&
            out.raw_integer_parameters.size() >= 5) {
        const auto output_count = std::max(0, out.raw_integer_parameters[0]);
        const auto input_count = std::max(0, out.raw_integer_parameters[1]);
        const auto total_count = static_cast<std::size_t>(output_count) +
                                 static_cast<std::size_t>(input_count);
        if (total_count <= out.raw_byte_parameters.size() &&
                total_count * 2U + 10U <= out.raw_parameters.size()) {
            std::size_t scalar = 0;
            std::size_t role = 0;
            const auto append_points = [&](auto &destination,
                                               std::int32_t count) {
                for (std::int32_t index = 0; index < count; ++index) {
                    destination.push_back(
                            SurroundPannerPoint{ out.raw_parameters[scalar],
                                    out.raw_parameters[scalar + 1],
                                    out.raw_byte_parameters[role] });
                    scalar += 2;
                    ++role;
                }
            };
            append_points(out.surround_output_points, output_count);
            append_points(out.surround_input_points, input_count);
            out.surround_lfe_crossover_frequency = out.raw_parameters[scalar++];
            out.surround_lfe_volume = out.raw_parameters[scalar++];
            out.surround_size = out.raw_parameters[scalar++];
            out.surround_divergence = out.raw_parameters[scalar++];
            out.surround_air_amount = out.raw_parameters[scalar++];
            out.surround_delay_amount = out.raw_parameters[scalar++];
            out.surround_volume_algorithm = out.raw_integer_parameters[2];
            out.surround_mouse_mode = out.raw_integer_parameters[3];
            if (!out.raw_boolean_parameters.empty())
                out.surround_use_speaker_delays = out.raw_boolean_parameters[0];
            if (out.raw_boolean_parameters.size() > 1)
                out.surround_use_air_absorption = out.raw_boolean_parameters[1];
            if (out.raw_boolean_parameters.size() > 2)
                out.surround_use_doppler_effect = out.raw_boolean_parameters[2];
            out.surround_offset_distance = out.raw_parameters[scalar++];
            out.surround_offset_azimuth = out.raw_parameters[scalar++];
            out.surround_offset_x = out.raw_parameters[scalar++];
            out.surround_offset_y = out.raw_parameters[scalar];
            out.surround_preset_speaker_setup = out.raw_integer_parameters[4];
        }
    }
    if (*type == GroupEffectType::delay && out.raw_parameters.size() >= 4) {
        out.delay_time = out.raw_parameters[0];
        out.delay_feedback = out.raw_parameters[1];
        out.delay_panning = out.raw_parameters[2];
        out.delay_damping = out.raw_parameters[3];
    }
    if (*type == GroupEffectType::skreamer && out.raw_parameters.size() >= 5) {
        out.skreamer_tone = out.raw_parameters[0];
        out.skreamer_drive = out.raw_parameters[1];
        out.skreamer_bass = out.raw_parameters[2];
        out.skreamer_bright = out.raw_parameters[3];
        out.skreamer_mix = out.raw_parameters[4];
    }
    if (*type == GroupEffectType::cabinet && out.raw_parameters.size() >= 4 &&
            !out.raw_integer_parameters.empty()) {
        out.cabinet_size = out.raw_parameters[0];
        out.cabinet_air = out.raw_parameters[1];
        out.cabinet_treble = out.raw_parameters[2];
        out.cabinet_bass = out.raw_parameters[3];
        out.cabinet_type = out.raw_integer_parameters[0];
    }
    if (*type == GroupEffectType::legacy_phaser &&
            out.raw_parameters.size() >= 5) {
        out.phaser_depth = out.raw_parameters[0];
        out.phaser_feedback = out.raw_parameters[1];
        out.phaser_speed = out.raw_parameters[2];
        out.phaser_phase = out.raw_parameters[3];
        out.phaser_note_value_speed = out.raw_parameters[4];
        out.phaser_note_value_enabled = out.raw_parameters[4] > 1.0e-9F;
    }
    if (*type == GroupEffectType::reverb && out.raw_parameters.size() >= 5) {
        out.reverb_pre_delay = out.raw_parameters[0];
        out.reverb_room_size = out.raw_parameters[1];
        out.reverb_stereo = out.raw_parameters[2];
        out.reverb_color = out.raw_parameters[3];
        out.reverb_filter = out.raw_parameters[4];
    }
    if (*type == GroupEffectType::solid_bus_compressor &&
            out.raw_parameters.size() >= 6) {
        out.solid_bus_threshold = out.raw_parameters[0];
        out.solid_bus_makeup = out.raw_parameters[1];
        out.solid_bus_attack = out.raw_parameters[2];
        out.solid_bus_release = out.raw_parameters[3];
        out.solid_bus_ratio = out.raw_parameters[4];
        out.solid_bus_mix = out.raw_parameters[5];
        if (!out.raw_boolean_parameters.empty())
            out.solid_bus_stereo_link = out.raw_boolean_parameters[0];
        if (out.raw_boolean_parameters.size() > 1)
            out.solid_bus_sidechain = out.raw_boolean_parameters[1];
    }
    if (*type == GroupEffectType::chorus && out.raw_parameters.size() >= 4) {
        out.chorus_depth = out.raw_parameters[0];
        out.chorus_speed = out.raw_parameters[1];
        out.chorus_phase = out.raw_parameters[2];
        out.chorus_note_value_speed = out.raw_parameters[3];
        out.chorus_note_value_enabled = out.raw_parameters[3] > 1.0e-9F;
    }
    if (*type == GroupEffectType::flanger && out.raw_parameters.size() >= 6) {
        // wire order differs from the object's member order
        out.flanger_depth = out.raw_parameters[0];
        out.flanger_feedback = out.raw_parameters[1];
        out.flanger_speed = out.raw_parameters[2];
        out.flanger_phase = out.raw_parameters[3];
        out.flanger_color = out.raw_parameters[4];
        out.flanger_note_value_speed = out.raw_parameters[5];
        if (out.raw_parameters.size() > 6)
            out.flanger_note_modifier = out.raw_parameters[6];
        if (out.raw_parameters.size() > 7)
            out.flanger_note_tempo = out.raw_parameters[7];
        if (!out.raw_boolean_parameters.empty())
            out.flanger_note_enabled = out.raw_boolean_parameters[0];
        else
            out.flanger_note_enabled = out.raw_parameters[5] > 1.0e-9F;
    }
    if (*type == GroupEffectType::rotator && out.raw_parameters.size() >= 6) {
        out.rotator_speed = out.raw_parameters[0];
        out.rotator_balance = out.raw_parameters[1];
        out.rotator_acceleration_high = out.raw_parameters[2];
        out.rotator_acceleration_low = out.raw_parameters[3];
        out.rotator_distance = out.raw_parameters[4];
        out.rotator_mix = out.raw_parameters[5];
    }
    if (*type == GroupEffectType::feedback_compressor &&
            out.raw_parameters.size() >= 7) {
        out.feedback_compressor_input = out.raw_parameters[0];
        out.feedback_compressor_makeup = out.raw_parameters[1];
        out.feedback_compressor_attack = out.raw_parameters[2];
        out.feedback_compressor_release = out.raw_parameters[3];
        out.feedback_compressor_ratio = out.raw_parameters[4];
        out.feedback_compressor_mix = out.raw_parameters[5];
        out.feedback_compressor_amount = out.raw_parameters[6];
        if (!out.raw_boolean_parameters.empty())
            out.feedback_compressor_high_quality =
                    out.raw_boolean_parameters[0];
        if (out.raw_boolean_parameters.size() > 1)
            out.feedback_compressor_stereo_link = out.raw_boolean_parameters[1];
        if (out.raw_boolean_parameters.size() > 2)
            out.feedback_compressor_sidechain = out.raw_boolean_parameters[2];
    }
    if (*type == GroupEffectType::psyche_delay &&
            out.raw_parameters.size() >= 9) {
        out.psyche_delay_time = out.raw_parameters[0];
        out.psyche_delay_feedback = out.raw_parameters[1];
        out.psyche_delay_detune = out.raw_parameters[2];
        out.psyche_delay_pitch = out.raw_parameters[3];
        out.psyche_delay_lr_offset = out.raw_parameters[4];
        out.psyche_delay_cross_feedback = out.raw_parameters[5];
        out.psyche_delay_note_value = out.raw_parameters[6];
        out.psyche_delay_note_modifier = out.raw_parameters[7];
        out.psyche_delay_note_tempo = out.raw_parameters[8];
        if (!out.raw_boolean_parameters.empty())
            out.psyche_delay_right_direction_toggle =
                    out.raw_boolean_parameters[0];
        if (out.raw_boolean_parameters.size() > 1)
            out.psyche_delay_right_detune_bypass =
                    out.raw_boolean_parameters[1];
        if (out.raw_boolean_parameters.size() > 2)
            out.psyche_delay_left_direction = out.raw_boolean_parameters[2];
        if (out.raw_boolean_parameters.size() > 3)
            out.psyche_delay_note_enabled = out.raw_boolean_parameters[3];
    }
    if (*type == GroupEffectType::choral && out.raw_parameters.size() >= 7 &&
            !out.raw_integer_parameters.empty()) {
        out.choral_amount = out.raw_parameters[0];
        out.choral_rate = out.raw_parameters[1];
        out.choral_delay = out.raw_parameters[2];
        out.choral_voices = out.raw_parameters[3];
        out.choral_width = out.raw_parameters[4];
        out.choral_feedback = out.raw_parameters[5];
        out.choral_mix = out.raw_parameters[6];
        if (!out.raw_boolean_parameters.empty())
            // the first bool controls polarity (ID7), the second routing (ID6)
            out.choral_feedback_polarity = out.raw_boolean_parameters[0];
        if (out.raw_boolean_parameters.size() > 1)
            out.choral_routing_switch = out.raw_boolean_parameters[1];
        out.choral_mode = out.raw_integer_parameters[0];
    }
    if (*type == GroupEffectType::replika_delay &&
            out.raw_parameters.size() >= 13 &&
            !out.raw_integer_parameters.empty()) {
        out.replika_style = out.raw_integer_parameters[0];
        out.replika_time = out.raw_parameters[0];
        out.replika_feedback = out.raw_parameters[1];
        out.replika_low_cut = out.raw_parameters[2];
        out.replika_high_cut = out.raw_parameters[3];
        out.replika_saturate = out.raw_parameters[4];
        out.replika_tape_age = out.raw_parameters[5];
        out.replika_flutter = out.raw_parameters[6];
        out.replika_quality = out.raw_parameters[7];
        out.replika_depth = out.raw_parameters[8];
        out.replika_rate = out.raw_parameters[9];
        out.replika_note_value = out.raw_parameters[10];
        out.replika_note_modifier = out.raw_parameters[11];
        out.replika_note_tempo = out.raw_parameters[12];
        if (!out.raw_boolean_parameters.empty())
            out.replika_style_modulation_enabled =
                    out.raw_boolean_parameters[0];
        if (out.raw_boolean_parameters.size() > 1)
            out.replika_tape_noise_enabled = out.raw_boolean_parameters[1];
        if (out.raw_boolean_parameters.size() > 2)
            out.replika_routing_enabled = out.raw_boolean_parameters[2];
        if (out.raw_boolean_parameters.size() > 3)
            out.replika_note_enabled = out.raw_boolean_parameters[3];
        if (out.raw_parameters.size() >= 17) {
            out.replika_bbd_type = out.raw_parameters[13];
            out.replika_diffusion_amount = out.raw_parameters[14];
            out.replika_diffusion_size = out.raw_parameters[15];
            out.replika_diffusion_mod = out.raw_parameters[16];
        }
        if (out.raw_boolean_parameters.size() > 4)
            out.replika_diffusion_enabled = out.raw_boolean_parameters[4];
        if (out.raw_parameters.size() >= 26) {
            out.replika_shuffle = out.raw_parameters[17];
            out.replika_feel = out.raw_parameters[18];
            out.replika_accent = out.raw_parameters[19];
            out.replika_pan = out.raw_parameters[20];
            out.replika_width = out.raw_parameters[21];
            out.replika_lr_offset = out.raw_parameters[22];
            out.replika_ducking_sensitivity = out.raw_parameters[23];
            out.replika_ducking_release = out.raw_parameters[24];
            out.replika_ducking_amount = out.raw_parameters[25];
        }
        if (out.raw_boolean_parameters.size() > 5)
            out.replika_routing_variant = out.raw_boolean_parameters[5];
    }
    return out;
}

void append_modern_effects(std::vector<GroupEffectInfo> &destination,
        const ParameterArrayPayload &source,
        std::optional<float> pre_a0_send_volume = std::nullopt) {
    for (std::size_t slot = 0; slot < source.entries.size(); ++slot) {
        const auto &entry = source.entries[slot];
        if (!entry.present || !entry.par_fx)
            continue;
        if (auto effect = modern_effect(*entry.par_fx, slot)) {
            // pre-a0 program sends fold in the program volume once on load,
            // don't touch the stored values. dry/inserts and live writes skip
            // this, and reverb's *3 comes later
            const auto &parameters = *entry.par_fx;
            if (pre_a0_send_volume && slot < 8 &&
                    parameters.internal_type.value_or(0) != 0 &&
                    parameters.private_s32.size() > 1 &&
                    parameters.private_s32[1] == -1 && effect->output_level)
                effect->output_level =
                        *pre_a0_send_volume * *effect->output_level;
            destination.push_back(std::move(*effect));
        }
    }
}

void resolve_irc_samples(std::span<GroupEffectInfo> effects,
        std::size_t document_sample_base, std::size_t table_sample_count,
        std::optional<std::uint32_t> special_base) {
    if (!special_base)
        return;
    for (auto &effect : effects) {
        if (effect.type != GroupEffectType::irc ||
                !effect.irc_filename_table_index ||
                *effect.irc_filename_table_index < 0)
            continue;
        const auto local =
                static_cast<std::size_t>(*special_base) +
                static_cast<std::size_t>(*effect.irc_filename_table_index);
        if (local < table_sample_count)
            effect.irc_sample_index = document_sample_base + local;
    }
}

DyxMorphGroupInfo dyx_morph_group(const K2MorphGroupSemantic &value) {
    DyxMorphGroupInfo out;
    out.id = value.id;
    out.name = value.name;
    out.smoothing = value.smoothing;
    out.left = value.left;
    out.right = value.right;
    out.tonal = value.tonal;
    out.root_key_shift = value.root_key_shift;
    return out;
}

DyxMorphMapInfo dyx_morph_map(const K2MorphMapSemantic &value) {
    DyxMorphMapInfo out;
    if (value.type)
        out.type = static_cast<DyxMorphMapType>(
                static_cast<std::uint8_t>(*value.type));
    out.id = value.id;
    out.name = value.name;
    out.morph_group_ids = value.morph_group_ids;
    return out;
}

DyxMorphGroupInfo dyx_morph_group(
        const DyxMorphGroupPayload &value, std::size_t program_index) {
    DyxMorphGroupInfo out;
    out.program_index = program_index;
    out.id = value.s32;
    out.name = value.name;
    out.smoothing = value.f32[0];
    out.left = value.f32[1];
    out.right = value.f32[2];
    out.tonal = value.flag;
    out.root_key_shift = value.s16;
    return out;
}

DyxMorphMapInfo dyx_morph_map(
        const DyxMorphMapPayload &value, std::size_t program_index) {
    DyxMorphMapInfo out;
    out.program_index = program_index;
    if (value.enum_1_to_2 >= 1 && value.enum_1_to_2 <= 2)
        out.type = static_cast<DyxMorphMapType>(value.enum_1_to_2);
    out.id = value.s32;
    out.name = value.name;
    for (std::size_t i = 0; i < value.values.size() && i < 64; ++i)
        out.morph_group_ids[i] = value.values[i];
    return out;
}

StartCriterion start_criterion(const K1StartCriteriaSemantic &value) {
    StartCriterion out;
    if (value.mode == "on_key")
        out.mode = StartMode::on_key;
    else if (value.mode == "on_controller")
        out.mode = StartMode::on_controller;
    else if (value.mode == "cycle_round_robin")
        out.mode = StartMode::cycle_round_robin;
    else if (value.mode == "cycle_random")
        out.mode = StartMode::cycle_random;
    else if (value.mode == "slice_trigger")
        out.mode = StartMode::slice_trigger;
    if (value.next_criteria == "and_not")
        out.next = NextStartCriterion::and_not;
    else if (value.next_criteria == "or")
        out.next = NextStartCriterion::or_else;
    out.minimum_key = value.key_min;
    out.maximum_key = value.key_max;
    out.controller = value.controller;
    out.minimum_controller_value = value.controller_min;
    out.maximum_controller_value = value.controller_max;
    out.slice_zone_index = value.slice_zone_index;
    out.slice_index = value.slice_index;
    out.cycle_class = value.cycle_class;
    out.sequencer_only = value.sequencer_only.value_or(false);
    return out;
}

StartCriterion start_criterion(const K2StartCriteriaSemantic &value) {
    StartCriterion out;
    if (value.mode)
        out.mode = static_cast<StartMode>(*value.mode);
    if (value.next_criteria)
        out.next = static_cast<NextStartCriterion>(*value.next_criteria);
    out.minimum_key = value.minimum_key;
    out.maximum_key = value.maximum_key;
    out.controller = value.controller;
    out.minimum_controller_value = value.minimum_cc;
    out.maximum_controller_value = value.maximum_cc;
    out.slice_zone_index = value.slice_zone_index;
    out.slice_index = value.slice_index;
    out.cycle_class = value.cycle_class;
    out.sequencer_only = value.sequencer_only.value_or(false);
    return out;
}

StartCriterion start_criterion(const StartCriteriaPayload &value) {
    StartCriterion out;
    out.mode = start_mode(value.enum_0_to_5);
    out.next = next_criterion(value.enum_0_to_2);
    out.minimum_key = value.s16[0];
    out.maximum_key = value.s16[1];
    out.controller = value.s16[2];
    out.minimum_controller_value = value.s16[3];
    out.maximum_controller_value = value.s16[4];
    // cycle comes before slice zone and slice index on the wire
    out.cycle_class = value.s32[0];
    out.slice_zone_index = value.s32[1];
    out.slice_index = value.s32[2];
    out.sequencer_only = value.flag;
    return out;
}

SourceGeneration source_generation(PatchGeneration value) {
    switch (value) {
        case PatchGeneration::k1:
            return SourceGeneration::k1;
        case PatchGeneration::k2:
            return SourceGeneration::k2;
        case PatchGeneration::k42:
            return SourceGeneration::k42;
        case PatchGeneration::k43_nisound:
            return SourceGeneration::modern;
        default:
            return SourceGeneration::unknown;
    }
}

std::string narrow(std::u16string_view value) {
    std::string result;
    auto append = [&](std::uint32_t cp) {
        if (cp <= 0x7f)
            result.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) {
            result.push_back(static_cast<char>(0xc0U | (cp >> 6U)));
            result.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
        } else if (cp <= 0xffff) {
            result.push_back(static_cast<char>(0xe0U | (cp >> 12U)));
            result.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
            result.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
        } else {
            result.push_back(static_cast<char>(0xf0U | (cp >> 18U)));
            result.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3fU)));
            result.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
            result.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
        }
    };
    for (std::size_t i = 0; i < value.size(); ++i) {
        std::uint32_t cp = value[i];
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < value.size() &&
                value[i + 1] >= 0xdc00 && value[i + 1] <= 0xdfff) {
            cp = 0x10000U + ((cp - 0xd800U) << 10U) + (value[++i] - 0xdc00U);
        } else if (cp >= 0xd800 && cp <= 0xdfff) {
            cp = 0xfffd;
        }
        append(cp);
    }
    return result;
}

std::vector<std::byte> read_file(const std::filesystem::path &path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream)
        throw std::runtime_error("cannot open file: " + path.string());
    const auto end = stream.tellg();
    if (end < 0)
        throw std::runtime_error(
                "cannot determine file size: " + path.string());
    std::vector<std::byte> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!bytes.empty() &&
            !stream.read(reinterpret_cast<char *>(bytes.data()), end))
        throw std::runtime_error("cannot read file: " + path.string());
    return bytes;
}

void classify_serialized_path(SerializedPathInfo &out) {
    if (!out.segments.empty()) {
        const auto first = out.segments.front().kind;
        if (first == 5 || first == 10 || first == 11) {
            out.kontakt_path_type = 4;
            out.resolution_base = PathResolutionBase::content_directory;
        } else if (first == 6) {
            out.kontakt_path_type = 5;
            out.resolution_base = PathResolutionBase::factory_directory;
        } else {
            out.kontakt_path_type = 1;
            for (const auto &segment : out.segments) {
                if (segment.kind == 8) {
                    out.kontakt_path_type = 2;
                    break;
                }
                if (segment.kind == 9) {
                    out.kontakt_path_type = 3;
                    break;
                }
            }
            out.resolution_base = PathResolutionBase::read_context;
        }
    } else {
        out.kontakt_path_type = 0;
        out.resolution_base = PathResolutionBase::empty;
    }
}

SerializedPathInfo serialized_path(const SerializedFileName &value) {
    SerializedPathInfo out;
    out.discarded_legacy_path = value.discarded_legacy_path;
    out.segments.reserve(value.segments.size());
    for (const auto &segment : value.segments) {
        out.segments.push_back({ segment.serialized_kind, segment.kind,
                static_cast<SerializedPathPayloadKind>(segment.payload_kind),
                segment.text, segment.value });
    }
    classify_serialized_path(out);
    return out;
}

std::optional<std::string> relative_serialized_path(
        const SerializedFileName &value) {
    std::filesystem::path result;
    for (const auto &segment : value.segments) {
        if (!segment.text || segment.text->empty())
            continue;
        result /= *segment.text;
    }
    if (result.empty())
        return std::nullopt;
    return result.generic_string();
}

ResolvedPathInfo resolve_path_impl(const SerializedPathInfo &serialized,
        const PathResolutionContext &context) {
    ResolvedPathInfo out;
    if (serialized.segments.empty())
        return out;

    for (std::size_t marker = 0; marker < serialized.segments.size();
            ++marker) {
        const auto marker_kind = serialized.segments[marker].kind;
        if (marker_kind == 8 || marker_kind == 9) {
            out.status = PathResolutionStatus::container_or_device;
            ContainerOrDevicePathInfo special;
            special.marker_kind = marker_kind;
            special.marker_index = marker;
            special.enclosing_path.segments.assign(serialized.segments.begin(),
                    serialized.segments.begin() +
                            static_cast<std::ptrdiff_t>(marker + 1));
            // keep the delimiter text, we still need it to find the outer
            // container
            special.enclosing_path.segments.back().kind = 4;
            classify_serialized_path(special.enclosing_path);
            special.inner_path.segments.assign(
                    serialized.segments.begin() +
                            static_cast<std::ptrdiff_t>(marker + 1),
                    serialized.segments.end());
            classify_serialized_path(special.inner_path);
            special.inner_path.resolution_base =
                    PathResolutionBase::container_inner;
            const auto enclosing =
                    resolve_path_impl(special.enclosing_path, context);
            special.enclosing_status = enclosing.status;
            special.resolved_enclosing_path = enclosing.path;
            out.path = enclosing.path;
            out.container_or_device = std::move(special);
            return out;
        }
    }

    const auto first_kind = serialized.segments.front().kind;
    std::optional<std::filesystem::path> base;
    std::size_t first_component = 0;
    bool flatten = false;
    if (first_kind == 5 || first_kind == 10 || first_kind == 11) {
        base = context.content_directory;
        first_component = 1;
    } else if (first_kind == 6) {
        base = context.factory_directory;
        first_component = 1;
    } else if (first_kind == 1) {
        // an empty kind-1 segment is a POSIX root; a named one is a platform
        // volume
        if (serialized.segments.front().text &&
                !serialized.segments.front().text->empty()) {
            out.status = PathResolutionStatus::platform_volume;
            PlatformVolumePathInfo volume;
            volume.volume_name = *serialized.segments.front().text;
            volume.path_within_volume.segments.assign(
                    serialized.segments.begin() + 1, serialized.segments.end());
            classify_serialized_path(volume.path_within_volume);
            volume.path_within_volume.resolution_base =
                    PathResolutionBase::platform_volume;
            out.platform_volume = std::move(volume);
            return out;
        }
        base = std::filesystem::path{ std::string(
                1, std::filesystem::path::preferred_separator) };
        first_component = 1;
        flatten = true;
    } else {
        base = context.read_context;
        flatten = true;
    }

    if (!base) {
        out.status = PathResolutionStatus::missing_context_root;
        return out;
    }
    if (first_component == 1 && (first_kind == 5 || first_kind == 6 ||
                                        first_kind == 10 || first_kind == 11)) {
        std::error_code error;
        const bool exists = std::filesystem::exists(*base, error);
        if (error || !exists) {
            out.status = PathResolutionStatus::unavailable_special_root;
            return out;
        }
    }

    auto path = *base;
    for (std::size_t i = first_component; i < serialized.segments.size(); ++i) {
        const auto &segment = serialized.segments[i];
        if (segment.kind == 3) {
            path /= "..";
            continue;
        }
        if (segment.kind != 2 && segment.kind != 4) {
            out.status = PathResolutionStatus::unsupported_segment;
            return out;
        }
        if (!segment.text || segment.text->empty() ||
                std::filesystem::path(*segment.text).has_parent_path()) {
            out.status = PathResolutionStatus::unsupported_segment;
            return out;
        }
        path /= *segment.text;
    }
    if (flatten)
        path = path.lexically_normal();
    out.status = PathResolutionStatus::resolved;
    out.path = std::move(path);
    return out;
}

KspPersistentVariable persistent_variable(std::string serialized) {
    KspPersistentVariable out;
    out.serialized_value = std::move(serialized);
    const auto split = out.serialized_value.find(' ');
    if (split != std::string::npos) {
        out.name = out.serialized_value.substr(0, split);
        out.value = out.serialized_value.substr(split + 1);
        const auto &name = *out.name;
        const auto &value = *out.value;
        try {
            if (!name.empty() && name.front() == '%') {
                std::vector<std::int64_t> values;
                std::istringstream stream(value);
                std::int64_t item{};
                while (stream >> item)
                    values.push_back(item);
                out.parsed_value = std::move(values);
            } else if (!name.empty() && name.front() == '?') {
                std::vector<double> values;
                std::istringstream stream(value);
                double item{};
                while (stream >> item)
                    values.push_back(item);
                out.parsed_value = std::move(values);
            } else if (!name.empty() && name.front() == '!') {
                std::vector<std::string> values;
                std::size_t begin = 0;
                while (begin < value.size()) {
                    const auto end = value.find('\n', begin);
                    auto item = value.substr(begin, end - begin);
                    if (!item.empty() && item.back() == '\r')
                        item.pop_back();
                    values.push_back(std::move(item));
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
                out.parsed_value = std::move(values);
            } else if (!name.empty() && name.front() == '@') {
                out.parsed_value = value;
            } else if (!name.empty() && name.front() == '~') {
                out.parsed_value = std::stod(value);
            } else if (!name.empty() && name.front() == '$') {
                out.parsed_value = static_cast<std::int64_t>(std::stoll(value));
            }
        } catch (const std::exception &) { out.parsed_value.reset(); }
    }
    return out;
}

std::size_t append_script(InstrumentInfo &instrument,
        const ParScriptPayload &script, bool multi_script = false) {
    KspScriptInfo out;
    out.multi_script = multi_script;
    out.source_text = script.source_text;
    out.description = script.description;
    out.text_file_name = script.text_file_name;
    out.source_editor_open = script.source_editor_open;
    out.touched_but_not_applied = script.touched_but_not_applied;
    out.bypass = script.bypass;
    out.legacy_password = script.version_0x50_password;
    out.password_hash = script.password_hash;
    for (const auto &value : script.persistent_variables) {
        if (value)
            out.persistent_variables.push_back(persistent_variable(*value));
    }
    const auto index = instrument.scripts.size();
    instrument.scripts.push_back(std::move(out));
    return index;
}

void append_k2_scripts(InstrumentInfo &instrument, const K2PatchData &data) {
    for (const auto &script : data.scripts) {
        KspScriptInfo out;
        out.source_text = script.source_text;
        out.description = script.description;
        out.text_file_name = script.text_file_name;
        out.source_editor_open = script.source_editor_open;
        out.touched_but_not_applied = script.touched_but_not_applied;
        out.bypass = script.bypass;
        out.legacy_password = script.serialized_password;
        for (const auto &value : script.persistent_variables) {
            auto item = persistent_variable(value.combined_value);
            item.name = value.serialized_name_suffix;
            item.value = value.serialized_value;
            out.persistent_variables.push_back(std::move(item));
        }
        instrument.scripts.push_back(std::move(out));
    }
}

std::optional<VoiceStealMode> voice_steal_mode(std::string_view mode) {
    if (mode == "kill_any")
        return VoiceStealMode::any;
    if (mode == "kill_oldest")
        return VoiceStealMode::oldest;
    if (mode == "kill_newest")
        return VoiceStealMode::newest;
    if (mode == "kill_highest")
        return VoiceStealMode::highest;
    if (mode == "kill_lowest")
        return VoiceStealMode::lowest;
    return std::nullopt;
}

VoiceLimitInfo voice_limit(const K1VoiceLimitSemantic &source,
        std::size_t program_index, std::uint8_t group_index) {
    VoiceLimitInfo out;
    out.program_index = program_index;
    out.group_index = group_index;
    out.name = source.name;
    out.maximum_voices = source.maximum_voices;
    if (source.mode)
        out.mode = voice_steal_mode(*source.mode);
    out.prefer_released = source.prefer_released;
    out.fade_time_ms = source.fade_time_ms;
    out.exclusion_group = source.exclusion_group;
    return out;
}

VoiceLimitInfo voice_limit(const K2VoiceLimitSemantic &source,
        std::size_t program_index, std::optional<std::uint8_t> group_index) {
    VoiceLimitInfo out;
    out.program_index = program_index;
    out.group_index = group_index;
    out.name = source.name;
    out.maximum_voices = source.maximum_voices;
    if (source.mode)
        out.mode = static_cast<VoiceStealMode>(*source.mode);
    out.prefer_released = source.prefer_released;
    out.fade_time_ms = source.fade_time_ms;
    out.exclusion_group = source.exclusion_group;
    return out;
}

VoiceLimitInfo voice_limit(const VoiceLimitPayload &source,
        std::size_t program_index, std::optional<std::uint8_t> group_index) {
    VoiceLimitInfo out;
    out.program_index = program_index;
    out.group_index = group_index;
    out.name = source.name;
    out.maximum_voices = source.s32[0];
    if (source.s16 >= 0 && source.s16 <= 4)
        out.mode = static_cast<VoiceStealMode>(source.s16);
    out.prefer_released = source.flag;
    out.fade_time_ms = source.s32[1];
    out.exclusion_group = source.s32[2];
    return out;
}

void append_k1(InstrumentInfo &out, const K1PatchData &data) {
    for (const auto &battery : data.battery_programs) {
        ProgramInfo program;
        program.name = battery.name;
        program.volume = battery.master_volume;
        out.programs.push_back(std::move(program));
        const auto program_index = out.programs.size() - 1;
        for (const auto &slot : battery.slots) {
            GroupInfo group;
            group.program_index = program_index;
            group.name = slot.label;
            group.volume = slot.volume;
            group.pan = slot.pan;
            group.tune = slot.pitch;
            if (slot.midi_channel) {
                const auto converted = *slot.midi_channel + 1;
                group.midi_channel =
                        converted >= 0 && converted < 17
                                ? static_cast<std::int16_t>(converted)
                                : 0;
            }
            const auto group_index = out.groups.size();
            out.groups.push_back(std::move(group));
            for (const auto &layer : slot.layers) {
                ZoneInfo zone;
                zone.group_index = group_index;
                if (slot.low_key)
                    zone.range.low_key =
                            static_cast<std::int16_t>(*slot.low_key);
                if (slot.high_key)
                    zone.range.high_key =
                            static_cast<std::int16_t>(*slot.high_key);
                if (slot.root_key)
                    zone.range.root_key =
                            static_cast<std::int16_t>(*slot.root_key);
                zone.range.low_velocity = layer.low_velocity;
                zone.range.high_velocity = layer.high_velocity;
                zone.sample_start = slot.sample_start;
                if (slot.volume && layer.volume)
                    zone.volume = *slot.volume * *layer.volume;
                if (slot.pan)
                    zone.pan = 1.0F - *slot.pan;
                zone.tune = slot.pitch;
                if (layer.path) {
                    SampleInfo sample;
                    sample.path = layer.path;
                    zone.sample_index = out.samples.size();
                    zone.sample_reference_status =
                            SampleReferenceStatus::resolved;
                    out.samples.push_back(std::move(sample));
                }
                out.zones.push_back(std::move(zone));
            }
        }
    }
    for (const auto &p : data.programs) {
        ProgramInfo value;
        value.name = legacy_attribute(p.attributes, "name");
        if (p.parameters) {
            value.midi_channel = p.parameters->midi_channel;
            value.volume = p.parameters->master_volume;
            value.pan = p.parameters->master_pan;
            value.tune = p.parameters->master_tune;
        }
        out.programs.push_back(std::move(value));
        const auto program_index = out.programs.size() - 1;
        for (std::size_t index = 0;
                index < p.voice_limits.size() && index < 128; ++index) {
            out.voice_limits.push_back(voice_limit(p.voice_limits[index],
                    program_index, static_cast<std::uint8_t>(index)));
        }
    }
    const auto group_base = out.groups.size();
    for (const auto &g : data.groups) {
        GroupInfo value;
        if (g.program_ordinal >= 0 &&
                static_cast<std::size_t>(g.program_ordinal) <
                        out.programs.size())
            value.program_index = static_cast<std::size_t>(g.program_ordinal);
        value.name = legacy_attribute(g.attributes, "name");
        if (g.parameters) {
            value.midi_channel = g.parameters->effective_midi_channel
                                         ? g.parameters->effective_midi_channel
                                         : g.parameters->midi_channel;
            value.volume = g.parameters->volume;
            value.pan = g.parameters->pan;
            value.tune = g.parameters->tune;
            value.output = g.parameters->output;
            value.key_tracking = g.parameters->key_tracking;
            value.reverse = g.parameters->reverse;
            value.release_trigger = g.parameters->release_trigger;
            value.release_trigger_note_monophonic =
                    g.parameters->release_trigger_note_monophonic;
            value.release_trigger_counter =
                    g.parameters->release_trigger_counter;
            value.muted = g.parameters->muted;
            value.solo = g.parameters->solo;
            value.voice_group = g.parameters->voice_group;
        }
        if (g.source_mode && g.source_mode->runtime_type &&
                *g.source_mode->runtime_type <= 9) {
            value.source_mode = SourceModeInfo{
                static_cast<PlaybackMode>(*g.source_mode->runtime_type),
                g.source_mode->speed, g.source_mode->note_value_speed,
                g.source_mode->note_value_speed.value_or(0.0F) > 1.0e-9F,
                std::nullopt, time_machine_source_info(*g.source_mode),
                std::nullopt
            };
            if (value.source_mode->mode == PlaybackMode::slice_machine)
                value.source_mode->slice_machine =
                        legacy_slice_source_info(*g.source_mode);
        }
        for (const auto &criterion : g.start_criteria)
            value.start_criteria.push_back(start_criterion(criterion));
        for (const auto &modulator : g.modulators) {
            if (modulator.modulator_class == K1ModulatorClass::internal &&
                    (modulator.lfo ||
                            (modulator.envelope &&
                                    (modulator.envelope->type ==
                                                    K1EnvelopeType::ahdsr ||
                                            modulator.envelope->type ==
                                                    K1EnvelopeType::fm7 ||
                                            modulator.envelope->type ==
                                                    K1EnvelopeType::dbd)))) {
                value.internal_modulators.push_back(
                        internal_modulator(modulator));
            } else if (modulator.modulator_class ==
                               K1ModulatorClass::external &&
                       modulator.external_parameters &&
                       modulator.external_parameters->source) {
                value.external_modulators.push_back(
                        external_modulator(modulator));
            }
        }
        for (const auto &effect : g.effects)
            if (effect.kind == K1EffectKind::filter)
                value.effects.push_back(filter_effect(effect));
            else if (effect.kind == K1EffectKind::inverter)
                value.effects.push_back(inverter_effect(effect));
            else if (effect.kind == K1EffectKind::stereo_spread)
                value.effects.push_back(stereo_effect(effect));
            else if (effect.kind == K1EffectKind::shaper)
                value.effects.push_back(shaper_effect(effect));
            else if (effect.kind == K1EffectKind::lo_fi)
                value.effects.push_back(lo_fi_effect(effect));
            else if (effect.kind == K1EffectKind::distortion)
                value.effects.push_back(distortion_effect(effect));
            else if (effect.kind == K1EffectKind::compressor)
                value.effects.push_back(compressor_effect(effect));
        out.groups.push_back(std::move(value));
    }
    for (const auto &z : data.zones) {
        ZoneInfo zone;
        zone.name = legacy_attribute(z.attributes, "name");
        const auto owner = std::find_if(data.groups.begin(), data.groups.end(),
                [&](const K1GroupSemantic &group) {
                    return group.program_ordinal == z.program_ordinal &&
                           group.group_ordinal == z.group_ordinal;
                });
        if (owner != data.groups.end()) {
            zone.group_index =
                    group_base +
                    static_cast<std::size_t>(owner - data.groups.begin());
        }
        if (z.parameters) {
            zone.range.low_key = z.parameters->low_key;
            zone.range.high_key = z.parameters->high_key;
            zone.range.low_velocity = z.parameters->low_velocity;
            zone.range.high_velocity = z.parameters->high_velocity;
            zone.range.root_key = z.parameters->root_key;
            zone.range.fade_low_key = z.parameters->fade_low_key;
            zone.range.fade_high_key = z.parameters->fade_high_key;
            zone.range.fade_low_velocity = z.parameters->fade_low_velocity;
            zone.range.fade_high_velocity = z.parameters->fade_high_velocity;
            zone.sample_start = z.parameters->sample_start;
            zone.sample_end = z.parameters->sample_end;
            zone.volume = z.parameters->volume;
            zone.pan = z.parameters->pan;
            zone.tune = z.parameters->tune;
            zone.reference_zone = z.parameters->reference_zone;
        }
        if (z.sample) {
            SampleInfo sample;
            sample.path = z.sample->path;
            zone.slices.reserve(z.sample->slices.size());
            for (const auto &slice : z.sample->slices) {
                zone.slices.push_back({ slice.start, slice.end, std::nullopt });
            }
            for (const auto &loop : z.loops) {
                SampleLoop item;
                item.start = loop.start;
                item.length = loop.length;
                item.count = loop.count;
                item.crossfade_length = loop.crossfade_length;
                item.tuning = loop.tuning;
                item.alternating = loop.alternating;
                switch (loop.mode) {
                    case K1LoopMode::oneshot:
                        item.mode = "oneshot";
                        break;
                    case K1LoopMode::until_end:
                        item.mode = "until_end";
                        break;
                    case K1LoopMode::until_release:
                        item.mode = "until_release";
                        break;
                }
                zone.loops.push_back(item);
                sample.loops.push_back(std::move(item));
            }
            zone.sample_index = out.samples.size();
            zone.sample_reference_status = SampleReferenceStatus::resolved;
            out.samples.push_back(std::move(sample));
        }
        out.zones.push_back(std::move(zone));
    }
}

void append_k2(InstrumentInfo &out, const K2PatchData &data) {
    for (const auto &group : data.morph_groups)
        out.dyx_morph_groups.push_back(dyx_morph_group(group));
    for (const auto &map : data.morph_maps)
        out.dyx_morph_maps.push_back(dyx_morph_map(map));
    for (const auto &p : data.programs) {
        ProgramInfo value;
        value.name = legacy_attribute(p.attributes, "name");
        if (p.parameters) {
            value.author = p.parameters->instrument_author;
            value.credits = p.parameters->instrument_credits;
            value.website = p.parameters->instrument_url;
            value.volume = p.parameters->volume;
            value.pan = p.parameters->pan;
            value.tune = p.parameters->tune;
            value.performance_view_script_index =
                    p.parameters->performance_view_script_index;
            value.dfd_channel_preload_size =
                    p.parameters->dfd_channel_preload_size;
            value.wallpaper_path = p.parameters->serialized_wallpaper_path;
        }
        out.programs.push_back(std::move(value));
    }
    std::vector<std::uint8_t> next_voice_group(out.programs.size());
    for (const auto &source : data.voice_limits) {
        if (source.program_ordinal < 0 ||
                static_cast<std::size_t>(source.program_ordinal) >=
                        out.programs.size())
            continue;
        const auto program_index =
                static_cast<std::size_t>(source.program_ordinal);
        std::optional<std::uint8_t> group_index;
        if (!source.global && next_voice_group[program_index] < 128)
            group_index = next_voice_group[program_index]++;
        out.voice_limits.push_back(
                voice_limit(source, program_index, group_index));
    }
    const auto group_base = out.groups.size();
    for (const auto &g : data.groups) {
        GroupInfo value;
        if (g.program_ordinal >= 0 &&
                static_cast<std::size_t>(g.program_ordinal) <
                        out.programs.size())
            value.program_index = static_cast<std::size_t>(g.program_ordinal);
        value.name = legacy_attribute(g.attributes, "name");
        if (g.parameters) {
            value.keyboard_color = g.parameters->battery_cell_color;
            value.midi_channel = g.parameters->midi_channel;
            value.volume = g.parameters->volume;
            value.pan = g.parameters->pan;
            value.tune = g.parameters->tune;
            value.key_tracking = g.parameters->key_tracking;
            value.reverse = g.parameters->reverse;
            if (g.parameters->interpolation_quality) {
                value.interpolation_quality = static_cast<InterpolationQuality>(
                        *g.parameters->interpolation_quality);
            }
            value.release_trigger = g.parameters->release_trigger;
            value.release_trigger_note_monophonic =
                    g.parameters->release_trigger_note_monophonic;
            value.release_trigger_counter =
                    g.parameters->release_trigger_counter;
            value.muted = g.parameters->muted;
            value.solo = g.parameters->soloed;
            value.purged = g.parameters->purged;
            value.voice_group = g.parameters->voice_group;
        }
        const auto source_mode = std::find_if(data.source_modes.begin(),
                data.source_modes.end(),
                [&](const K2SourceModeSemantic &source) {
                    return source.program_ordinal == g.program_ordinal &&
                           source.group_ordinal == g.group_ordinal;
                });
        if (source_mode != data.source_modes.end() && source_mode->mode) {
            value.source_mode = SourceModeInfo{ static_cast<PlaybackMode>(
                                                        *source_mode->mode),
                source_mode->speed, source_mode->note_value_speed,
                source_mode->note_value_speed_enabled.value_or(
                        source_mode->note_value_speed.value_or(0.0F) > 1.0e-9F),
                std::nullopt, time_machine_source_info(*source_mode),
                std::nullopt };
            if (value.source_mode->mode == PlaybackMode::slice_machine)
                value.source_mode->slice_machine =
                        legacy_slice_source_info(*source_mode);
            value.source_mode->zone_locked_speed =
                    source_mode->zone_locked_speed;
        }
        for (const auto &criterion : data.start_criteria) {
            if (criterion.program_ordinal == g.program_ordinal &&
                    criterion.group_ordinal == g.group_ordinal) {
                value.start_criteria.push_back(start_criterion(criterion));
            }
        }
        for (const auto &modulator : data.internal_modulators) {
            if (modulator.program_ordinal == g.program_ordinal &&
                    modulator.group_ordinal == g.group_ordinal &&
                    (modulator.lfo ||
                            (modulator.envelope &&
                                    (modulator.envelope->type ==
                                                    K2EnvelopeType::ahdsr ||
                                            modulator.envelope->type ==
                                                    K2EnvelopeType::fm7 ||
                                            modulator.envelope->type ==
                                                    K2EnvelopeType::dbd)))) {
                value.internal_modulators.push_back(
                        internal_modulator(modulator));
            }
        }
        for (const auto &modulator : data.external_modulators) {
            if (modulator.program_ordinal == g.program_ordinal &&
                    modulator.group_ordinal == g.group_ordinal &&
                    modulator.source) {
                value.external_modulators.push_back(
                        external_modulator(modulator));
            }
        }
        for (const auto &effect : data.effects) {
            if (effect.program_ordinal != g.program_ordinal ||
                    effect.group_ordinal != g.group_ordinal)
                continue;
            if (effect.kind == K2EffectKind::filter)
                value.effects.push_back(filter_effect(effect));
            else if (effect.kind == K2EffectKind::gainer)
                value.effects.push_back(gainer_effect(effect));
            else if (effect.kind == K2EffectKind::inverter)
                value.effects.push_back(inverter_effect(effect));
            else if (effect.kind == K2EffectKind::stereo_spread)
                value.effects.push_back(stereo_effect(effect));
            else if (effect.kind == K2EffectKind::shaper)
                value.effects.push_back(shaper_effect(effect));
            else if (effect.kind == K2EffectKind::lo_fi)
                value.effects.push_back(lo_fi_effect(effect));
            else if (effect.kind == K2EffectKind::distortion)
                value.effects.push_back(distortion_effect(effect));
            else if (effect.kind == K2EffectKind::compressor)
                value.effects.push_back(compressor_effect(effect));
            else if (effect.kind == K2EffectKind::limiter)
                value.effects.push_back(limiter_effect(effect));
            else if (effect.kind == K2EffectKind::dyx)
                value.effects.push_back(dyx_effect(effect));
            else if (effect.kind == K2EffectKind::irc)
                value.effects.push_back(irc_effect(effect));
            else if (effect.kind == K2EffectKind::send_levels)
                value.effects.push_back(send_levels_effect(effect));
            else if (effect.kind == K2EffectKind::surround_panner)
                value.effects.push_back(surround_panner_effect(effect));
        }
        out.groups.push_back(std::move(value));
    }
    for (const auto &z : data.zones) {
        if (z.removed_by_close_due_to_absent_serialized_sample)
            continue;
        ZoneInfo zone;
        zone.name = legacy_attribute(z.attributes, "name");
        const auto owner = std::find_if(data.groups.begin(), data.groups.end(),
                [&](const K2GroupSemantic &group) {
                    return group.program_ordinal == z.program_ordinal &&
                           group.group_ordinal == z.group_ordinal;
                });
        if (owner != data.groups.end()) {
            zone.group_index =
                    group_base +
                    static_cast<std::size_t>(owner - data.groups.begin());
        }
        if (z.parameters) {
            zone.range.low_key = z.parameters->low_key;
            zone.range.high_key = z.parameters->high_key;
            zone.range.low_velocity = z.parameters->low_velocity;
            zone.range.high_velocity = z.parameters->high_velocity;
            zone.range.root_key = z.parameters->root_key;
            zone.dyx_morph_group_id = z.parameters->morph_group_index;
            zone.range.fade_low_key = z.parameters->fade_low_key;
            zone.range.fade_high_key = z.parameters->fade_high_key;
            zone.range.fade_low_velocity = z.parameters->fade_low_velocity;
            zone.range.fade_high_velocity = z.parameters->fade_high_velocity;
            zone.sample_start = z.parameters->sample_start;
            zone.sample_end = z.parameters->sample_end;
            zone.sample_start_modulation_range =
                    z.parameters->sample_start_modulation_range;
            zone.volume = z.parameters->volume;
            zone.pan = z.parameters->pan;
            zone.tune = z.parameters->tune;
            zone.grid_unit_numerator = z.parameters->fixed_unit_numerator;
            zone.grid_unit_denominator = z.parameters->fixed_unit_denominator;
            zone.grid_tempo_scaling = z.parameters->tempo_scaling;
            zone.selected = z.parameters->selected;
            zone.reference_zone = z.parameters->reference_zone;
        }
        if (z.sample) {
            // the legacy flag sets both saved and live purge, false if missing
            zone.sample_start_modulation_purged =
                    z.sample->purged.value_or(false);
            if (z.sample->sample_data_type)
                zone.sample_bit_depth =
                        sample_bit_depth(*z.sample->sample_data_type);
            SampleInfo sample;
            sample.path = z.sample->path;
            sample.preferred_name = z.sample->preferred_base_name;
            sample.sample_rate = z.sample->sample_rate;
            sample.channel_count = z.sample->channel_count;
            sample.frame_count = z.sample->frame_count;
            sample.root_note = z.sample->root_note;
            sample.tuning = z.sample->tuning;
            std::vector<const K2SliceSemantic *> slices;
            for (const auto &candidate : data.slices) {
                if (candidate.zone_ordinal == z.zone_ordinal &&
                        candidate.position)
                    slices.push_back(&candidate);
            }
            std::ranges::sort(slices, {}, [](const K2SliceSemantic *slice) {
                return slice->index.value_or(
                        std::numeric_limits<std::int32_t>::max());
            });
            zone.slices.reserve(slices.size());
            for (std::size_t index = 0; index < slices.size(); ++index) {
                const auto start = *slices[index]->position;
                const auto end =
                        index + 1 < slices.size()
                                ? *slices[index + 1]->position
                                : z.sample->frame_count.value_or(start);
                zone.slices.push_back({ start, std::max(start, end),
                        slices[index]->flags
                                ? std::optional<std::uint32_t>{ static_cast<
                                          std::uint32_t>(
                                          *slices[index]->flags) }
                                : std::nullopt });
            }
            for (const auto &loop : z.loops) {
                SampleLoop item;
                item.start = loop.start;
                item.length = loop.length;
                item.count = loop.count;
                item.crossfade_length = loop.crossfade_length;
                item.tuning = loop.tuning;
                item.alternating = loop.alternating;
                item.mode = loop.mode;
                zone.loops.push_back(item);
                sample.loops.push_back(std::move(item));
            }
            zone.sample_index = out.samples.size();
            zone.sample_reference_status = SampleReferenceStatus::resolved;
            out.samples.push_back(std::move(sample));
        }
        out.zones.push_back(std::move(zone));
    }
    append_k2_scripts(out, data);
}

void append_modern_program(InstrumentInfo &out, const ProgramPayload &program,
        std::size_t sample_base, std::size_t sample_count,
        std::optional<std::uint32_t> sample_filename_base,
        std::optional<std::uint32_t> special_filename_base,
        const FileTable *file_table) {
    ProgramInfo info;
    info.name = program.public_payload.name;
    info.dfd_channel_preload_size = program.public_payload.s32;
    // each key-select range starts from this signed key
    info.initial_key_select_note = program.public_payload.s16;
    info.volume = program.public_payload.f32[0];
    info.pan = program.public_payload.f32[1];
    // modern tuning is already a linear ratio
    info.tune = program.public_payload.f32[2];
    info.performance_view_script_index = program.private_payload.s16;
    // older versions keep the resource path in private parameters, both use
    // absolute file table indices without the sample/special bases
    const auto resource_index =
            program.public_payload.content_file_table_index
                    ? program.public_payload.content_file_table_index
                    : program.private_payload.legacy_filename_table_index;
    if (file_table && resource_index && *resource_index >= 0 &&
            static_cast<std::size_t>(*resource_index) <
                    file_table->files.size()) {
        const auto &file =
                file_table->files[static_cast<std::size_t>(*resource_index)];
        info.resource_container_path_mode = file.field_00;
        info.resource_container_library_id =
                static_cast<std::uint32_t>(file.field_04);
        const auto &path = file.selected_path;
        if (!path.segments.empty())
            info.resource_container_path = serialized_path(path);
    }
    // only fall back if the modern field is missing, an explicit empty one has
    // to stay empty
    const auto wallpaper_index =
            program.public_payload.trailing_special_filename_indices.empty()
                    ? program.private_payload
                              .legacy_special_filename_table_index
                    : std::optional<std::int32_t>{ program.public_payload
                                  .trailing_special_filename_indices.back() };
    if (file_table && special_filename_base && wallpaper_index &&
            *wallpaper_index >= 0) {
        const auto index = static_cast<std::uint64_t>(*special_filename_base) +
                           static_cast<std::uint32_t>(*wallpaper_index);
        if (index < file_table->files.size())
            info.wallpaper_path = relative_serialized_path(
                    file_table->files[static_cast<std::size_t>(index)]
                            .selected_path);
    }
    for (const auto &script : program.private_payload.legacy_scripts)
        info.script_indices.push_back(append_script(out, script));
    for (const auto &script : program.children.scripts)
        info.script_indices.push_back(append_script(out, script));
    out.programs.push_back(std::move(info));
    const auto program_index = out.programs.size() - 1;
    out.voice_limits.push_back(
            voice_limit(program.children.voice_groups.global_limit,
                    program_index, std::nullopt));
    // mask bit 0 is local slot 1, slot 0 is the global limit. fill all 128
    // locals first, slots missing from the mask still limit to 1 voice with a
    // 10ms steal fade
    const auto local_limit_base = out.voice_limits.size();
    for (std::uint16_t selector = 1; selector <= 128; ++selector) {
        out.voice_limits.push_back(
                { program_index, static_cast<std::uint8_t>(selector), "", 1,
                        VoiceStealMode::oldest, true, 10, -1 });
    }
    for (const auto &source : program.children.voice_groups.active_limits) {
        out.voice_limits.at(local_limit_base + source.index) =
                voice_limit(source.value, program_index,
                        static_cast<std::uint8_t>(source.index + 1));
    }
    auto &program_info = out.programs.back();
    if (!program.children.effect_arrays.empty())
        append_modern_effects(
                program_info.insert_effects, program.children.effect_arrays[0]);
    if (program.children.effect_arrays.size() > 1)
        append_modern_effects(program_info.send_effects,
                program.children.effect_arrays[1],
                program.serializable.version < 0xa0 ? program_info.volume
                                                    : std::nullopt);
    if (program.children.effect_arrays.size() > 2)
        append_modern_effects(
                program_info.main_effects, program.children.effect_arrays[2]);
    for (const auto &source_bus : program.children.insert_buses) {
        InsertBusInfo bus;
        bus.name = source_bus.name;
        bus.level = source_bus.level_pan[0];
        bus.pan = source_bus.level_pan[1];
        bus.destination = source_bus.version_0x11_s32;
        if (!source_bus.version_0x12_flags.empty())
            bus.phase_invert = source_bus.version_0x12_flags[0];
        if (source_bus.version_0x12_flags.size() > 1)
            bus.swap_stereo = source_bus.version_0x12_flags[1];
        append_modern_effects(bus.effects, source_bus.effect_array);
        program_info.insert_buses.push_back(std::move(bus));
    }
    resolve_irc_samples(program_info.insert_effects, sample_base, sample_count,
            special_filename_base);
    resolve_irc_samples(program_info.send_effects, sample_base, sample_count,
            special_filename_base);
    resolve_irc_samples(program_info.main_effects, sample_base, sample_count,
            special_filename_base);
    for (auto &bus : program_info.insert_buses)
        resolve_irc_samples(
                bus.effects, sample_base, sample_count, special_filename_base);
    for (const auto &group : program.private_payload.morph_groups)
        out.dyx_morph_groups.push_back(dyx_morph_group(group, program_index));
    for (const auto &map : program.private_payload.morph_maps)
        out.dyx_morph_maps.push_back(dyx_morph_map(map, program_index));
    const auto group_base = out.groups.size();
    for (const auto &group : program.children.groups.groups) {
        GroupInfo item;
        item.name = group.public_payload.name;
        item.program_index = program_index;
        item.purged = group.private_payload.flag_after_parameter_array;
        // output is in the private parameters, the two public S32s are voice
        // group and insert count
        item.output = group.private_payload.version_0x91_s32;
        item.phase_invert = group.private_payload.version_0x92_flags[0];
        item.voice_group = group.public_payload.s32_after_s16[0];
        item.pre_amplifier_insert_count = group.public_payload.s32_after_s16[1];
        item.volume = group.public_payload.f32[0];
        item.pan = group.public_payload.f32[1];
        // only older tagged presets need exp2; this tuning is already linear
        item.tune = group.public_payload.f32[2];
        item.key_tracking = group.public_payload.flags[0];
        item.reverse = group.public_payload.flags[1];
        item.release_trigger = group.public_payload.flags[2];
        item.release_trigger_note_monophonic = group.public_payload.flags[3];
        item.release_trigger_counter = group.public_payload.s32_before_s16;
        item.midi_channel = group.public_payload.s16;
        item.muted = group.public_payload.trailing_flags[0];
        item.solo = group.public_payload.trailing_flags[1];
        if (group.private_payload.source_mode.prefix.internal_mode >= 0 &&
                group.private_payload.source_mode.prefix.internal_mode <= 9) {
            item.source_mode = SourceModeInfo{
                static_cast<PlaybackMode>(
                        group.private_payload.source_mode.prefix.internal_mode),
                group.private_payload.source_mode.prefix.field_after_mode,
                group.private_payload.source_mode.prefix.versioned_f32[0],
                group.private_payload.source_mode.prefix.versioned_f32[0] >
                        1.0e-9F,
                wavetable_source_info(group.private_payload.source_mode),
                time_machine_source_info(group.private_payload.source_mode),
                time_machine_pro_source_info(group.private_payload.source_mode),
                group.private_payload.source_mode.prefix.serializable.version <
                                0x102 ||
                        group.private_payload.source_mode.prefix
                                .version_0x102_flag
            };
            if (item.source_mode->mode == PlaybackMode::slice_machine)
                item.source_mode->slice_machine = modern_slice_source_info(
                        group.private_payload.source_mode);
            item.source_mode->zone_locked_speed =
                    group.private_payload.source_mode.prefix.second_flag;
        }
        for (const auto &[index, criterion] : group.children.start_criteria) {
            (void)index;
            item.start_criteria.push_back(start_criterion(criterion));
        }
        for (std::size_t source_slot = 0;
                source_slot < group.children.parameter_arrays[0].entries.size();
                ++source_slot) {
            const auto &entry =
                    group.children.parameter_arrays[0].entries[source_slot];
            if (entry.present && entry.internal_modulator &&
                    ((entry.internal_modulator->modulator_type == 1 &&
                             entry.internal_modulator->lfo) ||
                            (entry.internal_modulator->modulator_type == 2 &&
                                    entry.internal_modulator->envelope &&
                                    (entry.internal_modulator->envelope
                                                            ->envelope_type ==
                                                    0 ||
                                            entry.internal_modulator->envelope
                                                            ->envelope_type ==
                                                    1 ||
                                            entry.internal_modulator->envelope
                                                            ->envelope_type ==
                                                    2)))) {
                item.internal_modulators.push_back(
                        internal_modulator(*entry.internal_modulator));
                item.internal_modulators.back().source_slot =
                        static_cast<std::int32_t>(source_slot);
            }
        }
        for (std::size_t source_slot = 0;
                source_slot < group.children.parameter_arrays[1].entries.size();
                ++source_slot) {
            const auto &entry =
                    group.children.parameter_arrays[1].entries[source_slot];
            if (entry.present && entry.external_modulator &&
                    (entry.external_modulator->source ||
                            entry.external_modulator->mode == 2)) {
                item.external_modulators.push_back(
                        external_modulator(*entry.external_modulator));
                // external slots are 16..79 in the file, compacting the vector
                // must NOT shift them
                if (source_slot < 64)
                    item.external_modulators.back().source_slot =
                            16 + static_cast<std::int32_t>(source_slot);
            }
        }
        for (std::size_t slot = 0;
                slot < group.private_payload.parameter_array.entries.size();
                ++slot) {
            const auto &entry =
                    group.private_payload.parameter_array.entries[slot];
            if (!entry.present || !entry.par_fx)
                continue;
            if (auto effect = modern_effect(*entry.par_fx, slot))
                item.effects.push_back(std::move(*effect));
        }
        resolve_irc_samples(
                item.effects, sample_base, sample_count, special_filename_base);
        out.groups.push_back(std::move(item));
    }
    for (const auto &entry : program.children.zones.zones) {
        ZoneInfo zone;
        if (entry.factory_selector >= 0 &&
                static_cast<std::size_t>(entry.factory_selector) <
                        program.children.groups.groups.size()) {
            zone.group_index = group_base +
                               static_cast<std::size_t>(entry.factory_selector);
        }
        const auto &public_data = entry.zone.public_payload;
        const auto &private_data = entry.zone.private_payload;
        // modern files only restore the saved purge state, a saved true alone
        // doesn't purge the live one
        if (!private_data.trailing_flag)
            zone.sample_start_modulation_purged = false;
        if (private_data.final_s32 >= 0)
            zone.ksp_id = private_data.final_s32;
        zone.dyx_morph_group_id = private_data.leading_s32;
        zone.grid_unit_numerator = private_data.u8[2];
        zone.grid_unit_denominator = private_data.u8[3];
        zone.grid_tempo_scaling = private_data.f32[0];
        zone.selected = private_data.second_flag;
        zone.reference_zone = private_data.first_flag;
        zone.range.low_key = public_data.low_key;
        zone.range.high_key = public_data.high_key;
        zone.range.low_velocity = public_data.low_velocity;
        zone.range.high_velocity = public_data.high_velocity;
        zone.range.root_key = public_data.root_key;
        zone.range.fade_low_key = public_data.fade_low_key;
        zone.range.fade_high_key = public_data.fade_high_key;
        zone.range.fade_low_velocity = public_data.fade_low_velocity;
        zone.range.fade_high_velocity = public_data.fade_high_velocity;
        zone.sample_start = public_data.sample_start;
        zone.sample_end = public_data.sample_end;
        zone.sample_start_modulation_range =
                public_data.sample_start_modulation_range;
        if (public_data.sample_settings)
            zone.sample_bit_depth = sample_bit_depth(static_cast<std::uint32_t>(
                    public_data.sample_settings->leading_s32[0]));
        zone.volume = public_data.volume;
        zone.pan = public_data.pan;
        zone.tune = public_data.tune;

        // points are {sample position, level, curve}
        for (const auto &indexed : private_data.level_envs) {
            const auto &source = indexed.value;
            if (!source.has_data)
                continue;
            ZoneEnvelopeInfo envelope;
            envelope.index = indexed.index;
            envelope.external_modulator_index = source.s16;
            envelope.loop_start = source.s32[0];
            envelope.loop_length = source.s32[1];
            envelope.loop_active = source.flags[0];
            envelope.speed_lock = source.flags[1];
            envelope.target_xml_name = source.target_xml_name;
            envelope.target_index = source.s8;
            for (const auto &point : source.segments)
                envelope.points.push_back(
                        { point.s32, point.f32[0], point.f32[1] });
            zone.envelopes.push_back(std::move(envelope));
        }
        for (const auto &indexed_loop : entry.zone.children.loops) {
            const auto &loop = indexed_loop.value;
            SampleLoop item;
            item.start = loop.start;
            item.length = loop.length;
            item.count = loop.count;
            item.crossfade_length = loop.crossfade_length;
            item.tuning = loop.tuning;
            item.alternating = loop.alternating;
            switch (loop.mode) {
                case LoopPayload::Mode::none:
                    item.mode = "none";
                    break;
                case LoopPayload::Mode::until_end:
                    item.mode = "until_end";
                    break;
                case LoopPayload::Mode::until_release:
                    item.mode = "until_release";
                    break;
                case LoopPayload::Mode::oneshot:
                    item.mode = "oneshot";
                    break;
            }
            zone.loops.push_back(std::move(item));
        }
        if (const auto &slices = entry.zone.children.slices;
                slices && slices->slices.size() > 1) {
            zone.slices.reserve(slices->slices.size() - 1);
            for (std::size_t index = 0; index + 1 < slices->slices.size();
                    ++index) {
                zone.slices.push_back({ slices->slices[index].position,
                        slices->slices[index + 1].position,
                        slices->slices[index].value,
                        slices->slices[index].position_f32,
                        slices->slices[index + 1].position_f32 });
            }
        }
        if (public_data.sample_file_table_index) {
            zone.sample_file_table_index = public_data.sample_file_table_index;
            if (*public_data.sample_file_table_index < 0) {
                zone.sample_reference_status = SampleReferenceStatus::empty;
            } else if (const auto local =
                               static_cast<std::size_t>(
                                       sample_filename_base.value_or(0)) +
                               static_cast<std::size_t>(
                                       *public_data.sample_file_table_index);
                    local < sample_count) {
                // version-2 sample indices start after the path-only file run
                zone.sample_index = sample_base + local;
                zone.sample_reference_status = SampleReferenceStatus::resolved;
            } else {
                zone.sample_reference_status =
                        SampleReferenceStatus::out_of_range;
            }
        }
        out.zones.push_back(std::move(zone));
    }
}

void append_modern(InstrumentInfo &out, const ModernPatchPayload &patch) {
    const auto sample_base = out.samples.size();
    if (patch.file_table) {
        for (std::size_t i = 0; i < patch.file_table->files.size(); ++i) {
            const auto &file = patch.file_table->files[i];
            SampleInfo sample;
            sample.serialized_path = serialized_path(file.selected_path);
            sample.secondary_serialized_path =
                    serialized_path(file.secondary_path);
            sample.file_table_index = static_cast<std::int32_t>(i);
            sample.timestamp = file.timestamp;
            sample.content_file_path_mode = file.field_00;
            sample.content_file_library_id =
                    static_cast<std::uint32_t>(file.field_04);
            out.samples.push_back(std::move(sample));
        }
    }
    const auto sample_count = out.samples.size() - sample_base;
    const auto special_filename_base =
            patch.file_table ? patch.file_table->special_filename_base
                             : std::nullopt;
    const auto sample_filename_base =
            patch.file_table ? patch.file_table->sample_filename_base
                             : std::nullopt;
    if (patch.program)
        append_modern_program(out, *patch.program, sample_base, sample_count,
                sample_filename_base, special_filename_base,
                patch.file_table ? &*patch.file_table : nullptr);
    if (patch.program_container) {
        if (!patch.program_container->public_payload.name.empty())
            out.name = patch.program_container->public_payload.name;
        for (const auto &entry : patch.program_container->children.programs)
            append_modern_program(out, entry.program, sample_base, sample_count,
                    sample_filename_base, special_filename_base,
                    patch.file_table ? &*patch.file_table : nullptr);
    }
    if (patch.bank && patch.bank->slot_list) {
        if (!patch.bank->public_payload.name.empty())
            out.name = patch.bank->public_payload.name;
        for (const auto &slot : patch.bank->slot_list->entries)
            for (const auto &entry : slot.program_container.children.programs)
                append_modern_program(out, entry.program, sample_base,
                        sample_count, sample_filename_base,
                        special_filename_base,
                        patch.file_table ? &*patch.file_table : nullptr);
    }
    if (patch.bank)
        for (const auto &script : patch.bank->private_payload.legacy_scripts)
            append_script(out, script, true);
    if (patch.preset && patch.preset->script)
        append_script(out, *patch.preset->script);
}

void append_nkc_node(Model &model, const NkcNode &node) {
    if (!node.name.empty()) {
        model.resources.push_back({ narrow(node.name), node.entry_type, 0, 0 });
    }
    for (const auto &child : node.children)
        append_nkc_node(model, child);
}

} // namespace

InstrumentSnapshotInfo parse_instrument_snapshot_file(
        const std::filesystem::path &path) {
    return parse_instrument_snapshot_file(
            path, bundled_encryption_private_key());
}

bool requires_encryption_private_key(const std::filesystem::path &path) {
    const auto bytes = read_file(path);
    const auto generation = detect_patch_generation(bytes);
    if (generation == PatchGeneration::k42)
        return k42_legacy_otp_encrypted(bytes);
    if (generation == PatchGeneration::k2)
        return k2_legacy_otp_encrypted(bytes);
    const auto visit = [&](auto &&self, std::span<const std::byte> data,
                               unsigned depth) -> bool {
        if (depth > 64)
            throw std::runtime_error("protection nesting exceeds limit");
        const auto document = parse(data);
        for (const auto &item : document.protected_items) {
            if (item.kind == ProtectedItemKind::encryption_item &&
                    item.xor_enabled.value_or(false))
                return true;
            const auto decoded = decode_protected_item(data, item);
            if (self(self, decoded, depth + 1))
                return true;
        }
        return false;
    };
    return visit(visit, bytes, 0);
}

InstrumentSnapshotInfo parse_instrument_snapshot_file(
        const std::filesystem::path &path,
        std::span<const std::byte> private_key) {
    const auto bytes = read_file(path);
    const auto outer = parse(bytes);
    const auto libraries = discover_local_libraries(path);
    InstrumentSnapshotInfo result;
    result.name = outer.metadata.name;
    bool found = false;
    std::function<void(std::span<const std::byte>, const Document &,
            const std::vector<std::byte> &, unsigned)>
            visit;
    visit = [&](std::span<const std::byte> data, const Document &document,
                    const std::vector<std::byte> &inherited_key,
                    unsigned depth) {
        if (depth > 16)
            throw std::runtime_error(
                    "snapshot protection nesting exceeds limit");
        for (const auto &patch : document.modern_patches) {
            if (!patch.snapshot_metadata)
                continue;
            if (!patch.standalone_snapshot) {
                throw std::runtime_error(patch.errors.empty()
                                                 ? "snapshot has no state"
                                                 : patch.errors.front());
            }
            if (found)
                throw std::runtime_error(
                        "multiple instrument snapshots in one file");
            if (!patch.file_table)
                throw std::runtime_error("snapshot has no filename table");
            const auto index =
                    patch.snapshot_metadata->translated_filename_table_index;
            if (index < 0 || static_cast<std::size_t>(index) >=
                                     patch.file_table->files.size())
                throw std::runtime_error(
                        "snapshot parent filename index is out of range");
            for (std::size_t i = 0; i < patch.file_table->files.size(); ++i) {
                const auto &file = patch.file_table->files[i];
                SampleInfo sample;
                sample.serialized_path = serialized_path(file.selected_path);
                sample.secondary_serialized_path =
                        serialized_path(file.secondary_path);
                sample.file_table_index = static_cast<std::int32_t>(i);
                sample.timestamp = file.timestamp;
                sample.content_file_path_mode = file.field_00;
                sample.content_file_library_id =
                        static_cast<std::uint32_t>(file.field_04);
                result.files.push_back(std::move(sample));
            }
            result.parent_instrument = result.files[index];
            result.special_filename_base =
                    patch.file_table->special_filename_base;
            result.state = *patch.standalone_snapshot;
            found = true;
        }
        if (document.protected_items.empty())
            return;
        auto key = inherited_key;
        for (const auto &preset : document.presets) {
            const bool needs_key = std::ranges::any_of(
                    document.protected_items, [](const auto &item) {
                        return item.kind ==
                                       ProtectedItemKind::encryption_item &&
                               item.xor_enabled.value_or(false);
                    });
            if (needs_key && !preset.authorization_snpid.empty() &&
                    preset.authorization_snpid != "000") {
                key = derive_local_product_encryption_key(
                        private_key, libraries, preset.authorization_snpid);
                break;
            }
        }
        for (const auto &item : document.protected_items) {
            const auto decoded = decode_protected_item(data, item, key);
            visit(decoded, parse(decoded), key, depth + 1);
        }
    };
    visit(bytes, outer, {}, 0);
    if (!found)
        throw std::runtime_error("file contains no instrument snapshot");
    return result;
}

void apply_instrument_snapshot(
        InstrumentInfo &instrument, const InstrumentSnapshotInfo &snapshot) {
    if (instrument.programs.size() != 1)
        throw std::runtime_error(
                "an instrument snapshot requires one parent program");
    auto &program = instrument.programs.front();
    const auto sample_base = instrument.samples.size();
    instrument.samples.insert(instrument.samples.end(), snapshot.files.begin(),
            snapshot.files.end());
    const auto effects = [&](std::vector<GroupEffectInfo> &target,
                                 const ParameterArrayPayload &source) {
        target.clear();
        append_modern_effects(target, source);
        resolve_irc_samples(target, sample_base, snapshot.files.size(),
                snapshot.special_filename_base);
    };
    const auto &state = snapshot.state;
    // extra saved groups get dropped, groups past the saved count keep their
    // state
    for (std::size_t i = 0;
            i < std::min(instrument.groups.size(), state.groups.size()); ++i) {
        auto &target = instrument.groups[i];
        const auto &source = state.groups[i];
        target.volume = source.prefix.leading_f32[0];
        target.pan = source.prefix.leading_f32[1];
        target.tune = std::exp2(source.prefix.leading_f32[2]);
        target.key_tracking = source.prefix.flags[0];
        target.reverse = source.prefix.flags[1];
        target.release_trigger = source.prefix.flags[2];
        target.release_trigger_note_monophonic = source.prefix.flags[3];
        target.release_trigger_counter = source.prefix.field_after_flags;
        target.phase_invert = source.flags_after_source_mode[0];
        if (source.samples_purged)
            target.purged = *source.samples_purged;
        if (source.version_4_s32.size() == 2)
            target.output = source.version_4_s32[0];
        const auto &mode = source.source_mode;
        target.source_mode = SourceModeInfo{ static_cast<PlaybackMode>(
                                                     mode.prefix.internal_mode),
            mode.prefix.field_after_mode, mode.prefix.versioned_f32[0],
            mode.prefix.versioned_f32[0] > 1.0e-9F, wavetable_source_info(mode),
            time_machine_source_info(mode), time_machine_pro_source_info(mode),
            mode.prefix.serializable.version < 0x102 ||
                    mode.prefix.version_0x102_flag };
        if (target.source_mode->mode == PlaybackMode::slice_machine)
            target.source_mode->slice_machine = modern_slice_source_info(mode);
        target.source_mode->zone_locked_speed = mode.prefix.second_flag;
        effects(target.effects, source.effect_array);
        target.internal_modulators.clear();
        for (std::size_t slot = 0;
                slot < source.internal_modulator_array.entries.size(); ++slot) {
            const auto &entry = source.internal_modulator_array.entries[slot];
            if (!entry.present || !entry.internal_modulator)
                continue;
            const auto &mod = *entry.internal_modulator;
            if ((mod.modulator_type == 1 && mod.lfo) ||
                    (mod.modulator_type == 2 && mod.envelope &&
                            mod.envelope->envelope_type <= 2)) {
                target.internal_modulators.push_back(internal_modulator(mod));
                target.internal_modulators.back().source_slot =
                        static_cast<std::int32_t>(slot);
            }
        }
        target.external_modulators.clear();
        for (std::size_t slot = 0;
                slot < source.external_modulator_array.entries.size(); ++slot) {
            const auto &entry = source.external_modulator_array.entries[slot];
            if (entry.present && entry.external_modulator &&
                    (entry.external_modulator->source ||
                            entry.external_modulator->mode == 2)) {
                target.external_modulators.push_back(
                        external_modulator(*entry.external_modulator));
                target.external_modulators.back().source_slot =
                        16 + static_cast<std::int32_t>(slot);
            }
        }
    }
    if (state.master_effect_array)
        effects(program.insert_effects, *state.master_effect_array);
    if (state.program_effect_array)
        effects(program.send_effects, *state.program_effect_array);
    if (state.third_effect_array)
        effects(program.main_effects, *state.third_effect_array);
    for (std::size_t i = 0; i < std::min(program.insert_buses.size(),
                                        state.insert_buses.size());
            ++i) {
        auto &bus = program.insert_buses[i];
        const auto &source = state.insert_buses[i];
        bus.name = source.name;
        bus.level = source.level_pan[0];
        bus.pan = source.level_pan[1];
        if (source.version_0x11_s32)
            bus.destination = source.version_0x11_s32;
        if (!source.version_0x12_flags.empty())
            bus.phase_invert = source.version_0x12_flags[0];
        if (source.version_0x12_flags.size() > 1)
            bus.swap_stereo = source.version_0x12_flags[1];
        effects(bus.effects, source.effect_array);
    }
    for (std::size_t slot = 0; slot < std::min(program.script_indices.size(),
                                              state.string_arrays.size());
            ++slot) {
        auto &script = instrument.scripts.at(program.script_indices[slot]);
        // variables absent from the snapshot keep their current values
        for (const auto &value : state.string_arrays[slot]) {
            if (!value)
                continue;
            auto restored = persistent_variable(*value);
            const auto existing = std::find_if(
                    script.persistent_variables.begin(),
                    script.persistent_variables.end(),
                    [&](const auto &variable) {
                        return restored.name && variable.name == restored.name;
                    });
            if (existing != script.persistent_variables.end())
                *existing = std::move(restored);
            else
                script.persistent_variables.push_back(std::move(restored));
        }
    }
}

ResolvedPathInfo resolve_path(const SerializedPathInfo &serialized,
        const PathResolutionContext &context) {
    return resolve_path_impl(serialized, context);
}

Model normalize(const Document &document) {
    Model model;
    InstrumentInfo instrument;
    instrument.generation = source_generation(document.generation);
    instrument.name = document.metadata.name;
    instrument.author = document.metadata.author;
    instrument.version = document.metadata.version;
    if (document.k1_patch_data)
        append_k1(instrument, *document.k1_patch_data);
    if (document.k2_patch_data)
        append_k2(instrument, *document.k2_patch_data);
    for (const auto &patch : document.modern_patches)
        append_modern(instrument, patch);
    if (document.k42_patch_data && instrument.programs.empty())
        model.diagnostics.push_back("K4.2 wrapper parsed; normalized inner "
                                    "program semantics are not yet available");
    for (const auto &error : document.errors)
        model.diagnostics.push_back(
                std::to_string(error.offset) + ": " + error.message);
    for (const auto &sample : document.audio_sample_items) {
        model.embedded_audio_samples.push_back({ sample.sample_index,
                sample.frame_count, sample.channel_count, sample.channels });
    }
    for (const auto &reference : document.external_file_references) {
        model.external_file_references.push_back({ reference.value_code,
                reference.snpid, reference.string_0, reference.string_1 });
    }
    for (const auto &reference : document.internal_resource_references) {
        model.internal_resource_references.push_back(
                { reference.resource_type, reference.reference_id });
    }
    for (const auto &picture : document.picture_items) {
        model.pictures.push_back({ picture.picture_type, picture.filename,
                picture.binary_data, picture.legacy_filename_components,
                picture.legacy_filename_uri });
    }
    for (const auto &binary : document.binary_chunk_items) {
        model.binary_resources.push_back(
                { binary.binary_data, binary.context_id });
    }
    for (const auto &resources : document.resources_items) {
        model.resource_collections.push_back({ resources.num_samples,
                resources.num_pictures, resources.num_generic_binaries });
    }
    for (const auto &item : document.generic_items) {
        if (item.derived_records.empty())
            continue;
        const auto &outer = item.derived_records.front();
        model.generic_items.push_back({ outer.domain, outer.item_id,
                outer.version, item.derived_payload });
    }
    for (const auto &module : document.module_items) {
        ModuleInfo info;
        info.authorization_level = module.authorization_level;
        info.authoring_application_version =
                module.authoring_application_version;
        if (module.license_info) {
            info.product_bindings = module.license_info->product_bindings;
            info.watermark = module.license_info->watermark;
        }
        model.modules.push_back(std::move(info));
    }
    for (const auto &authorization : document.authorization_items) {
        AuthorizationInfo info;
        info.level = authorization.level;
        if (authorization.license_info) {
            info.product_bindings =
                    authorization.license_info->product_bindings;
            info.watermark = authorization.license_info->watermark;
        }
        model.authorizations.push_back(std::move(info));
    }
    for (const auto &item : document.base_items) {
        model.repository_base_items.push_back({ item.child_count });
    }
    for (const auto &bank : document.module_bank_items) {
        model.module_banks.push_back({ bank.name });
    }
    for (const auto &bank : document.bank_items) {
        model.repository_banks.push_back({ bank.name });
    }
    for (const auto &container : document.bank_container_items) {
        model.repository_bank_containers.push_back(
                { container.selected_bank_index, container.child_count });
    }
    for (const auto &container : document.preset_container_items) {
        model.repository_preset_containers.push_back({ container.child_count });
    }
    if (document.format != Format::unknown)
        model.instruments.push_back(std::move(instrument));
    if (document.resource_monolith) {
        auto resources = normalize(*document.resource_monolith);
        model.resources = std::move(resources.resources);
    }
    return model;
}

Model normalize(const NicntProductHints &product_hints) {
    Model model;
    for (const auto &product : product_hints.products) {
        model.products.push_back({ product.name, product.type, product.snpid,
                product.upid, product.company, product.vendor, product.website,
                product.engine, product.engine_version });
    }
    for (const auto &rejected : product_hints.rejected_products)
        model.diagnostics.push_back("product " +
                                    std::to_string(rejected.source_index) +
                                    ": " + rejected.error);
    return model;
}

Model normalize(const NicntContainer &container) {
    Model model;
    for (const auto &product : container.products) {
        model.products.push_back({ product.name, product.type, product.snpid,
                product.upid, product.company, product.vendor, product.website,
                product.engine, product.engine_version });
    }
    for (const auto &toc : container.content_tocs)
        for (const auto &entry : toc.entries)
            model.contents.push_back({ narrow(entry.name), entry.id,
                    entry.revision, entry.relative_offset, entry.size });
    for (const auto &rejected : container.rejected_products)
        model.diagnostics.push_back("product " +
                                    std::to_string(rejected.source_index) +
                                    ": " + rejected.error);
    return model;
}

Model normalize(const MonolithContainer &container) {
    Model model;
    for (const auto &table : container.tables)
        for (const auto &entry : table.entries) {
            std::uint64_t size = entry.serialized_size;
            if (entry.payload)
                size = entry.payload->source_size;
            model.resources.push_back({ narrow(entry.name), entry.type,
                    entry.resolved_offset, size });
        }
    return model;
}

Model normalize(const NkcCache &cache) {
    Model model;
    append_nkc_node(model, cache.root);
    return model;
}

Model normalize(const NcwInfo &value) {
    Model model;
    model.audio = AudioInfo{ value.sample_rate, value.channel_count,
        value.bits_per_sample, value.sample_count };
    return model;
}

Model parse_model(std::span<const std::byte> bytes,
        std::span<const std::byte> encryption_key) {
    return normalize(parse(bytes, encryption_key));
}

Model parse_model_file(const std::filesystem::path &path) {
    return parse_model_file_with_private_key(
            path, bundled_encryption_private_key());
}

Model parse_model_file_with_private_key(const std::filesystem::path &path,
        std::span<const std::byte> private_key) {
    const auto bytes = read_file(path);
    auto document = parse(bytes);
    auto model = normalize(document);
    if (!document.protected_items.empty()) {
        const auto outer_name = document.metadata.name;
        const auto outer_author = document.metadata.author;
        const auto outer_version = document.metadata.version;
        const auto libraries = discover_local_libraries(path);
        append_protected_models(
                model, bytes, document, private_key, 0, libraries);
        model.instruments.erase(
                std::remove_if(model.instruments.begin(),
                        model.instruments.end(), empty_instrument),
                model.instruments.end());
        if (!model.instruments.empty()) {
            auto &instrument = model.instruments.front();
            if (!instrument.name)
                instrument.name = outer_name;
            if (!instrument.author)
                instrument.author = outer_author;
            if (!instrument.version)
                instrument.version = outer_version;
        }
    }
    return model;
}

Model parse_model_file(const std::filesystem::path &path,
        std::span<const std::byte> encryption_key) {
    const auto bytes = read_file(path);
    auto document = parse(bytes, encryption_key);
    auto model = normalize(document);
    if (!document.protected_items.empty()) {
        const auto outer_name = document.metadata.name;
        const auto outer_author = document.metadata.author;
        const auto outer_version = document.metadata.version;
        append_protected_models_with_product_key(
                model, bytes, document, encryption_key, 0);
        model.instruments.erase(
                std::remove_if(model.instruments.begin(),
                        model.instruments.end(), empty_instrument),
                model.instruments.end());
        if (!model.instruments.empty()) {
            auto &instrument = model.instruments.front();
            if (!instrument.name)
                instrument.name = outer_name;
            if (!instrument.author)
                instrument.author = outer_author;
            if (!instrument.version)
                instrument.version = outer_version;
        }
    }
    return model;
}

Model parse_nicnt_model(std::span<const std::byte> bytes) {
    return normalize(parse_nicnt(bytes));
}

Model parse_monolith_model(
        std::span<const std::byte> bytes, std::size_t root_offset) {
    return normalize(parse_monolith_container(bytes, root_offset));
}

Model parse_nkc_model(std::span<const std::byte> bytes) {
    return normalize(parse_nkc_cache(bytes));
}

Model parse_ncw_model(
        std::span<const std::byte> bytes, std::size_t file_offset) {
    return normalize(parse_ncw_info(bytes, file_offset));
}

} // namespace libnki
