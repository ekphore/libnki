// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../internal.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

namespace libnki {
namespace {

const std::string *tag_attribute(
        const K1TagElement &element, std::string_view name) {
    const auto found = std::find_if(element.attributes.begin(),
            element.attributes.end(), [name](const K1TagAttribute &attribute) {
                return attribute.name == name;
            });
    return found == element.attributes.end() ? nullptr : &found->value;
}

std::optional<std::uint16_t> parse_k2_dotted_version(const std::string &value) {
    unsigned major{};
    unsigned minor{};
    if (std::sscanf(value.c_str(), "%x.%x", &major, &minor) != 2 ||
            major > 0xffffU || minor > 0xffffU)
        return std::nullopt;
    const auto packed = static_cast<std::uint32_t>(minor) |
                        (static_cast<std::uint32_t>(major) << 8U);
    if (packed == 0 || packed > 0xffffU)
        return std::nullopt;
    return static_cast<std::uint16_t>(packed);
}

std::vector<const K1TagElement *> k2_parameter_values(
        const K1TagElement &element) {
    std::vector<const K1TagElement *> values;
    for (const auto &child : element.children) {
        if (child.name == "V")
            values.push_back(&child);
        else if (child.name == "Parameters") {
            for (const auto &value : child.children)
                if (value.name == "V")
                    values.push_back(&value);
        }
    }
    return values;
}

} // namespace

struct K2SurroundPresetSpeaker {
    float x{};
    float y{};
    std::uint8_t flags_or_role{};
};
struct K2SurroundPreset {
    std::uint32_t speaker_count{};
    std::array<K2SurroundPresetSpeaker, 16> speakers{};
};
static constexpr std::array<K2SurroundPreset, 42> k2_surround_presets = { {
#include "tables/k2_surround_presets.inc"
} };

K2EffectSemantic detail::parse_k2_effect(const K1TagElement &element) {
    K2EffectSemantic out;
    out.attributes = element.attributes;
    for (const auto *value_tag : k2_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "routersOpen")
            out.routers_open = *value == "yes";
        else if (*name == "classID")
            out.class_id = std::atoi(value->c_str());
        else if (*name == "bypass")
            out.bypass = *value == "yes";
        else if (*name == "outLevel")
            out.output_level = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "outLevelDry")
            out.dry_output_level =
                    static_cast<float>(std::atof(value->c_str()));
        else if (*name == "sendFXOutPartition")
            out.send_fx_output_partition = std::atoi(value->c_str());
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    for (const auto &child : element.children) {
        std::optional<std::pair<K2EffectKind, std::uint32_t>> kind;
        if (child.name == "Inverter")
            kind = { { K2EffectKind::inverter, 4 } };
        else if (child.name == "Gainer")
            kind = { { K2EffectKind::gainer, 0x47 } };
        else if (child.name == "Shaper")
            kind = { { K2EffectKind::shaper, 7 } };
        else if (child.name == "Stereo")
            kind = { { K2EffectKind::stereo_spread, 10 } };
        else if (child.name == "Dyx")
            kind = { { K2EffectKind::dyx, 5 } };
        else if (child.name == "Compressor")
            kind = { { K2EffectKind::compressor, 2 } };
        else if (child.name == "Limiter")
            kind = { { K2EffectKind::limiter, 3 } };
        else if (child.name == "LoFi")
            kind = { { K2EffectKind::lo_fi, 9 } };
        else if (child.name == "Distortion")
            kind = { { K2EffectKind::distortion, 0x0b } };
        else if (child.name == "Skreamer")
            kind = { { K2EffectKind::skreamer, 0x0d } };
        else if (child.name == "Rotator")
            kind = { { K2EffectKind::rotator, 0x0e } };
        else if (child.name == "Twang")
            kind = { { K2EffectKind::twang, 0x11 } };
        else if (child.name == "Cabinet")
            kind = { { K2EffectKind::cabinet, 0x1d } };
        else if (child.name == "Chorus")
            kind = { { K2EffectKind::chorus, 0x3d } };
        else if (child.name == "Flanger")
            kind = { { K2EffectKind::flanger, 0x3c } };
        else if (child.name == "Phaser")
            kind = { { K2EffectKind::phaser, 0x3b } };
        else if (child.name == "Filter")
            kind = { { K2EffectKind::filter, 8 } };
        else if (child.name == "Reverb")
            kind = { { K2EffectKind::reverb, 0x3e } };
        else if (child.name == "Delay")
            kind = { { K2EffectKind::delay, 0x43 } };
        else if (child.name == "SendLevels")
            kind = { { K2EffectKind::send_levels, 0x0c } };
        else if (child.name == "SurroundPanner")
            kind = { { K2EffectKind::surround_panner, 6 } };
        else if (child.name == "IRC")
            kind = { { K2EffectKind::irc, 0x46 } };
        if (!kind)
            continue;
        out.kind = kind->first;
        out.internal_type = kind->second;
        for (const auto *value_tag : k2_parameter_values(child)) {
            const auto *name = tag_attribute(*value_tag, "name");
            const auto *value = tag_attribute(*value_tag, "value");
            if (name == nullptr || value == nullptr)
                continue;
            const auto real = [&] {
                return static_cast<float>(std::atof(value->c_str()));
            };
            if (*name == "version") {
                out.subtype_version = parse_k2_dotted_version(*value);
                continue;
            }
            switch (kind->first) {
                case K2EffectKind::inverter: {
                    if (*name == "phase")
                        out.inverter_phase = *value == "yes";
                    else if (*name == "panorama")
                        out.inverter_panorama = *value == "yes";
                    break;
                }
                case K2EffectKind::gainer: {
                    if (*name == "gain")
                        out.gain = real();
                    break;
                }
                case K2EffectKind::shaper: {
                    if (*name == "shape")
                        out.shaper_shape = real();
                    else if (*name == "type")
                        out.shaper_type = std::atoi(value->c_str());
                    break;
                }
                case K2EffectKind::stereo_spread: {
                    if (*name == "spread")
                        out.stereo_spread = real();
                    else if (*name == "pan")
                        out.stereo_pan = real();
                    else if (*name == "pseudo")
                        out.stereo_pseudo = *value == "yes";
                    break;
                }
                case K2EffectKind::dyx: {
                    if (*name == "morph")
                        out.dyx_morph = real();
                    else if (*name == "dry")
                        out.dyx_dry = real();
                    else if (*name == "morphMapIdx")
                        out.dyx_morph_map_index = std::atoi(value->c_str());
                    else if (*name == "linearPhase")
                        out.dyx_linear_phase = *value == "yes";
                    break;
                }
                case K2EffectKind::compressor: {
                    if (*name == "model") {
                        if (*value == "classic")
                            out.compressor_model = K2CompressorModel::classic;
                        else if (*value == "enhanced")
                            out.compressor_model = K2CompressorModel::enhanced;
                        else if (*value == "pro")
                            out.compressor_model = K2CompressorModel::pro;
                    } else if (*name == "threshold")
                        out.compressor_threshold = real();
                    else if (*name == "ratio")
                        out.compressor_ratio = real();
                    else if (*name == "attack")
                        out.compressor_attack = real();
                    else if (*name == "release")
                        out.compressor_release = real();
                    else if (*name == "stereoLink")
                        out.compressor_stereo_link = *value == "yes";
                    break;
                }
                case K2EffectKind::limiter: {
                    if (*name == "inGain")
                        out.limiter_input_gain = real();
                    else if (*name == "rlsTime")
                        out.limiter_release_time = real();
                    break;
                }
                case K2EffectKind::lo_fi: {
                    if (*name == "bits")
                        out.lo_fi_bits = real();
                    else if (*name == "downSample")
                        out.lo_fi_down_sample = real();
                    else if (*name == "shIsInteger")
                        out.lo_fi_sample_hold_integer = *value == "yes";
                    else if (*name == "noiseLevel")
                        out.lo_fi_noise_level = real();
                    else if (*name == "noiseColor")
                        out.lo_fi_noise_color = real();
                    break;
                }
                case K2EffectKind::distortion: {
                    if (*name == "type") {
                        if (*value == "tube")
                            out.distortion_type = K2DistortionType::tube;
                        else if (*value == "transistor")
                            out.distortion_type = K2DistortionType::transistor;
                    } else if (*name == "drive")
                        out.distortion_drive = real();
                    else if (*name == "damping")
                        out.distortion_damping = real();
                    break;
                }
                case K2EffectKind::skreamer: {
                    if (*name == "tone")
                        out.skreamer_tone = real();
                    else if (*name == "drive")
                        out.skreamer_drive = real();
                    else if (*name == "bass")
                        out.skreamer_bass = real();
                    else if (*name == "bright")
                        out.skreamer_bright = real();
                    else if (*name == "mix")
                        out.skreamer_mix = real();
                    break;
                }
                case K2EffectKind::rotator: {
                    if (*name == "speed")
                        out.rotator_speed = real();
                    else if (*name == "balance")
                        out.rotator_balance = real();
                    else if (*name == "accelHi")
                        out.rotator_acceleration_high = real();
                    else if (*name == "accelLo")
                        out.rotator_acceleration_low = real();
                    else if (*name == "distance")
                        out.rotator_distance = real();
                    else if (*name == "mix")
                        out.rotator_mix = real();
                    break;
                }
                case K2EffectKind::twang: {
                    if (*name == "volume")
                        out.twang_volume = real();
                    else if (*name == "treble")
                        out.twang_treble = real();
                    else if (*name == "mid")
                        out.twang_mid = real();
                    else if (*name == "bass")
                        out.twang_bass = real();
                    else if (*name == "bright")
                        out.twang_bright = *value == "yes";
                    else if (*name == "polyphonic") {
                        out.twang_serialized_polyphonic = *value == "yes";
                        out.twang_effective_monophonic =
                                !*out.twang_serialized_polyphonic;
                    }
                    break;
                }
                case K2EffectKind::cabinet: {
                    if (*name == "size")
                        out.cabinet_size = real();
                    else if (*name == "air")
                        out.cabinet_air = real();
                    else if (*name == "treble")
                        out.cabinet_treble = real();
                    else if (*name == "bass")
                        out.cabinet_bass = real();
                    else if (*name == "cabinetType")
                        out.cabinet_type = std::atoi(value->c_str());
                    break;
                }
                case K2EffectKind::chorus: {
                    if (*name == "depth")
                        out.chorus_depth = real();
                    else if (*name == "speed")
                        out.chorus_speed = real();
                    else if (*name == "phase")
                        out.chorus_phase = real();
                    else if (*name == "noteValue_speed") {
                        out.chorus_note_value_speed = real();
                        out.chorus_note_value_speed_enabled =
                                *out.chorus_note_value_speed > 1.0e-9F;
                    }
                    break;
                }
                case K2EffectKind::flanger: {
                    if (*name == "depth")
                        out.flanger_depth = real();
                    else if (*name == "feedback")
                        out.flanger_feedback = real();
                    else if (*name == "speed")
                        out.flanger_speed = real();
                    else if (*name == "phase")
                        out.flanger_phase = real();
                    else if (*name == "color")
                        out.flanger_color = real();
                    else if (*name == "noteValue_speed") {
                        out.flanger_note_value_speed = real();
                        out.flanger_note_value_speed_enabled =
                                *out.flanger_note_value_speed > 1.0e-9F;
                    }
                    break;
                }
                case K2EffectKind::phaser: {
                    if (*name == "depth")
                        out.phaser_depth = real();
                    else if (*name == "feedback")
                        out.phaser_feedback = real();
                    else if (*name == "speed")
                        out.phaser_speed = real();
                    else if (*name == "phase")
                        out.phaser_phase = real();
                    else if (*name == "noteValue_speed") {
                        out.phaser_note_value_speed = real();
                        out.phaser_note_value_speed_enabled =
                                *out.phaser_note_value_speed > 1.0e-9F;
                    }
                    break;
                }
                case K2EffectKind::filter: {
                    if (*name == "type") {
                        static constexpr auto types = std::to_array<
                                std::pair<std::string_view, K2FilterType>>({
                                { "lp1pole", K2FilterType::low_pass_1_pole },
                                { "hp1pole", K2FilterType::high_pass_1_pole },
                                { "lp2pole", K2FilterType::low_pass_2_pole },
                                { "hp2pole", K2FilterType::high_pass_2_pole },
                                { "bp2pole", K2FilterType::band_pass_2_pole },
                                { "lp4pole", K2FilterType::low_pass_4_pole },
                                { "hp4pole", K2FilterType::high_pass_4_pole },
                                { "bp4pole", K2FilterType::band_pass_4_pole },
                                { "br4pole", K2FilterType::band_reject_4_pole },
                                { "lp6pole", K2FilterType::low_pass_6_pole },
                                { "phaser", K2FilterType::phaser },
                                { "vowelA", K2FilterType::vowel_a },
                                { "vowelB", K2FilterType::vowel_b },
                                { "pro52", K2FilterType::pro_52 },
                                { "ladder", K2FilterType::ladder },
                                { "versatile", K2FilterType::versatile },
                                { "eq1band", K2FilterType::eq_1_band },
                                { "eq2band", K2FilterType::eq_2_band },
                                { "eq3band", K2FilterType::eq_3_band },
                        });
                        const auto found = std::find_if(types.begin(),
                                types.end(), [&](const auto &entry) {
                                    return entry.first == *value;
                                });
                        if (found != types.end())
                            out.filter_type = found->second;
                    } else if (*name == "cutoff")
                        out.filter_cutoff = real();
                    else if (*name == "resonance")
                        out.filter_resonance = real();
                    else if (*name == "shiftB")
                        out.filter_shift_b = real();
                    else if (*name == "shiftC")
                        out.filter_shift_c = real();
                    else if (*name == "resB")
                        out.filter_resonance_b = real();
                    else if (*name == "resC")
                        out.filter_resonance_c = real();
                    else if (*name == "gain")
                        out.filter_gain = real();
                    else {
                        int index{};
                        char tail{};
                        if (std::sscanf(name->c_str(), "freq_%d%c", &index,
                                    &tail) == 1 &&
                                index >= 1 && index <= 3)
                            out.filter_eq_frequency[static_cast<std::size_t>(
                                    index - 1)] = real();
                        else if (std::sscanf(name->c_str(), "bandWidth_%d%c",
                                         &index, &tail) == 1 &&
                                 index >= 1 && index <= 3)
                            out.filter_eq_bandwidth[static_cast<std::size_t>(
                                    index - 1)] = real();
                        else if (std::sscanf(name->c_str(), "gain_%d%c", &index,
                                         &tail) == 1 &&
                                 index >= 1 && index <= 3)
                            out.filter_eq_gain[static_cast<std::size_t>(
                                    index - 1)] = real();
                        else if (name->size() == 5 &&
                                 name->starts_with("type") &&
                                 (*name)[4] >= 'A' && (*name)[4] <= 'C')
                            out.filter_vowel_type[static_cast<std::size_t>(
                                    (*name)[4] - 'A')] = real();
                        else if (name->size() == 4 &&
                                 name->starts_with("byp") &&
                                 (*name)[3] >= 'A' && (*name)[3] <= 'C')
                            out.filter_vowel_bypass[static_cast<std::size_t>(
                                    (*name)[3] - 'A')] = real();
                    }
                    break;
                }
                case K2EffectKind::reverb: {
                    if (*name == "preDelay")
                        out.reverb_pre_delay = real();
                    else if (*name == "roomsize")
                        out.reverb_room_size = real();
                    else if (*name == "stereo")
                        out.reverb_stereo = real();
                    else if (*name == "color")
                        out.reverb_color = real();
                    else if (*name == "filter")
                        out.reverb_filter = real();
                    break;
                }
                case K2EffectKind::delay: {
                    if (*name == "time")
                        out.delay_time = real();
                    else if (*name == "feedback")
                        out.delay_feedback = real();
                    else if (*name == "panning")
                        out.delay_panning = real();
                    else if (*name == "damping")
                        out.delay_damping = real();
                    else if (*name == "noteValue_time") {
                        out.delay_note_value_time = real();
                        out.delay_note_value_time_enabled =
                                *out.delay_note_value_time > 1.0e-9F;
                    }
                    break;
                }
                case K2EffectKind::send_levels: {
                    int index{};
                    char tail{};
                    if (std::sscanf(name->c_str(), "level_%d%c", &index,
                                &tail) == 1 &&
                            index >= 0 && index < 8)
                        out.send_levels[static_cast<std::size_t>(index)] =
                                real();
                    break;
                }
                case K2EffectKind::surround_panner: {
                    if (*name == "numSpk")
                        out.surround_serialized_speaker_count =
                                std::atoi(value->c_str());
                    else if (*name == "numSrc")
                        out.surround_source_count = std::atoi(value->c_str());
                    else if (*name == "lfeXOverFreq")
                        out.surround_lfe_crossover_frequency = real();
                    else if (*name == "lfeVolume")
                        out.surround_lfe_volume = real();
                    else if (*name == "size")
                        out.surround_size = real();
                    else if (*name == "divergence")
                        out.surround_divergence = real();
                    else if (*name == "amountAir")
                        out.surround_air_amount = real();
                    else if (*name == "amountDelay")
                        out.surround_delay_amount = real();
                    else if (*name == "amountDoppler")
                        out.surround_doppler_amount = real();
                    else if (*name == "volumeAlgorithm") {
                        if (*value == "volume_algorithm_const_power")
                            out.surround_volume_algorithm =
                                    K2SurroundVolumeAlgorithm::constant_power;
                        else if (*value == "volume_algorithm_sinusoid")
                            out.surround_volume_algorithm =
                                    K2SurroundVolumeAlgorithm::sinusoid;
                        else if (*value == "volume_algorithm_logarithmic")
                            out.surround_volume_algorithm =
                                    K2SurroundVolumeAlgorithm::logarithmic;
                    } else if (*name == "useSpeakerDelays")
                        out.surround_use_speaker_delays = *value == "yes";
                    else if (*name == "useAirAbsorption")
                        out.surround_use_air_absorption = *value == "yes";
                    else if (*name == "useDopplerEffect")
                        out.surround_use_doppler_effect = *value == "yes";
                    else if (*name == "offsetDistance")
                        out.surround_offset_distance = real();
                    else if (*name == "offsetAzimuth")
                        out.surround_offset_azimuth = real();
                    else if (*name == "offsetX")
                        out.surround_offset_x = real();
                    else if (*name == "offsetY")
                        out.surround_offset_y = real();
                    else if (*name == "presetSpeakerSetup")
                        out.surround_preset_speaker_setup =
                                std::atoi(value->c_str());
                    else {
                        int index{};
                        char field[8]{};
                        auto assign_channel = [&](K2SurroundChannel &channel) {
                            if (std::strcmp(field, "x") == 0)
                                channel.x = real();
                            else if (std::strcmp(field, "y") == 0)
                                channel.y = real();
                            else if (std::strcmp(field, "flags") == 0) {
                                channel.flags = static_cast<std::uint8_t>(
                                        std::atoi(value->c_str()));
                                channel.effective_flags_or_role = channel.flags;
                            } else if (std::strcmp(field, "role") == 0) {
                                channel.role = static_cast<std::uint8_t>(
                                        std::atoi(value->c_str()));
                                channel.effective_flags_or_role = channel.role;
                            }
                        };
                        if (std::sscanf(name->c_str(), "spk_%02d_%7s", &index,
                                    field) == 2 &&
                                index >= 0 && index < 16)
                            assign_channel(out.surround_speakers
                                            [static_cast<std::size_t>(index)]);
                        else if (std::sscanf(name->c_str(), "src_%02d_%7s",
                                         &index, field) == 2 &&
                                 index >= 0 && index < 16)
                            assign_channel(out.surround_sources
                                            [static_cast<std::size_t>(index)]);
                    }
                    break;
                }
                case K2EffectKind::irc: {
                    if (*name == "irFile")
                        out.irc_serialized_ir_file = *value;
                    else if (*name == "sampleRateDecFactor")
                        out.irc_sample_rate_decimation_factor = real();
                    else if (*name == "convolutionBlockSize")
                        out.irc_serialized_convolution_block_size =
                                std::atoi(value->c_str());
                    else if (*name == "preDelay")
                        out.irc_pre_delay = real();
                    else if (*name == "lengthRatio_ER")
                        out.irc_early_length_ratio = real();
                    else if (*name == "freqHighPass_ER")
                        out.irc_early_high_pass_frequency = real();
                    else if (*name == "freqLowPass_ER")
                        out.irc_early_low_pass_frequency = real();
                    else if (*name == "lengthRatio_LR")
                        out.irc_late_length_ratio = real();
                    else if (*name == "freqHighPass_LR")
                        out.irc_late_high_pass_frequency = real();
                    else if (*name == "freqLowPass_LR")
                        out.irc_late_low_pass_frequency = real();
                    else if (*name == "er_lr_XPoint")
                        out.irc_early_late_crosspoint = real();
                    else if (*name == "reverse")
                        out.irc_reverse = *value == "yes";
                    else if (*name == "autoGain")
                        out.irc_auto_gain = *value == "yes";
                    else if (*name == "preserveLengthIR")
                        out.irc_preserve_ir_length = *value == "yes";
                    else if (*name == "bypassLatencyCompensation")
                        out.irc_serialized_bypass_latency_compensation =
                                *value == "yes";
                    else if (*name == "envActive")
                        out.irc_envelope_active = *value == "yes";
                    else {
                        int index{};
                        char tail{};
                        if (std::sscanf(name->c_str(), "envTime_%d%c", &index,
                                    &tail) == 1 &&
                                index >= 0 && index < 8)
                            out.irc_envelope_times[static_cast<std::size_t>(
                                    index)] = real();
                        else if (std::sscanf(name->c_str(), "envLevel_%d%c",
                                         &index, &tail) == 1 &&
                                 index >= 0 && index < 8)
                            out.irc_envelope_levels[static_cast<std::size_t>(
                                    index)] = real();
                    }
                    break;
                }
                default:
                    break;
            }
        }
        if (out.kind == K2EffectKind::shaper && out.subtype_version &&
                *out.subtype_version < 0x0070 && out.shaper_shape) {
            *out.shaper_shape += *out.shaper_shape;
        }
        if (out.kind == K2EffectKind::compressor && out.subtype_version &&
                *out.subtype_version < 0x0070 && out.compressor_threshold) {
            *out.compressor_threshold =
                    std::log2(*out.compressor_threshold) * 6.0F;
        }
        if (out.kind == K2EffectKind::limiter && out.subtype_version &&
                *out.subtype_version < 0x0060 && out.limiter_input_gain) {
            *out.limiter_input_gain = std::log2(*out.limiter_input_gain) * 6.0F;
        }
        if (out.kind == K2EffectKind::twang) {
            out.twang_effective_monophonic =
                    !out.twang_serialized_polyphonic.value_or(false);
        }
        if (out.kind == K2EffectKind::filter && out.subtype_version &&
                *out.subtype_version < 0x0080 && out.filter_type &&
                *out.filter_type >= K2FilterType::eq_1_band &&
                *out.filter_type <= K2FilterType::eq_3_band) {
            for (auto &gain : out.filter_eq_gain) {
                if (gain)
                    *gain = std::log2(*gain) * 6.0F;
            }
        }
        if (out.kind == K2EffectKind::surround_panner && out.subtype_version &&
                *out.subtype_version < 0x0070) {
            if (out.surround_offset_distance)
                *out.surround_offset_distance *= 2.0F;
            if (out.surround_offset_x)
                *out.surround_offset_x *= 2.0F;
            if (out.surround_offset_y)
                *out.surround_offset_y *= 2.0F;
            if (out.surround_lfe_volume)
                *out.surround_lfe_volume =
                        std::log2(*out.surround_lfe_volume) * 6.0F;
        }
        if (out.kind == K2EffectKind::surround_panner) {
            out.surround_effective_speakers = out.surround_speakers;
            out.surround_effective_speaker_count =
                    out.surround_serialized_speaker_count;
            if (out.surround_preset_speaker_setup &&
                    *out.surround_preset_speaker_setup >= 0 &&
                    static_cast<std::size_t>(
                            *out.surround_preset_speaker_setup) <
                            k2_surround_presets.size()) {
                const auto &preset =
                        k2_surround_presets[static_cast<std::size_t>(
                                *out.surround_preset_speaker_setup)];
                out.surround_effective_speaker_count =
                        static_cast<std::int32_t>(preset.speaker_count);
                const auto copied =
                        std::max<std::uint32_t>(preset.speaker_count, 1);
                for (std::uint32_t index = 0; index < copied; ++index) {
                    auto &target = out.surround_effective_speakers[index];
                    target.x = preset.speakers[index].x;
                    target.y = preset.speakers[index].y;
                    target.effective_flags_or_role =
                            preset.speakers[index].flags_or_role;
                }
            }
        }
        if (out.kind == K2EffectKind::irc) {
            out.irc_effective_bypass_latency_compensation =
                    out.irc_serialized_bypass_latency_compensation.value_or(
                            out.subtype_version &&
                            *out.subtype_version > 0x005f);
            const auto block_size =
                    out.irc_serialized_convolution_block_size.value_or(0);
            out.irc_effective_convolution_block_size =
                    block_size < 0
                            ? (out.subtype_version && *out.subtype_version <
                                                              0x0070
                                              ? 0x100
                                              : 0)
                            : std::min(block_size, 0x400);
        }
    }
    return out;
}

} // namespace libnki

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace libnki::detail {
namespace {

const std::string *object_attribute(
        const K1TagElement &element, std::string_view name) {
    const auto found = std::find_if(element.attributes.begin(),
            element.attributes.end(),
            [name](const K1TagAttribute &item) { return item.name == name; });
    return found == element.attributes.end() ? nullptr : &found->value;
}

std::vector<const K1TagElement *> object_values(const K1TagElement &element) {
    std::vector<const K1TagElement *> result;
    for (const auto &child : element.children) {
        if (child.name == "V")
            result.push_back(&child);
        else if (child.name == "Parameters") {
            for (const auto &value : child.children)
                if (value.name == "V")
                    result.push_back(&value);
        }
    }
    return result;
}

std::optional<std::uint16_t> object_dotted_version(const std::string &value) {
    unsigned major{};
    unsigned minor{};
    if (std::sscanf(value.c_str(), "%x.%x", &major, &minor) != 2)
        return std::nullopt;
    const auto packed = minor | (major << 8U);
    if (packed == 0 || packed > 0xffffU)
        return std::nullopt;
    return static_cast<std::uint16_t>(packed);
}

} // namespace

K2BankSemantic parse_k2_bank(const K1TagElement &element) {
    K2BankSemantic out;
    out.attributes = element.attributes;
    for (const auto *item : object_values(element)) {
        const auto *name = object_attribute(*item, "name");
        const auto *value = object_attribute(*item, "value");
        if (!name || !value)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        if (*name == "loadPurged")
            out.load_purged = *value == "yes";
        else if (*name == "showMultiScript")
            out.show_multi_script = *value == "yes";
        else if (*name == "masterVolume")
            out.serialized_master_volume = real();
        else if (*name == "masterTune")
            out.serialized_master_tune = real();
        else if (*name == "origSubDir")
            out.original_subdirectory = *value;
        else if (*name == "origSaveMode")
            out.original_save_mode = integer();
        else if (*name == "origAbsolutePaths")
            out.original_absolute_paths = *value == "yes";
        else if (*name == "origCompressedSamples")
            out.original_compressed_samples = *value == "yes";
        else {
            int slot{};
            int send{};
            char tail{};
            if (std::sscanf(name->c_str(), "midiChannel_slot%03d%c", &slot,
                        &tail) == 1 &&
                    slot >= 0 && slot < 64)
                out.slots[static_cast<std::size_t>(slot)].midi_channel =
                        static_cast<std::int16_t>(integer());
            else if (std::sscanf(name->c_str(), "solo_slot%03d%c", &slot,
                             &tail) == 1 &&
                     slot >= 0 && slot < 64)
                out.slots[static_cast<std::size_t>(slot)].solo =
                        *value == "yes";
            else if (std::sscanf(name->c_str(), "mute_slot%03d%c", &slot,
                             &tail) == 1 &&
                     slot >= 0 && slot < 64)
                out.slots[static_cast<std::size_t>(slot)].mute =
                        *value == "yes";
            else if (std::sscanf(name->c_str(), "auxSendLevel%d_slot%03d%c",
                             &send, &slot, &tail) == 2 &&
                     send >= 0 && send < 4 && slot >= 0 && slot < 64)
                out.slots[static_cast<std::size_t>(slot)]
                        .auxiliary_send_levels[static_cast<std::size_t>(send)] =
                        real();
            else if (std::sscanf(name->c_str(), "reorderIdx_%03d%c", &slot,
                             &tail) == 1 &&
                     slot >= 0 && slot < 64)
                out.slots[static_cast<std::size_t>(slot)].reorder_index =
                        integer();
        }
    }
    return out;
}

K2ProgramContainerSemantic parse_k2_program_container(
        const K1TagElement &element) {
    K2ProgramContainerSemantic out;
    out.attributes = element.attributes;
    for (const auto *item : object_values(element)) {
        const auto *name = object_attribute(*item, "name");
        const auto *value = object_attribute(*item, "value");
        if (!name || !value)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        if (*name == "output")
            out.serialized_output = integer();
        else if (*name == "loadPurged")
            out.load_purged = *value == "yes";
        else if (*name == "tableOpen")
            out.table_open = *value == "yes";
        else if (*name == "smallRackUnit")
            out.small_rack_unit = *value == "yes";
        else if (*name == "auxSendsVisible")
            out.auxiliary_sends_visible = *value == "yes";
        else if (*name == "curProgramChangeNum")
            out.current_program_change_number =
                    static_cast<std::int16_t>(integer());
        else if (*name == "outputMask")
            out.serialized_output_mask = static_cast<std::uint32_t>(integer());
        else if (*name == "volume")
            out.volume = real();
        else if (*name == "pan")
            out.pan = real();
        else if (*name == "origSubDir")
            out.original_subdirectory = *value;
        else if (*name == "origSaveMode")
            out.original_save_mode = integer();
        else if (*name == "origAbsolutePaths")
            out.original_absolute_paths = *value == "yes";
        else if (*name == "origCompressedSamples")
            out.original_compressed_samples = *value == "yes";
        else if (*name == "hasBeenSaved")
            out.has_been_saved = *value == "yes";
    }
    return out;
}

K2OutputConfigurationSemantic parse_k2_output_configuration(
        const K1TagElement &element) {
    K2OutputConfigurationSemantic out;
    out.attributes = element.attributes;
    for (const auto *item : object_values(element)) {
        const auto *name = object_attribute(*item, "name");
        const auto *value = object_attribute(*item, "value");
        if (!name || !value)
            continue;
        int index{};
        char tail{};
        if (std::sscanf(name->c_str(), "physOutMapping_%d%c", &index, &tail) ==
                        1 &&
                index >= 0 && index < 128)
            out.physical_output_mapping[static_cast<std::size_t>(index)] =
                    std::atoi(value->c_str());
    }
    return out;
}

K2OutputPartitionSemantic parse_k2_output_partition(
        const K1TagElement &element) {
    K2OutputPartitionSemantic out;
    out.attributes = element.attributes;
    for (const auto *item : object_values(element)) {
        const auto *name = object_attribute(*item, "name");
        const auto *value = object_attribute(*item, "value");
        if (!name || !value)
            continue;
        if (*name == "name")
            out.name = *value;
        else if (*name == "numChannels")
            out.channel_count =
                    static_cast<std::int16_t>(std::atoi(value->c_str()));
        else if (*name == "auxIdx")
            out.auxiliary_index =
                    static_cast<std::int16_t>(std::atoi(value->c_str()));
        else if (*name == "volume")
            out.volume = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "version")
            out.parsed_version = object_dotted_version(*value);
    }
    return out;
}

void apply_k2_close_semantics(K2PatchData &data) {
    for (auto &program : data.programs) {
        std::vector<K2GroupSemantic *> groups;
        for (auto &group : data.groups) {
            if (group.program_ordinal == program.program_ordinal)
                groups.push_back(&group);
        }
        if (groups.empty())
            continue;

        const auto serialized =
                program.parameters
                        ? program.parameters->active_group_index.value_or(0)
                        : 0;
        auto effective = serialized;
        const auto valid =
                effective >= 0 &&
                static_cast<std::size_t>(effective) < groups.size() &&
                groups[static_cast<std::size_t>(effective)]
                        ->effective_selected_for_edit;
        if (!valid) {
            effective = -1;
            for (std::size_t index = 0; index < groups.size(); ++index) {
                if (groups[index]->effective_selected_for_edit) {
                    effective = static_cast<std::int32_t>(index);
                    break;
                }
            }
            if (effective < 0) {
                effective = 0;
                groups[0]->effective_selected_for_edit = true;
                groups[0]->selected_for_edit_repaired = true;
            }
            program.active_group_index_repaired = true;
        }
        program.effective_active_group_index = effective;
    }

    const auto in_range = [](std::uint32_t value, std::uint32_t first,
                                  std::uint32_t count) {
        return value >= first && value - first < count;
    };
    const auto parameter_matches_object = [&](std::uint32_t tag,
                                                  std::uint32_t descriptor) {
        const auto object_class = descriptor >> 16U & 0xffU;
        const auto subtype = descriptor >> 8U & 0xffU;
        const auto discriminator = descriptor & 0xffU;
        if (object_class == 1U) {
            if (in_range(tag, 0x2aaU, 6U))
                return subtype == 2U && discriminator == 0U;
            if (in_range(tag, 0x2b2U, 3U))
                return subtype == 2U && discriminator == 2U;
            if (tag == 0x2b7U)
                return subtype == 5U;
            if (in_range(tag, 0x2baU, 7U))
                return subtype == 1U;
            if (in_range(tag, 0x2c3U, 4U))
                return subtype == 4U;
            if (in_range(tag, 0x2c9U, 6U))
                return ((0x23U >> (tag - 0x2c9U)) & 1U) != 0U;
            return false;
        }
        if (object_class == 3U)
            return in_range(tag, 2U, 0x12U);
        if (object_class != 4U)
            return false;
        if (in_range(tag, 0x215U, 5U) || in_range(tag, 0x17U, 3U))
            return true;
        if (in_range(tag, 0x1cU, 0x29U))
            return subtype == 8U;
        if (in_range(tag, 0x47U, 2U))
            return subtype == 5U;
        if (in_range(tag, 0x4bU, 2U))
            return subtype == 0x0bU;
        if (in_range(tag, 0x4fU, 5U))
            return subtype == 0x0dU;
        if (in_range(tag, 0x56U, 6U))
            return subtype == 0x0eU;
        if (in_range(tag, 0x5eU, 4U))
            return subtype == 0x0fU;
        if (in_range(tag, 0x64U, 6U))
            return subtype == 0x10U;
        if ((tag & ~3U) == 0x6cU)
            return subtype == 0x11U;
        if (in_range(tag, 0x72U, 6U))
            return subtype == 0x12U;
        if (in_range(tag, 0x7aU, 8U))
            return subtype == 0x13U;
        if (in_range(tag, 0x84U, 7U))
            return subtype == 0x14U;
        if (in_range(tag, 0x8dU, 8U))
            return subtype == 0x15U;
        if (in_range(tag, 0x97U, 8U))
            return subtype == 0x34U;
        if (in_range(tag, 0xa1U, 0x11U))
            return subtype == 0x16U;
        if (in_range(tag, 0xb4U, 0x0cU))
            return subtype == 0x17U;
        if (in_range(tag, 0xc2U, 10U))
            return subtype == 0x18U;
        if (in_range(tag, 0xceU, 7U))
            return subtype == 0x19U;
        if (in_range(tag, 0xd7U, 4U))
            return subtype == 0x35U;
        if (in_range(tag, 0xddU, 5U))
            return subtype == 0x36U;
        if (in_range(tag, 0xe4U, 0x0bU))
            return subtype == 0x37U;
        if (in_range(tag, 0xf1U, 10U))
            return subtype == 0x1aU;
        if (in_range(tag, 0xfdU, 6U))
            return subtype == 0x1bU;
        if (tag == 0x105U)
            return subtype == 0x1cU;
        if ((tag & ~3U) == 0x108U)
            return subtype == 0x1dU;
        if (in_range(tag, 0x10eU, 4U))
            return subtype == 9U;
        if ((tag & ~1U) == 0x114U)
            return subtype == 10U;
        if (tag == 0x118U)
            return subtype == 7U;
        if (in_range(tag, 0x11bU, 4U))
            return subtype == 2U;
        if (in_range(tag, 0x121U, 3U))
            return subtype == 0x1eU;
        if (in_range(tag, 0x126U, 8U))
            return subtype == 0x1fU;
        if (in_range(tag, 0x130U, 3U))
            return subtype == 0x20U;
        if (in_range(tag, 0x135U, 7U))
            return subtype == 0x21U;
        if (in_range(tag, 0x13eU, 0x0cU))
            return subtype == 0x22U;
        if (in_range(tag, 0x14cU, 6U))
            return subtype == 0x23U;
        if ((tag & ~1U) == 0x154U)
            return subtype == 3U;
        if (in_range(tag, 0x158U, 7U))
            return subtype == 6U;
        if (in_range(tag, 0x161U, 3U))
            return subtype == 0x2aU;
        if (in_range(tag, 0x166U, 7U))
            return subtype == 0x29U;
        if (in_range(tag, 0x16fU, 9U))
            return subtype == 0x24U;
        if (in_range(tag, 0x17aU, 10U))
            return subtype == 0x25U;
        if (in_range(tag, 0x186U, 0x0dU))
            return subtype == 0x26U;
        if (in_range(tag, 0x195U, 7U))
            return subtype == 0x27U;
        if (in_range(tag, 0x19eU, 7U))
            return subtype == 0x2bU;
        if (in_range(tag, 0x1a7U, 10U))
            return subtype == 0x28U;
        if (in_range(tag, 0x1b3U, 0x23U))
            return subtype == 0x0cU;
        if (in_range(tag, 0x1d8U, 3U))
            return subtype == 0x2cU;
        if (in_range(tag, 0x1ddU, 4U))
            return subtype == 0x2dU;
        if (in_range(tag, 0x1e9U, 3U))
            return subtype == 0x2fU;
        if ((tag & ~1U) == 0x1eeU)
            return subtype == 0x30U;
        if (in_range(tag, 0x1f2U, 6U))
            return subtype == 0x31U;
        if (in_range(tag, 0x1faU, 4U))
            return subtype == 0x32U;
        if ((tag & ~3U) == 0x200U)
            return subtype == 0x33U;
        if (in_range(tag, 0x206U, 0x0bU))
            return subtype == 0x38U;
        if (in_range(tag, 0x21cU, 3U))
            return subtype == 0x3dU;
        if (in_range(tag, 0x221U, 5U))
            return subtype == 0x3cU;
        if ((tag & ~3U) == 0x228U)
            return subtype == 0x3bU;
        if ((tag & ~1U) == 0x22eU)
            return subtype == 0x47U;
        if (in_range(tag, 0x232U, 5U))
            return subtype == 0x3eU;
        if (in_range(tag, 0x239U, 9U))
            return subtype == 0x3fU;
        if (in_range(tag, 0x244U, 0x0bU))
            return subtype == 0x41U;
        if (in_range(tag, 0x251U, 0x17U))
            return subtype == 0x42U;
        if (in_range(tag, 0x26aU, 6U))
            return subtype == 0x44U;
        if (in_range(tag, 0x272U, 10U))
            return subtype == 0x45U;
        if (in_range(tag, 0x27eU, 5U))
            return subtype == 0x40U;
        if (in_range(tag, 0x285U, 4U))
            return subtype == 0x43U;
        if (in_range(tag, 0x28bU, 7U))
            return subtype == 0x46U;
        return false;
    };
    const auto effect_descriptor =
            [](const K2EffectSemantic &effect) -> std::optional<std::uint32_t> {
        if (!effect.internal_type || *effect.internal_type == 0U)
            return std::nullopt;
        auto descriptor = 0x40000U | (*effect.internal_type << 8U);
        if (*effect.internal_type == 8U) {
            if (!effect.filter_type)
                return std::nullopt;
            descriptor |= static_cast<std::uint32_t>(*effect.filter_type);
        }
        return descriptor;
    };
    const auto internal_descriptor = [](const K2InternalModSemantic &modulator)
            -> std::optional<std::uint32_t> {
        if (!modulator.kind)
            return std::nullopt;
        const auto kind = static_cast<std::uint32_t>(*modulator.kind);
        std::uint32_t discriminator{};
        if (*modulator.kind == K2InternalModSemantic::Kind::envelope) {
            if (!modulator.envelope || !modulator.envelope->type)
                return std::nullopt;
            discriminator =
                    static_cast<std::uint32_t>(*modulator.envelope->type);
        } else if (*modulator.kind == K2InternalModSemantic::Kind::glide &&
                   modulator.glide && modulator.glide->type) {
            discriminator = static_cast<std::uint32_t>(*modulator.glide->type);
        }
        return 0x10000U | (kind << 8U) | discriminator;
    };

    data.effective_automation = data.automation;
    data.purged_automation.clear();
    for (auto iterator = data.effective_automation.begin();
            iterator != data.effective_automation.end();) {
        const auto tag = iterator->parameter_tag_id.value_or(0U);
        bool valid = tag != 0U;
        if (iterator->group_ordinal < 0) {
            if (valid && (in_range(tag, 0x16U, 0x1fcU) ||
                                 in_range(tag, 0x214U, 0x7fU))) {
                const auto selector =
                        iterator->effective_program_object_selector.value_or(
                                -1);
                valid = iterator->object_index &&
                        *iterator->object_index >= 0 &&
                        *iterator->object_index < 8 &&
                        (selector == 0 || selector == 1);
                const auto effect =
                        valid ? std::find_if(data.effects.begin(),
                                        data.effects.end(),
                                        [&](const K2EffectSemantic &value) {
                                            return value.program_ordinal ==
                                                           iterator->program_ordinal &&
                                                   value.group_ordinal < 0 &&
                                                   value.program_object_selector ==
                                                           selector &&
                                                   value.serialized_index ==
                                                           iterator->object_index;
                                        })
                              : data.effects.end();
                const auto descriptor = effect == data.effects.end()
                                                ? std::optional<std::uint32_t>{}
                                                : effect_descriptor(*effect);
                valid = descriptor &&
                        parameter_matches_object(tag, *descriptor);
            } else if (valid && (tag == 0x29bU || tag == 0x29cU)) {
                const auto selector =
                        iterator->effective_program_object_selector.value_or(
                                -1);
                valid = selector >= 3 && selector <= 18;
            }
        } else if (valid && in_range(tag, 0x16U, 0x1fcU)) {
            valid = iterator->object_index && *iterator->object_index >= 0 &&
                    *iterator->object_index < 8;
            const auto effect =
                    valid ? std::find_if(data.effects.begin(),
                                    data.effects.end(),
                                    [&](const K2EffectSemantic &value) {
                                        return value.program_ordinal ==
                                                       iterator->program_ordinal &&
                                               value.group_ordinal ==
                                                       iterator->group_ordinal &&
                                               value.serialized_index ==
                                                       iterator->object_index;
                                    })
                          : data.effects.end();
            const auto descriptor = effect == data.effects.end()
                                            ? std::optional<std::uint32_t>{}
                                            : effect_descriptor(*effect);
            valid = descriptor && parameter_matches_object(tag, *descriptor);
        } else if (valid && in_range(tag, 0x2a8U, 0x24U)) {
            valid = iterator->object_index && *iterator->object_index >= 0 &&
                    *iterator->object_index < 16;
            const auto modulator =
                    valid ? std::find_if(data.internal_modulators.begin(),
                                    data.internal_modulators.end(),
                                    [&](const K2InternalModSemantic &value) {
                                        return value.program_ordinal ==
                                                       iterator->program_ordinal &&
                                               value.group_ordinal ==
                                                       iterator->group_ordinal &&
                                               value.serialized_index ==
                                                       iterator->object_index;
                                    })
                          : data.internal_modulators.end();
            const auto descriptor = modulator == data.internal_modulators.end()
                                            ? std::optional<std::uint32_t>{}
                                            : internal_descriptor(*modulator);
            const auto has_target =
                    modulator != data.internal_modulators.end() &&
                    std::any_of(modulator->targets.begin(),
                            modulator->targets.end(),
                            [](const K2ModTargetSemantic &target) {
                                return target.target_id.value_or(0U) != 0U;
                            });
            valid = has_target && descriptor &&
                    parameter_matches_object(tag, *descriptor);
        } else if (valid && in_range(tag, 2U, 0x12U)) {
            valid = parameter_matches_object(tag, 0x30000U);
        }
        if (valid) {
            ++iterator;
        } else {
            data.purged_automation.push_back(*iterator);
            iterator = data.effective_automation.erase(iterator);
        }
    }
}

} // namespace libnki::detail
