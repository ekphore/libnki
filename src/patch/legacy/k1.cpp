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

namespace libnki::detail::k1 {
namespace {

const std::string *k1_attribute(
        const K1TagElement &element, std::string_view name) {
    const auto found = std::find_if(element.attributes.begin(),
            element.attributes.end(), [name](const K1TagAttribute &attribute) {
                return attribute.name == name;
            });
    return found == element.attributes.end() ? nullptr : &found->value;
}

std::optional<std::uint32_t> k1_mod_target_id(std::string_view name) {
    static constexpr auto direct =
            std::to_array<std::pair<std::string_view, std::uint32_t>>({
                    { "volume", 2 },
                    { "pan", 3 },
                    { "pitch", 6 },
                    { "filterCutoff", 0x1f },
                    { "filterQ", 0x20 },
                    { "filterBandwidth", 0x23 },
                    { "formantTalk", 0x24 },
                    { "formantSize", 0x25 },
                    { "formantSharp", 0x26 },
                    { "formantShift", 0x11 },
                    { "overlap", 0x12 },
                    { "warpFactor", 0x0b },
                    { "warpFactor2", 0x0c },
                    { "wavetablePosition", 0x0d },
                    { "wavetableInharmonic", 0x0e },
                    { "wavetableModAmount", 0x0f },
                    { "wavetableModFrequency", 0x10 },
                    { "cutoffLP", 0x37 },
                    { "cutoffHP", 0x38 },
                    { "resoLP", 0x39 },
                    { "resoHP", 0x3a },
                    { "filterFeedback", 0x22 },
                    { "filterFM", 0x21 },
                    { "grainSize", 0x13 },
                    { "grainSpeed", 0x15 },
                    { "loopStart", 7 },
                    { "loopLength", 8 },
                    { "intensity", 0x19 },
                    { "frequency", 0x1a },
                    { "pulseWidth", 0x1b },
                    { "startPhase", 0xb4 },
                    { "eqFreq1", 0x28 },
                    { "eqBandWidth1", 0x29 },
                    { "eqGain1", 0x2a },
                    { "eqFreq2", 0x2b },
                    { "eqBandWidth2", 0x2c },
                    { "eqGain2", 0x2d },
                    { "eqFreq3", 0x2e },
                    { "eqBandWidth3", 0x2f },
                    { "eqGain3", 0x30 },
                    { "vfShift", 0x33 },
                    { "vfType", 0x34 },
                    { "vfBypass", 0x35 },
                    { "distortionIntensity", 0x40 },
                    { "stereoSpreadIntensity", 0x5e },
                    { "stereoPan", 0x5f },
                    { "shaper", 0x62 },
                    { "bitdepth", 0x65 },
                    { "downsample", 0x66 },
                    { "noiselevel", 0x67 },
                    { "noisecolor", 0x68 },
                    { "playPos", 0xb0 },
                    { "playDirection", 0xb1 },
                    { "ahdsr_attack", 0xb8 },
                    { "ahdsr_hold", 0xb9 },
                    { "ahdsr_decay", 0xba },
                    { "ahdsr_sustain", 0xbd },
                    { "ahdsr_release", 0xbb },
                    { "dbd_decay1", 0xbf },
                    { "dbd_break", 0xc2 },
                    { "dbd_decay2", 0xc0 },
            });
    const auto found = std::find_if(direct.begin(), direct.end(),
            [&](const auto &entry) { return entry.first == name; });
    if (found != direct.end())
        return found->second;
    const auto decimal_suffix =
            [&](std::string_view prefix) -> std::optional<unsigned> {
        if (!name.starts_with(prefix) || name.size() == prefix.size())
            return std::nullopt;
        unsigned value{};
        for (const char character : name.substr(prefix.size())) {
            if (character < '0' || character > '9')
                return std::nullopt;
            value = value * 10U + static_cast<unsigned>(character - '0');
        }
        return value;
    };
    if (const auto index = decimal_suffix("sendLevel"); index && *index <= 7)
        return 0x71U + *index;
    if (name.starts_with("scLevelB") && name.size() == 10) {
        const auto tens = name[8] - '0';
        const auto ones = name[9] - '0';
        if (tens >= 0 && tens <= 9 && ones >= 0 && ones <= 9 &&
                tens * 10 + ones <= 15)
            return 0x79U + static_cast<unsigned>(tens * 10 + ones);
    }
    if (name == "scLevelPGM")
        return 0x89U;
    if (name == "sendLevelDelay")
        return 0x71U;
    if (name == "sendLevelChorus")
        return 0x72U;
    if (name == "sendLevelFlanger")
        return 0x73U;
    if (name == "sendLevelPhaser")
        return 0x74U;
    if (name == "sendLevelReverb")
        return 0x75U;
    if (const auto index = decimal_suffix("arp32step_v");
            index && *index >= 1 && *index <= 32)
        return 0x8cU + *index;
    for (const auto &[prefix, base] :
            std::to_array<std::pair<std::string_view, unsigned>>(
                    { { "fm7_level", 0xc3 }, { "fm7_time", 0xcd },
                            { "fm7_slope", 0xd7 } })) {
        if (const auto index = decimal_suffix(prefix);
                index && *index >= 1 && *index <= 8)
            return base + *index;
    }
    if (name == "intensity_nc" || name == "intensity_upper")
        return 0x19U;
    return std::nullopt;
}

std::optional<std::uint16_t> parse_k1_dotted_version(const std::string &value) {
    unsigned short major{};
    unsigned short minor{};
    if (std::sscanf(value.c_str(), "%hx.%hx", &major, &minor) != 2) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(minor | (major << 8U));
}

K1ZoneParameters parse_k1_zone_parameters(
        const K1TagElement &zone, const K1TagElement &parameters) {
    K1ZoneParameters out;
    if (const auto *version = k1_attribute(zone, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    const auto as_i16 = [](const std::string &value) {
        return static_cast<std::int16_t>(std::atoi(value.c_str()));
    };
    const auto as_i32 = [](const std::string &value) {
        return static_cast<std::int32_t>(std::atoi(value.c_str()));
    };
    const auto as_float = [](const std::string &value) {
        return static_cast<float>(std::atof(value.c_str()));
    };
    for (const auto &value_tag : parameters.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "lowKey")
            out.low_key = as_i16(*value);
        else if (*name == "highKey")
            out.high_key = as_i16(*value);
        else if (*name == "lowVelocity")
            out.low_velocity = as_i16(*value);
        else if (*name == "highVelocity")
            out.high_velocity = as_i16(*value);
        else if (*name == "fadeLowKey")
            out.fade_low_key = as_i16(*value);
        else if (*name == "fadeHighKey")
            out.fade_high_key = as_i16(*value);
        else if (*name == "fadeLowVelo")
            out.fade_low_velocity = as_i16(*value);
        else if (*name == "fadeHighVelo")
            out.fade_high_velocity = as_i16(*value);
        else if (*name == "rootKey")
            out.root_key = as_i16(*value);
        else if (*name == "zoneVolume")
            out.volume = as_float(*value);
        else if (*name == "zonePan")
            out.pan = as_float(*value);
        else if (*name == "zoneTune")
            out.tune = as_float(*value);
        else if (*name == "sampleStart")
            out.sample_start = as_i32(*value);
        else if (*name == "sampleEnd")
            out.sample_end = as_i32(*value);
        else if (*name == "slicerSens")
            out.slicer_sensitivity = as_float(*value);
        else if (*name == "isReferenceZone")
            out.reference_zone = *value == "yes";
    }

    // old pan values need centering; inverted ranges collapse to their upper
    // bound
    if (out.pan && out.struct_version < 0x70U)
        *out.pan = *out.pan * 2.0F - 1.0F;
    if (out.low_velocity)
        *out.low_velocity = std::max<std::int16_t>(*out.low_velocity, 1);
    if (out.high_velocity)
        *out.high_velocity = std::min<std::int16_t>(*out.high_velocity, 0x7f);
    if (out.low_velocity && out.high_velocity &&
            *out.high_velocity < *out.low_velocity) {
        *out.low_velocity = *out.high_velocity;
    }
    if (out.low_key)
        *out.low_key = std::max<std::int16_t>(*out.low_key, 0);
    if (out.high_key)
        *out.high_key = std::min<std::int16_t>(*out.high_key, 0x7f);
    if (out.low_key && out.high_key && *out.high_key < *out.low_key) {
        *out.low_key = *out.high_key;
    }
    if (out.root_key) {
        *out.root_key = std::clamp<std::int16_t>(*out.root_key, 0, 0x7f);
    }
    if (out.sample_start)
        *out.sample_start = std::max<std::int32_t>(*out.sample_start, 0);
    if (out.sample_end && *out.sample_end >= 0)
        *out.sample_end = 0;
    return out;
}

K1SampleSemantic parse_k1_sample(const K1TagElement &sample) {
    K1SampleSemantic out;
    for (const auto &value_tag : sample.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "file") {
            out.path = *value;
            out.path_encoding = K1SamplePathEncoding::old_style;
        } else if (*name == "file_ex") {
            out.path = *value;
            out.path_encoding = K1SamplePathEncoding::new_style_file_ex;
        } else if (*name == "file_ex2") {
            out.path = *value;
            out.path_encoding = K1SamplePathEncoding::new_style_file_ex2;
        } else if (name->starts_with("slice_")) {
            K1SampleSlice slice;
            slice.index = std::atoi(name->c_str() + 6);
            std::size_t separator = 0;
            while (separator < value->size() && (*value)[separator] >= '0' &&
                    (*value)[separator] <= '9') {
                ++separator;
            }
            slice.start = std::atoi(value->substr(0, separator).c_str());
            if (separator < value->size())
                ++separator;
            slice.end = std::atoi(value->substr(separator).c_str());
            out.slices.push_back(slice);
        }
    }
    return out;
}

K1LoopSemantic parse_k1_loop(const K1TagElement &loop) {
    K1LoopSemantic out;
    if (const auto *version = k1_attribute(loop, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    if (const auto *index = k1_attribute(loop, "index")) {
        out.index = static_cast<std::int32_t>(std::atoi(index->c_str()));
    }
    for (const auto &value_tag : loop.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "loopStart") {
            out.start = std::atoi(value->c_str());
            out.serialized_start = out.start;
        } else if (*name == "loopLength") {
            out.length = std::atoi(value->c_str());
            out.serialized_length = out.length;
        } else if (*name == "loopCount")
            out.count = std::atoi(value->c_str());
        else if (*name == "xfadeLength")
            out.crossfade_length = std::atoi(value->c_str());
        else if (*name == "alternatingLoop")
            out.alternating = *value == "yes";
        else if (*name == "loopTuning")
            out.tuning = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "mode") {
            if (*value == "until_end")
                out.mode = K1LoopMode::until_end;
            else if (*value == "until_release")
                out.mode = K1LoopMode::until_release;
            else if (*value == "oneshot")
                out.mode = K1LoopMode::oneshot;
        }
    }
    return out;
}

K1ModulatorSemantic parse_k1_modulator(
        const K1TagElement &element, K1ModulatorClass modulator_class) {
    K1ModulatorSemantic out;
    out.modulator_class = modulator_class;
    out.attributes = element.attributes;
    if (const auto *index = k1_attribute(element, "index")) {
        const auto parsed = std::atoi(index->c_str());
        const auto limit =
                modulator_class == K1ModulatorClass::internal ? 16 : 64;
        if (parsed < 0 || parsed >= limit) {
            throw std::runtime_error("K1 modulator index is out of range");
        }
        out.index = static_cast<std::uint8_t>(parsed);
    }
    if (const auto *version = k1_attribute(element, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    if (modulator_class == K1ModulatorClass::internal) {
        const auto subtype = std::find_if(element.children.begin(),
                element.children.end(), [](const K1TagElement &child) {
                    return child.name == "LFO" || child.name == "Envelope" ||
                           child.name == "Arpegg" ||
                           child.name == "EnvFollow" || child.name == "Glide" ||
                           child.name == "XSync";
                });
        if (subtype != element.children.end()) {
            out.internal_type = subtype->name;
            if (const auto *version = k1_attribute(*subtype, "version")) {
                out.subtype_version = parse_k1_dotted_version(*version);
            }
        } else if (const auto *type = k1_attribute(element, "type"))
            out.internal_type = *type;
        out.internal_parameters.emplace();
        if (out.internal_type == "LFO") {
            out.lfo.emplace();
            const auto *waveform = subtype != element.children.end()
                                           ? k1_attribute(*subtype, "type")
                                           : k1_attribute(element, "name");
            if (waveform != nullptr) {
                if (*waveform == "sine")
                    out.lfo->waveform = K1LfoWaveform::sine;
                else if (*waveform == "rectangle")
                    out.lfo->waveform = K1LfoWaveform::rectangle;
                else if (*waveform == "triangle")
                    out.lfo->waveform = K1LfoWaveform::triangle;
                else if (*waveform == "sawtooth")
                    out.lfo->waveform = K1LfoWaveform::sawtooth;
                else if (*waveform == "random")
                    out.lfo->waveform = K1LfoWaveform::random;
                else if (*waveform == "multi")
                    out.lfo->waveform = K1LfoWaveform::multi;
            }
        } else if (out.internal_type == "Envelope") {
            out.envelope.emplace();
            const auto *envelope_type = subtype != element.children.end()
                                                ? k1_attribute(*subtype, "type")
                                                : k1_attribute(element, "name");
            if (envelope_type != nullptr) {
                if (*envelope_type == "ahdsr")
                    out.envelope->type = K1EnvelopeType::ahdsr;
                else if (*envelope_type == "fm7")
                    out.envelope->type = K1EnvelopeType::fm7;
                else if (*envelope_type == "dbd")
                    out.envelope->type = K1EnvelopeType::dbd;
            }
        } else if (out.internal_type == "EnvFollow") {
            out.envelope_follower.emplace();
        } else if (out.internal_type == "Arpegg") {
            out.arpeggiator.emplace();
            const auto *arpeggiator_type =
                    subtype != element.children.end()
                            ? k1_attribute(*subtype, "type")
                            : k1_attribute(element, "name");
            if (arpeggiator_type != nullptr) {
                out.arpeggiator->is_32_step = *arpeggiator_type == "_32step";
            }
        } else if (out.internal_type == "Glide") {
            out.glide.emplace();
            const auto *glide_type = subtype != element.children.end()
                                             ? k1_attribute(*subtype, "type")
                                             : k1_attribute(element, "name");
            if (glide_type != nullptr) {
                if (*glide_type == "speed")
                    out.glide->mode = K1GlideMode::speed;
                else if (*glide_type == "time")
                    out.glide->mode = K1GlideMode::time;
            }
        }
    } else if (modulator_class == K1ModulatorClass::external) {
        out.external_parameters.emplace();
    }
    std::vector<const K1TagElement *> value_tags;
    const auto collect_values = [&](const auto &self,
                                        const K1TagElement &parent) -> void {
        for (const auto &child : parent.children) {
            if (child.name == "V")
                value_tags.push_back(&child);
            else
                self(self, child);
        }
    };
    collect_values(collect_values, element);

    std::array<K1ModulationTarget, 16> targets{};
    for (std::size_t i = 0; i < targets.size(); ++i)
        targets[i].index = i;
    std::size_t last_target = 0;
    bool any = false;
    const auto indexed_name =
            [](std::string_view name,
                    std::string_view prefix) -> std::optional<std::size_t> {
        if (name.size() < prefix.size())
            return std::nullopt;
        for (std::size_t i = 0; i < prefix.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(name[i])) !=
                    std::tolower(static_cast<unsigned char>(prefix[i])))
                return std::nullopt;
        }
        const auto index =
                std::atoi(std::string(name.substr(prefix.size())).c_str());
        if (index < 0 || index >= 16) {
            throw std::runtime_error(
                    "K1 modulation target index is out of range");
        }
        return static_cast<std::size_t>(index);
    };
    for (const auto *value_tag : value_tags) {
        const auto *name = k1_attribute(*value_tag, "name");
        const auto *value = k1_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (out.internal_parameters) {
            auto &internal = *out.internal_parameters;
            if (*name == "frequency")
                internal.frequency =
                        static_cast<float>(std::atof(value->c_str()));
            else if (*name == "pulseWidth")
                internal.pulse_width =
                        static_cast<float>(std::atof(value->c_str()));
            else if (*name == "noteValue_frequency") {
                internal.note_value_frequency =
                        static_cast<float>(std::atof(value->c_str()));
            } else if (*name == "retrigger")
                internal.retrigger = *value == "yes";
            else if (*name == "bypass")
                internal.bypass = *value == "yes";
            else if (*name == "modIdx" && out.internal_type == "XSync") {
                internal.x_sync_mod_index = std::atoi(value->c_str());
            }
        }
        if (out.lfo) {
            auto &lfo = *out.lfo;
            const auto real = [&] {
                return static_cast<float>(std::atof(value->c_str()));
            };
            if (*name == "delay")
                lfo.delay = real();
            else if (*name == "noteValue_delay")
                lfo.note_value_delay = real();
            else if (lfo.waveform == K1LfoWaveform::multi) {
                if (*name == "levelSine")
                    lfo.level_sine = real();
                else if (*name == "levelRectangle")
                    lfo.level_rectangle = real();
                else if (*name == "levelTriangle")
                    lfo.level_triangle = real();
                else if (*name == "levelSawtooth")
                    lfo.level_sawtooth = real();
                else if (*name == "levelRandom")
                    lfo.level_random = real();
            }
        }
        if (out.external_parameters) {
            auto &external = *out.external_parameters;
            if (*name == "ccNumber") {
                external.cc_number =
                        static_cast<std::int8_t>(std::atoi(value->c_str()));
            } else if (*name == "delay") {
                external.delay = static_cast<float>(std::atof(value->c_str()));
            } else if (*name == "bypass") {
                external.bypass = *value == "yes";
            } else if (*name == "source") {
                if (*value == "pitchBend")
                    external.source = K1ExternalModSource::pitch_bend;
                else if (*value == "polyAfterTouch")
                    external.source = K1ExternalModSource::poly_aftertouch;
                else if (*value == "monoAfterTouch")
                    external.source = K1ExternalModSource::mono_aftertouch;
                else if (*value == "midiCC")
                    external.source = K1ExternalModSource::midi_cc;
                else if (*value == "velocity")
                    external.source = K1ExternalModSource::velocity;
                else if (*value == "keyPos")
                    external.source = K1ExternalModSource::key_position;
                else if (*value == "releaseVelocity")
                    external.source = K1ExternalModSource::release_velocity;
                else if (*value == "rlsTrigCounter") {
                    external.source =
                            K1ExternalModSource::release_trigger_counter;
                }
            }
        }
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        if (out.envelope) {
            auto &envelope = *out.envelope;
            if (envelope.type == K1EnvelopeType::ahdsr) {
                if (*name == "attack")
                    envelope.attack = real();
                else if (*name == "hold")
                    envelope.hold = real();
                else if (*name == "decay")
                    envelope.decay = real();
                else if (*name == "sustain")
                    envelope.sustain = real();
                else if (*name == "release")
                    envelope.release = real();
                else if (*name == "atkCurving")
                    envelope.attack_curving = real();
                else if (*name == "noteOffLessMode")
                    envelope.note_off_less_mode = *value == "yes";
                else if (*name == "notevalue_attack")
                    envelope.note_value_attack = real();
                else if (*name == "notevalue_hold")
                    envelope.note_value_hold = real();
                else if (*name == "notevalue_decay")
                    envelope.note_value_decay = real();
                else if (*name == "notevalue_release")
                    envelope.note_value_release = real();
            } else if (envelope.type == K1EnvelopeType::dbd) {
                if (*name == "break")
                    envelope.break_level = real();
                else if (*name == "decay1")
                    envelope.decay1 = real();
                else if (*name == "decay2")
                    envelope.decay2 = real();
                else if (*name == "notevalue_decay1")
                    envelope.note_value_decay1 = real();
                else if (*name == "notevalue_decay2")
                    envelope.note_value_decay2 = real();
            } else if (envelope.type == K1EnvelopeType::fm7) {
                if (*name == "loopStart")
                    envelope.loop_start = std::atoi(value->c_str());
                else if (*name == "loopEnd")
                    envelope.loop_end = std::atoi(value->c_str());
                else if (*name == "releaseEnd")
                    envelope.release_end = std::atoi(value->c_str());
                else if (*name == "loopEnabled")
                    envelope.loop_enabled = *value == "yes";
                else if (*name == "oneshotMode")
                    envelope.oneshot_mode = *value == "yes";
                else if (*name == "notevalue_grid")
                    envelope.note_value_grid = real();
                else {
                    const auto array_value = [&](std::string_view prefix,
                                                     auto &destination) {
                        if (!name->starts_with(prefix))
                            return false;
                        const auto suffix =
                                std::string_view(*name).substr(prefix.size());
                        if (suffix.empty() || !std::all_of(suffix.begin(),
                                                      suffix.end(), [](char c) {
                                                          return c >= '0' &&
                                                                 c <= '9';
                                                      }))
                            return false;
                        const auto index = static_cast<std::size_t>(
                                std::atoi(std::string(suffix).c_str()));
                        if (index >= destination.size())
                            return false;
                        destination[index] = real();
                        return true;
                    };
                    if (!array_value("time", envelope.times) &&
                            !array_value("level", envelope.levels)) {
                        (void)array_value("slope", envelope.slopes);
                    }
                }
            }
        }
        if (out.envelope_follower) {
            auto &follower = *out.envelope_follower;
            if (*name == "attack")
                follower.attack = real();
            else if (*name == "decay")
                follower.decay = real();
            else if (*name == "gain")
                follower.gain = real();
            else if (*name == "adaptionSpeed")
                follower.adaptation_speed = real();
        }
        if (out.arpeggiator && out.arpeggiator->is_32_step) {
            auto &arpeggiator = *out.arpeggiator;
            if (*name == "numSteps")
                arpeggiator.number_of_steps = std::atoi(value->c_str());
            else if (*name == "singleTrigger")
                arpeggiator.single_trigger = *value == "yes";
            else if (name->starts_with("step_")) {
                const auto suffix = std::string_view(*name).substr(5);
                if (!suffix.empty() &&
                        std::all_of(suffix.begin(), suffix.end(),
                                [](char c) { return c >= '0' && c <= '9'; })) {
                    const auto index = static_cast<std::size_t>(
                            std::atoi(std::string(suffix).c_str()));
                    if (index < arpeggiator.steps.size())
                        arpeggiator.steps[index] = real();
                }
            }
        }
        if (out.glide) {
            if (*name == "coef")
                out.glide->coefficient = real();
            else if (*name == "notevalue_coef")
                out.glide->note_value_coefficient = real();
        }
        std::optional<std::size_t> index;
        enum class Field {
            none,
            target,
            intensity,
            target_mod_index,
            slot_index
        } field{};
        if (*name == "target") {
            index = 0;
            field = Field::target;
        } else if (*name == "intensity") {
            index = 0;
            field = Field::intensity;
        } else if (*name == "targetModIdx") {
            index = 0;
            field = Field::target_mod_index;
        } else if (*name == "slotIdx") {
            index = 0;
            field = Field::slot_index;
        } else if ((index = indexed_name(*name, "target_")))
            field = Field::target;
        else if ((index = indexed_name(*name, "intensity_")))
            field = Field::intensity;
        else if ((index = indexed_name(*name, "targetModIdx_")))
            field = Field::target_mod_index;
        else if ((index = indexed_name(*name, "slotIdx_")))
            field = Field::slot_index;
        if (!index)
            continue;
        any = true;
        last_target = std::max(last_target, *index);
        auto &target = targets[*index];
        if (field == Field::target) {
            target.xml_target = *value;
            target.target_id = k1_mod_target_id(*value);
        } else if (field == Field::intensity) {
            target.intensity = static_cast<float>(std::atof(value->c_str()));
        } else if (field == Field::target_mod_index) {
            target.target_mod_index =
                    static_cast<std::int8_t>(std::atoi(value->c_str()));
        } else if (field == Field::slot_index) {
            target.slot_index =
                    static_cast<std::int16_t>(std::atoi(value->c_str()));
        }
    }
    out.target_count = static_cast<std::uint8_t>(last_target + 1);
    if (any) {
        out.targets.assign(targets.begin(), targets.begin() + out.target_count);
        for (auto &target : out.targets) {
            if (target.intensity && *target.intensity < 0.0F) {
                *target.intensity = -*target.intensity;
                target.negative_intensity = true;
            }
        }
    }
    if (out.external_parameters &&
            out.external_parameters->source == K1ExternalModSource::midi_cc &&
            out.external_parameters->cc_number) {
        switch (*out.external_parameters->cc_number) {
            case -127:
                out.external_parameters->source =
                        K1ExternalModSource::legacy_cc_source_12;
                out.external_parameters->cc_number = 0;
                break;
            case -126:
                out.external_parameters->source =
                        K1ExternalModSource::legacy_cc_source_13;
                out.external_parameters->cc_number = 0;
                break;
            case -125:
                out.external_parameters->source =
                        K1ExternalModSource::legacy_cc_source_11;
                out.external_parameters->cc_number = 0;
                break;
            default:
                break;
        }
    }
    if (out.struct_version < 0x60U && out.arpeggiator &&
            out.targets.size() == 1 && out.targets[0].xml_target == "volume") {
        for (auto &step : out.arpeggiator->steps) {
            if (step)
                *step = -*step;
        }
        out.arpeggiator->pre_0x60_volume_steps_negated = true;
    }
    if (out.envelope && out.envelope->type == K1EnvelopeType::ahdsr &&
            out.envelope->note_off_less_mode == true && out.envelope->sustain &&
            out.envelope->hold && out.envelope->decay) {
        const auto shaped = *out.envelope->sustain * 2.0F - 1.0F;
        const auto up = shaped + 1.0F;
        const auto down = 1.0F - shaped;
        auto curve = up * up * up - 1.0F;
        if (shaped >= 0.0F)
            curve = 1.0F - down * down * down;
        // clang-format off
        out.envelope->hold = std::min(*out.envelope->hold + (curve * 0.5F +
                0.5F) * *out.envelope->decay, 15000.0F);
        // clang-format on
    }
    const auto table_element = std::find_if(element.children.begin(),
            element.children.end(),
            [](const K1TagElement &child) { return child.name == "ModTable"; });
    if (table_element != element.children.end()) {
        K1ModulationTable table;
        for (std::size_t i = 0; i < table.values.size(); ++i) {
            table.values[i] = static_cast<float>(i) / 128.0F;
        }
        std::int32_t previous_index = -1;
        for (const auto &value_tag : table_element->children) {
            if (value_tag.name != "V")
                continue;
            const auto *name = k1_attribute(value_tag, "name");
            const auto *value = k1_attribute(value_tag, "value");
            if (name == nullptr || value == nullptr)
                continue;
            int parsed_index{};
            if (std::sscanf(name->c_str(), "t%d", &parsed_index) != 1)
                continue;
            const auto index =
                    static_cast<std::size_t>(std::clamp(parsed_index, 0, 127));
            table.values[index] = static_cast<float>(std::atof(value->c_str()));
            table.explicit_points[index] = true;
            if (previous_index >= 0 &&
                    previous_index + 1 != static_cast<std::int32_t>(index) &&
                    previous_index <= static_cast<std::int32_t>(index)) {
                const auto first = static_cast<std::size_t>(previous_index);
                const auto start = table.values[first];
                const auto step = (table.values[index] - start) /
                                  static_cast<float>(index - first);
                for (std::size_t cursor = first; cursor < index; ++cursor) {
                    table.values[cursor] =
                            start + step * static_cast<float>(cursor - first);
                }
            }
            previous_index = static_cast<std::int32_t>(index);
        }
        if (out.external_parameters && out.external_parameters->source) {
            const auto source = static_cast<std::uint32_t>(
                    *out.external_parameters->source);
            table.external_source_range_conversion =
                    source == 1U || source == 7U || source == 13U;
        }
        if (table.external_source_range_conversion) {
            for (auto &value : table.values)
                value = value * 0.5F + 0.5F;
        }
        out.modulation_table = std::move(table);
    }
    return out;
}

void collect_k1_modulators(const K1TagElement &element,
        std::vector<K1ModulatorSemantic> &modulators) {
    if (element.name == "NiSS_IntMod") {
        modulators.push_back(
                parse_k1_modulator(element, K1ModulatorClass::internal));
    } else if (element.name == "NiSS_ExtMod") {
        modulators.push_back(
                parse_k1_modulator(element, K1ModulatorClass::external));
    } else if (element.name == "NiSS_StatMod") {
        modulators.push_back(parse_k1_modulator(
                element, K1ModulatorClass::static_modulator));
    }
    for (const auto &child : element.children)
        collect_k1_modulators(child, modulators);
}

std::optional<K1EffectKind> k1_effect_kind(std::string_view name) {
    if (name == "Filter" || name == "FXFilter")
        return K1EffectKind::filter;
    if (name == "FXCompressor")
        return K1EffectKind::compressor;
    if (name == "FXInverter")
        return K1EffectKind::inverter;
    if (name == "FXLoFi")
        return K1EffectKind::lo_fi;
    if (name == "FXShaper")
        return K1EffectKind::shaper;
    if (name == "FXStereo")
        return K1EffectKind::stereo_spread;
    if (name == "FXDistortion")
        return K1EffectKind::distortion;
    if (name == "FXDelay")
        return K1EffectKind::delay;
    if (name == "FXChorus")
        return K1EffectKind::chorus;
    if (name == "FXFlanger")
        return K1EffectKind::flanger;
    if (name == "FXPhaser")
        return K1EffectKind::phaser;
    if (name == "FXReverb")
        return K1EffectKind::reverb;
    return std::nullopt;
}

K1EffectSemantic parse_k1_effect(
        const K1TagElement &element, K1EffectKind kind) {
    K1EffectSemantic out;
    out.kind = kind;
    out.attributes = element.attributes;
    if (const auto *version = k1_attribute(element, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    const auto &values = parameters == element.children.end()
                                 ? element.children
                                 : parameters->children;
    for (const auto &value_tag : values) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto yes = [&] { return *value == "yes"; };
        if (*name == "bypass")
            out.bypass = yes();
        else if (*name == "outLevel")
            out.output_level = real();
        else if (*name == "returnLevel")
            out.return_level = real();
        else if (*name == "executionOrder")
            out.execution_order = std::atoi(value->c_str());
        if (kind == K1EffectKind::filter) {
            if (*name == "type") {
                static constexpr auto types =
                        std::to_array<std::string_view>({ "lp1pole", "hp1pole",
                                "lp2pole", "hp2pole", "bp2pole", "lp4pole",
                                "hp4pole", "bp4pole", "br4pole", "lp6pole",
                                "phaser", "vowelA", "vowelB", "sampleAndHold",
                                "versatile", "eq1band", "eq2band", "eq3band" });
                if (std::find(types.begin(), types.end(), *value) !=
                        types.end())
                    out.type = *value;
            } else if (*name == "cutoff")
                out.cutoff = real();
            else if (*name == "resonance")
                out.resonance = real();
            else if (*name == "gain")
                out.gain = real();
            else if (*name == "bandWidth_1")
                out.band_width[0] = real();
            else if (*name == "bandWidth_2")
                out.band_width[1] = real();
            else if (*name == "bandWidth_3")
                out.band_width[2] = real();
            else if (*name == "freq_1")
                out.frequency[0] = real();
            else if (*name == "freq_2")
                out.frequency[1] = real();
            else if (*name == "freq_3")
                out.frequency[2] = real();
            else if (*name == "gain_1")
                out.band_gain[0] = real();
            else if (*name == "gain_2")
                out.band_gain[1] = real();
            else if (*name == "gain_3")
                out.band_gain[2] = real();
            else if (*name == "shiftB")
                out.shift[1] = real();
            else if (*name == "shiftC")
                out.shift[2] = real();
            else if (*name == "typeA")
                out.band_type[0] = real();
            else if (*name == "typeB")
                out.band_type[1] = real();
            else if (*name == "typeC")
                out.band_type[2] = real();
            else if (*name == "bypA")
                out.band_bypass[0] = real();
            else if (*name == "bypB")
                out.band_bypass[1] = real();
            else if (*name == "bypC")
                out.band_bypass[2] = real();
            else if (*name == "resB")
                out.band_resonance[1] = real();
            else if (*name == "resC")
                out.band_resonance[2] = real();
        } else if (kind == K1EffectKind::compressor) {
            if (*name == "threshold")
                out.threshold = real();
            else if (*name == "ratio")
                out.ratio = real();
            else if (*name == "attack")
                out.attack = real();
            else if (*name == "release")
                out.release = real();
            else if (*name == "stereoLink")
                out.stereo_link = yes();
            else if (*name == "model" &&
                     (*value == "classic" || *value == "enhanced")) {
                out.model = *value;
            }
        } else if (kind == K1EffectKind::inverter) {
            if (*name == "phase")
                out.phase = yes();
            else if (*name == "panorama")
                out.panorama = yes();
        } else if (kind == K1EffectKind::lo_fi) {
            if (*name == "bits")
                out.bits = real();
            else if (*name == "downSample") {
                out.down_sample_file_value = real();
                out.down_sample = real();
            } else if (*name == "noiseLevel")
                out.noise_level = real();
            else if (*name == "noiseColor")
                out.noise_color = real();
        } else if (kind == K1EffectKind::shaper && *name == "shape") {
            out.shape = real();
        } else if (kind == K1EffectKind::stereo_spread && *name == "spread") {
            out.spread = real();
        } else if (kind == K1EffectKind::distortion) {
            if (*name == "drive")
                out.drive = real();
            else if (*name == "damping")
                out.damping = real();
            else if (*name == "type" &&
                     (*value == "transistor" || *value == "tube")) {
                out.type = *value;
            }
        } else if (kind == K1EffectKind::delay) {
            if (*name == "time")
                out.time = real();
            else if (*name == "feedback")
                out.feedback = real();
            else if (*name == "panning")
                out.panning = real();
            else if (*name == "damping")
                out.damping = real();
            else if (*name == "noteValue_time")
                out.note_value_time = real();
        } else if (kind == K1EffectKind::chorus) {
            if (*name == "depth")
                out.depth = real();
            else if (*name == "speed")
                out.speed = real();
            else if (*name == "phase")
                out.phase_amount = real();
            else if (*name == "noteValue_speed")
                out.note_value_speed = real();
        } else if (kind == K1EffectKind::flanger) {
            if (*name == "depth")
                out.depth = real();
            else if (*name == "feedback")
                out.feedback = real();
            else if (*name == "speed")
                out.speed = real();
            else if (*name == "phase")
                out.phase_amount = real();
            else if (*name == "color")
                out.color = real();
            else if (*name == "noteValue_speed")
                out.note_value_speed = real();
        } else if (kind == K1EffectKind::phaser) {
            if (*name == "depth")
                out.depth = real();
            else if (*name == "feedback")
                out.feedback = real();
            else if (*name == "speed")
                out.speed = real();
            else if (*name == "phase")
                out.phase_amount = real();
            else if (*name == "noteValue_speed")
                out.note_value_speed = real();
        } else if (kind == K1EffectKind::reverb) {
            if (*name == "preDelay")
                out.pre_delay = real();
            else if (*name == "roomsize")
                out.room_size = real();
            else if (*name == "stereo")
                out.stereo = real();
            else if (*name == "color")
                out.color = real();
            else if (*name == "filter")
                out.filter_amount = real();
        }
    }
    if (kind == K1EffectKind::filter && out.type &&
            (*out.type == "eq1band" || *out.type == "eq2band" ||
                    *out.type == "eq3band")) {
        for (auto &value : out.band_gain) {
            if (value)
                *value = std::log2(*value) * 6.0F;
        }
    }
    if (kind == K1EffectKind::compressor && out.threshold) {
        *out.threshold = std::log2(*out.threshold) * 6.0F;
    }
    if (kind == K1EffectKind::lo_fi) {
        if (out.bits)
            *out.bits = std::min(
                    1.0F, *out.bits >= 1e-12F ? *out.bits / 16.0F : 1.0F);
        if (out.down_sample) {
            *out.down_sample = std::min(1.0F,
                    *out.down_sample >= 1e-12F ? *out.down_sample / 16000.0F
                                               : 1.0F);
        }
    }
    if (kind == K1EffectKind::shaper && out.shape)
        *out.shape *= 2.0F;
    if (kind == K1EffectKind::stereo_spread && out.spread &&
            out.struct_version < 0x70U) {
        *out.spread = *out.spread * 2.0F - 1.0F;
    }
    return out;
}

void collect_k1_effects(
        const K1TagElement &element, std::vector<K1EffectSemantic> &effects) {
    if (const auto kind = k1_effect_kind(element.name)) {
        effects.push_back(parse_k1_effect(element, *kind));
    }
    for (const auto &child : element.children)
        collect_k1_effects(child, effects);
}

// executionOrder is one-based; search from that slot for the first free FX slot
void assign_k1_effect_slots(std::vector<K1EffectSemantic> &effects) {
    std::array<bool, 8> occupied{};
    for (auto &effect : effects) {
        const auto execution_order =
                std::clamp(effect.execution_order.value_or(1), 1, 8);
        for (auto slot = static_cast<std::size_t>(execution_order - 1);
                slot < occupied.size(); ++slot) {
            if (occupied[slot])
                continue;
            occupied[slot] = true;
            effect.runtime_slot = static_cast<std::uint8_t>(slot);
            break;
        }
    }
}

K1EffectSemantic *find_k1_effect(
        std::vector<K1EffectSemantic> &effects, K1EffectKind kind) {
    K1EffectSemantic *first = nullptr;
    for (auto &effect : effects) {
        if (effect.kind != kind || !effect.runtime_slot)
            continue;
        if (first == nullptr || *effect.runtime_slot < *first->runtime_slot)
            first = &effect;
    }
    return first;
}

void insert_k1_automation_fx_slots(
        std::vector<K1AutomationSemantic> &automation_objects,
        std::vector<K1EffectSemantic> &effects) {
    static constexpr auto filter = std::to_array<std::string_view>({ "cutoff",
            "resonance", "filter_ingain", "multi_svf_bw", "talk", "sharp",
            "frm_size", "filter_shiftB", "filter_shiftC", "filter_resB",
            "filter_resC", "filter_typeA", "filter_typeB", "filter_typeC",
            "filter_bypA", "filter_bypB", "filter_bypC", "filter_gain", "freq1",
            "bw1", "gain1", "freq2", "bw2", "gain2", "freq3", "bw3", "gain3",
            "cutoffLP", "cutoffHP", "resoLP", "resoHP", "filter_fm",
            "filter_feedback" });
    static constexpr auto compressor = std::to_array<std::string_view>(
            { "comp_attack", "comp_decay", "threshold", "ratio" });
    static constexpr auto lofi = std::to_array<std::string_view>(
            { "bits", "frequency", "noiseLevel", "noiseColor" });
    for (auto &automation : automation_objects) {
        if (!automation.target_tag)
            continue;
        const auto in = [&](const auto &names) {
            return std::find(names.begin(), names.end(),
                           *automation.target_tag) != names.end();
        };
        std::optional<K1EffectKind> kind;
        if (in(filter))
            kind = K1EffectKind::filter;
        else if (in(compressor))
            kind = K1EffectKind::compressor;
        else if (*automation.target_tag == "drive" ||
                 *automation.target_tag == "damping") {
            kind = K1EffectKind::distortion;
        } else if (in(lofi))
            kind = K1EffectKind::lo_fi;
        else if (*automation.target_tag == "stereo" ||
                 *automation.target_tag == "stereo_pan") {
            kind = K1EffectKind::stereo_spread;
        } else if (*automation.target_tag == "shape") {
            kind = K1EffectKind::shaper;
        }
        if (!kind)
            continue;
        const auto *effect = find_k1_effect(effects, *kind);
        if (effect == nullptr)
            continue;
        automation.effect_slot = effect->runtime_slot;
        automation.effect_slot_inferred_from_target_tag = true;
    }
}

// legacy targets identify an effect family, so resolve its slot after FX
// placement
void insert_k1_legacy_fx_slot_indices(K1GroupSemantic &group) {
    static constexpr auto filter_targets = std::to_array<std::string_view>(
            { "filterCutoff", "filterQ", "filterBandwidth", "formantTalk",
                    "formantSize", "formantSharp", "cutoffLP", "cutoffHP",
                    "resoLP", "resoHP", "filterFeedback", "filterFM", "eqFreq1",
                    "eqBandWidth1", "eqGain1", "eqFreq2", "eqBandWidth2",
                    "eqGain2", "eqFreq3", "eqBandWidth3", "eqGain3", "vfShift",
                    "vfType", "vfBypass" });
    for (auto &modulator : group.modulators) {
        for (auto &target : modulator.targets) {
            std::optional<K1EffectKind> kind;
            if (target.xml_target &&
                    std::find(filter_targets.begin(), filter_targets.end(),
                            *target.xml_target) != filter_targets.end()) {
                kind = K1EffectKind::filter;
            } else if (target.xml_target == "distortionIntensity") {
                kind = K1EffectKind::distortion;
            } else if (target.xml_target == "stereoSpreadIntensity" ||
                       target.xml_target == "stereoPan") {
                kind = K1EffectKind::stereo_spread;
            } else if (target.xml_target == "shaper") {
                kind = K1EffectKind::shaper;
            } else if (target.xml_target == "bitdepth" ||
                       target.xml_target == "downsample" ||
                       target.xml_target == "noiselevel" ||
                       target.xml_target == "noisecolor") {
                kind = K1EffectKind::lo_fi;
            }
            if (!kind)
                continue;
            const auto *effect = find_k1_effect(group.effects, *kind);
            if (effect == nullptr)
                continue;
            target.slot_index =
                    static_cast<std::int16_t>(*effect->runtime_slot);
            target.slot_index_inferred_from_effect_type = true;
        }
    }
}

void adapt_k1_fx_intensity_target(
        K1ModulationTarget &target, std::vector<K1EffectSemantic> &effects) {
    if (!target.intensity || !target.xml_target)
        return;
    if (*target.xml_target == "stereoSpreadIntensity") {
        *target.intensity *= 0.5F;
        target.legacy_fx_intensity_corrected = true;
        return;
    }
    if (!target.slot_index || *target.slot_index < 0 || *target.slot_index >= 8)
        return;
    const auto slot = static_cast<std::uint8_t>(*target.slot_index);
    const auto effect_at_slot = [&](K1EffectKind kind) -> K1EffectSemantic * {
        const auto found = std::find_if(
                effects.begin(), effects.end(), [&](K1EffectSemantic &effect) {
                    return effect.kind == kind && effect.runtime_slot == slot;
                });
        return found == effects.end() ? nullptr : &*found;
    };
    if (*target.xml_target == "distortionIntensity") {
        const auto *effect = effect_at_slot(K1EffectKind::distortion);
        if (effect == nullptr || !effect->drive)
            return;
        *target.intensity *= 1.0F - *effect->drive;
    } else if (*target.xml_target == "bitdepth") {
        const auto *effect = effect_at_slot(K1EffectKind::lo_fi);
        if (effect == nullptr || !effect->bits)
            return;
        *target.intensity *= 1.0F - *effect->bits;
    } else if (*target.xml_target == "downsample") {
        const auto *effect = effect_at_slot(K1EffectKind::lo_fi);
        if (effect == nullptr || !effect->down_sample)
            return;
        target.legacy_fx_intensity_requires_engine_sample_rate_conversion =
                true;
        return;
    } else if (*target.xml_target == "noiselevel") {
        const auto *effect = effect_at_slot(K1EffectKind::lo_fi);
        if (effect == nullptr || !effect->noise_level)
            return;
        *target.intensity *= 1.0F - *effect->noise_level;
    } else {
        return;
    }
    target.legacy_fx_intensity_corrected = true;
}

// for external/static legacy modulators, we adapt only the first target;
// for internal modulators, we adapt every target
void adapt_k1_fx_intensities(K1GroupSemantic &group) {
    for (auto &modulator : group.modulators) {
        if (modulator.modulator_class == K1ModulatorClass::internal) {
            if (modulator.subtype_version.value_or(0) >= 0x60U)
                continue;
            for (auto &target : modulator.targets) {
                adapt_k1_fx_intensity_target(target, group.effects);
            }
            continue;
        }
        const bool eligible =
                modulator.modulator_class ==
                        K1ModulatorClass::static_modulator ||
                (modulator.modulator_class == K1ModulatorClass::external &&
                        modulator.external_parameters &&
                        modulator.external_parameters->source);
        if (eligible && modulator.struct_version < 0x90U &&
                !modulator.targets.empty()) {
            adapt_k1_fx_intensity_target(
                    modulator.targets.front(), group.effects);
        }
    }
}

// move XSync's first target to the referenced internal modulator before
// removing XSync; keep the destination count in step with that move
void purge_k1_xsync_modulators(K1GroupSemantic &group) {
    std::vector<bool> purged(group.modulators.size());
    for (std::size_t source_position = 0;
            source_position < group.modulators.size(); ++source_position) {
        auto &source = group.modulators[source_position];
        if (source.modulator_class != K1ModulatorClass::internal ||
                source.internal_type != "XSync" || !source.index ||
                source.targets.empty() || !source.internal_parameters ||
                !source.internal_parameters->x_sync_mod_index) {
            continue;
        }
        const auto destination_index =
                *source.internal_parameters->x_sync_mod_index;
        if (destination_index < 0 || destination_index >= 16)
            continue;
        const auto destination = std::find_if(group.modulators.begin(),
                group.modulators.end(),
                [&](const K1ModulatorSemantic &candidate) {
                    return candidate.modulator_class ==
                                   K1ModulatorClass::internal &&
                           candidate.index ==
                                   static_cast<std::uint8_t>(destination_index);
                });
        if (destination == group.modulators.end() ||
                destination->targets.size() >= 16)
            continue;
        auto moved = source.targets.front();
        moved.moved_from_xsync_modulator_index = source.index;
        destination->targets.push_back(std::move(moved));
        destination->target_count =
                static_cast<std::uint8_t>(destination->targets.size());
        purged[source_position] = true;
    }
    std::size_t position = 0;
    std::erase_if(group.modulators,
            [&](const K1ModulatorSemantic &) { return purged[position++]; });
}

void adapt_k1_wrong_arpeggiator_direction(K1GroupSemantic &group) {
    for (const auto &arpeggiator : group.modulators) {
        if (arpeggiator.modulator_class != K1ModulatorClass::internal ||
                arpeggiator.internal_type != "Arpegg" ||
                arpeggiator.subtype_version.value_or(0) >= 0x70U ||
                arpeggiator.targets.size() != 1 ||
                arpeggiator.targets.front().xml_target != "pitch" ||
                !arpeggiator.index) {
            continue;
        }
        for (auto &modulator : group.modulators) {
            if (modulator.modulator_class == K1ModulatorClass::internal &&
                    modulator.index == arpeggiator.index) {
                continue;
            }
            const bool eligible =
                    modulator.modulator_class == K1ModulatorClass::internal ||
                    modulator.modulator_class ==
                            K1ModulatorClass::static_modulator ||
                    (modulator.modulator_class == K1ModulatorClass::external &&
                            modulator.external_parameters &&
                            modulator.external_parameters->source);
            if (!eligible)
                continue;
            for (auto &target : modulator.targets) {
                if (target.xml_target == "intensity" &&
                        target.target_mod_index &&
                        *target.target_mod_index >= 0 &&
                        static_cast<std::uint8_t>(*target.target_mod_index) ==
                                *arpeggiator.index &&
                        target.intensity) {
                    *target.intensity = -*target.intensity;
                    target.wrong_arpeggiator_direction_corrected = true;
                }
            }
        }
    }
}

// Lo-Fi needs the engine rate for its last multiply, so keep what we read and
// flag it until we know the rate
void mark_k1_lofi_engine_rate_conversion(
        std::vector<K1EffectSemantic> &effects, bool skip_unity) {
    for (auto &effect : effects) {
        if (effect.kind != K1EffectKind::lo_fi || !effect.down_sample)
            continue;
        effect.down_sample_requires_engine_sample_rate_conversion =
                !skip_unity || *effect.down_sample != 1.0F;
    }
}

K1SendLevelsSemantic parse_k1_send_levels(const K1TagElement &element) {
    K1SendLevelsSemantic out;
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    const auto &values = parameters == element.children.end()
                                 ? element.children
                                 : parameters->children;
    for (const auto &value_tag : values) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto real = static_cast<float>(std::atof(value->c_str()));
        if (*name == "delay")
            out.delay = real;
        else if (*name == "chorus")
            out.chorus = real;
        else if (*name == "flanger")
            out.flanger = real;
        else if (*name == "phaser")
            out.phaser = real;
        else if (*name == "reverb")
            out.reverb = real;
    }
    return out;
}

bool k1_send_levels_match(
        const K1SendLevelsSemantic &left, const K1SendLevelsSemantic &right) {
    constexpr float epsilon = 1e-6F;
    return std::fabs(left.delay - right.delay) < epsilon &&
           std::fabs(left.chorus - right.chorus) < epsilon &&
           std::fabs(left.flanger - right.flanger) < epsilon &&
           std::fabs(left.phaser - right.phaser) < epsilon &&
           std::fabs(left.reverb - right.reverb) < epsilon;
}

bool k1_is_send_level_target(std::string_view target) {
    const auto decimal_suffix =
            [&](std::string_view prefix) -> std::optional<unsigned> {
        if (!target.starts_with(prefix) || target.size() == prefix.size())
            return std::nullopt;
        unsigned value = 0;
        for (const char character : target.substr(prefix.size())) {
            if (character < '0' || character > '9')
                return std::nullopt;
            value = value * 10U + static_cast<unsigned>(character - '0');
        }
        return value;
    };
    if (const auto index = decimal_suffix("sendLevel"); index && *index <= 7)
        return true;
    if (target.starts_with("scLevelB") && target.size() == 10) {
        const auto tens = target[8] - '0';
        const auto ones = target[9] - '0';
        if (tens >= 0 && tens <= 9 && ones >= 0 && ones <= 9 &&
                tens * 10 + ones <= 15)
            return true;
    }
    return target == "scLevelPGM" || target == "sendLevelDelay" ||
           target == "sendLevelChorus" || target == "sendLevelFlanger" ||
           target == "sendLevelPhaser" || target == "sendLevelReverb";
}

bool k1_group_has_send_level_modulation(const K1GroupSemantic &group) {
    for (const auto &modulator : group.modulators) {
        const bool eligible =
                modulator.modulator_class == K1ModulatorClass::internal ||
                modulator.modulator_class ==
                        K1ModulatorClass::static_modulator ||
                modulator.modulator_class == K1ModulatorClass::external;
        if (!eligible)
            continue;
        if (std::any_of(modulator.targets.begin(), modulator.targets.end(),
                    [](const K1ModulationTarget &target) {
                        return target.xml_target &&
                               k1_is_send_level_target(*target.xml_target);
                    }))
            return true;
    }
    return false;
}

// K1 only has five sends, the other twenty use defaults. it always lands in
// slot 7 (runtime type 12)
void adapt_k1_pre_v2_send_levels(
        K1ProgramSemantic &program, std::span<K1GroupSemantic> groups) {
    if (groups.empty())
        return;
    const auto levels = [](const K1GroupSemantic &group) {
        return group.send_levels.value_or(K1SendLevelsSemantic{});
    };
    const auto first = levels(groups.front());
    bool group_scoped = k1_group_has_send_level_modulation(groups.front());
    for (std::size_t index = 1; index < groups.size() && !group_scoped;
            ++index) {
        group_scoped = !k1_send_levels_match(first, levels(groups[index])) ||
                       k1_group_has_send_level_modulation(groups[index]);
    }
    if (group_scoped) {
        for (auto &group : groups) {
            group.effective_send_levels = levels(group);
            group.effective_send_levels->runtime_effect_slot = 7;
            group.effective_send_levels->materialized_by_pre_v2_close = true;
        }
        return;
    }
    program.effective_send_levels = first;
    program.effective_send_levels->runtime_effect_slot = 7;
    program.effective_send_levels->materialized_by_pre_v2_close = true;
}

K1VoiceLimitSemantic parse_k1_voice_limit(const K1TagElement &element) {
    K1VoiceLimitSemantic out;
    if (const auto *version = k1_attribute(element, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    const auto &values = parameters == element.children.end()
                                 ? element.children
                                 : parameters->children;
    for (const auto &value_tag : values) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "name")
            out.name = *value;
        else if (*name == "maxNumVoices")
            out.maximum_voices = std::atoi(value->c_str());
        else if (*name == "preferReleased")
            out.prefer_released = *value == "yes";
        else if (*name == "msFadeTime")
            out.fade_time_ms = std::atoi(value->c_str());
        else if (*name == "exclusionGroup")
            out.exclusion_group = std::atoi(value->c_str());
        else if (*name == "mode") {
            if (*value == "kill_any") {
                out.mode =
                        out.struct_version > 0x5fU ? "kill_any" : "kill_oldest";
            } else if (*value == "kill_oldest" || *value == "kill_newest" ||
                       *value == "kill_highest" || *value == "kill_lowest") {
                out.mode = *value;
            }
        }
    }
    return out;
}

K1AutomationSemantic parse_k1_automation(const K1TagElement &element) {
    K1AutomationSemantic out;
    out.attributes = element.attributes;
    if (const auto *version = k1_attribute(element, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    const auto &values = parameters == element.children.end()
                                 ? element.children
                                 : parameters->children;
    for (const auto &value_tag : values) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "type") {
            if (*value == "midiController")
                out.type = K1AutomationType::midi_controller;
            else if (*value == "hostAutomation")
                out.type = K1AutomationType::host_automation;
        } else if (*name == "targetTag")
            out.target_tag = *value;
        else if (*name == "midiCC") {
            out.midi_cc = static_cast<std::int16_t>(std::atoi(value->c_str()));
        } else if (*name == "modIdx")
            out.modulator_index = std::atoi(value->c_str());
        else if (*name == "softTakeOver")
            out.soft_take_over = *value == "yes";
    }
    if (out.target_tag) {
        static constexpr std::pair<std::string_view, std::uint32_t> tags[] = {
#include "tables/k1_automation_tags.inc"
        };
        const auto found = std::find_if(
                std::begin(tags), std::end(tags), [&](const auto &entry) {
                    return entry.first == *out.target_tag;
                });
        out.parameter_tag = found == std::end(tags) ? 0U : found->second;
    }
    if (out.target_tag) {
        static constexpr auto delay =
                std::to_array<std::string_view>({ "dl_return", "dl_time",
                        "dl_damping", "dl_pan", "dl_feedback" });
        static constexpr auto chorus = std::to_array<std::string_view>(
                { "ch_return", "ch_depth", "ch_speed", "ch_phase" });
        static constexpr auto flanger =
                std::to_array<std::string_view>({ "fl_return", "fl_depth",
                        "fl_speed", "fl_phase", "fl_feedback", "fl_color" });
        static constexpr auto phaser =
                std::to_array<std::string_view>({ "ph_return", "ph_depth",
                        "ph_speed", "ph_phase", "ph_feedback" });
        static constexpr auto reverb =
                std::to_array<std::string_view>({ "rv_return", "rv_predelay",
                        "rv_size", "rv_colour", "rv_stereo", "rv_damping" });
        static constexpr auto sends =
                std::to_array<std::string_view>({ "sendlevel_0", "sendlevel_1",
                        "sendlevel_2", "sendlevel_3", "sendlevel_4",
                        "sendlevel_5", "sendlevel_6", "sendlevel_7",
                        "sendlevel_0_and_1", "sclevel_bus00", "sclevel_bus01",
                        "sclevel_bus02", "sclevel_bus03", "sclevel_bus04",
                        "sclevel_bus05", "sclevel_bus06", "sclevel_bus07",
                        "sclevel_bus08", "sclevel_bus09", "sclevel_bus10",
                        "sclevel_bus11", "sclevel_bus12", "sclevel_bus13",
                        "sclevel_bus14", "sclevel_bus15", "sclevel_pgm" });
        const auto in = [&](const auto &names) {
            return std::find(names.begin(), names.end(), *out.target_tag) !=
                   names.end();
        };
        std::optional<std::uint8_t> fixed_slot;
        if (in(delay))
            fixed_slot = 0;
        else if (in(chorus))
            fixed_slot = 1;
        else if (in(flanger))
            fixed_slot = 2;
        else if (in(phaser))
            fixed_slot = 3;
        else if (in(reverb))
            fixed_slot = 4;
        else if (in(sends))
            fixed_slot = 7;
        if (fixed_slot) {
            out.effect_slot = fixed_slot;
            out.effect_slot_inferred_from_target_tag = true;
        }
    }
    return out;
}

std::optional<std::uint8_t> k1_effect_runtime_type(K1EffectKind kind) {
    switch (kind) {
        case K1EffectKind::filter:
            return 8;
        case K1EffectKind::compressor:
            return 2;
        case K1EffectKind::inverter:
            return 4;
        case K1EffectKind::lo_fi:
            return 9;
        case K1EffectKind::shaper:
            return 7;
        case K1EffectKind::stereo_spread:
            return 10;
        case K1EffectKind::distortion:
            return 11;
        case K1EffectKind::delay:
            return 0x43;
        case K1EffectKind::chorus:
            return 0x3d;
        case K1EffectKind::flanger:
            return 0x3c;
        case K1EffectKind::phaser:
            return 0x3b;
        case K1EffectKind::reverb:
            return 0x3e;
    }
    return std::nullopt;
}

std::optional<std::uint32_t> k1_internal_object_descriptor(
        const K1ModulatorSemantic &modulator) {
    if (modulator.modulator_class != K1ModulatorClass::internal ||
            !modulator.internal_type)
        return std::nullopt;
    std::uint32_t subtype{};
    std::uint32_t discriminator{};
    if (*modulator.internal_type == "LFO")
        subtype = 1;
    else if (*modulator.internal_type == "Envelope") {
        subtype = 2;
        if (!modulator.envelope || !modulator.envelope->type)
            return std::nullopt;
        switch (*modulator.envelope->type) {
            case K1EnvelopeType::ahdsr:
                discriminator = 0;
                break;
            case K1EnvelopeType::fm7:
                discriminator = 1;
                break;
            case K1EnvelopeType::dbd:
                discriminator = 2;
                break;
        }
    } else if (*modulator.internal_type == "Arpegg")
        subtype = 3;
    else if (*modulator.internal_type == "EnvFollow")
        subtype = 4;
    else if (*modulator.internal_type == "Glide")
        subtype = 5;
    else
        return std::nullopt;
    return 0x10000U | (subtype << 8U) | discriminator;
}

bool k1_parameter_tag_matches_object(
        std::uint32_t tag, std::uint32_t descriptor) {
    const auto object_class = (descriptor >> 16U) & 0xffU;
    const auto subtype = (descriptor >> 8U) & 0xffU;
    const auto discriminator = descriptor & 0xffU;
    if (object_class == 1) {
        if (tag >= 0x2aaU && tag <= 0x2afU)
            return subtype == 2 && discriminator == 0;
        if (tag >= 0x2b2U && tag <= 0x2b4U)
            return subtype == 2 && discriminator == 2;
        if (tag == 0x2b7U)
            return subtype == 5;
        if (tag >= 0x2baU && tag <= 0x2c0U)
            return subtype == 1;
        if (tag >= 0x2c3U && tag <= 0x2c6U)
            return subtype == 4;
        return tag == 0x2c9U || tag == 0x2caU;
    }
    if (object_class == 3)
        return tag >= 2U && tag <= 0x13U;
    if (object_class != 4)
        return false;
    if (tag >= 0x17U && tag <= 0x19U)
        return true;
    if (tag >= 0x1cU && tag <= 0x44U)
        return subtype == 8;
    if (tag >= 0x4bU && tag <= 0x4cU)
        return subtype == 11;
    if (tag >= 0x10eU && tag <= 0x111U)
        return subtype == 9;
    if (tag >= 0x114U && tag <= 0x115U)
        return subtype == 10;
    if (tag == 0x118U)
        return subtype == 7;
    if (tag >= 0x11bU && tag <= 0x11eU)
        return subtype == 2;
    if (tag >= 0x1b3U && tag <= 0x1d5U)
        return subtype == 0xc;
    if (tag >= 0x215U && tag <= 0x219U)
        return true;
    if (tag >= 0x21cU && tag <= 0x21eU)
        return subtype == 0x3d;
    if (tag >= 0x221U && tag <= 0x225U)
        return subtype == 0x3c;
    if (tag >= 0x228U && tag <= 0x22bU)
        return subtype == 0x3b;
    if (tag >= 0x232U && tag <= 0x236U)
        return subtype == 0x3e;
    if (tag >= 0x285U && tag <= 0x288U)
        return subtype == 0x43;
    return false;
}

void assign_k1_program_automation_object_selectors(K1ProgramSemantic &program) {
    for (auto &automation : program.automation) {
        const auto tag = automation.parameter_tag.value_or(0U);
        if (tag >= 0x16U && tag <= 0x211U)
            automation.program_object_selector = 1;
        else if (tag >= 0x214U && tag <= 0x292U)
            automation.program_object_selector = 0;
        else
            automation.program_object_selector = -1;
    }
}

bool k1_program_automation_is_valid(const K1AutomationSemantic &automation,
        const K1ProgramSemantic &program) {
    const auto tag = automation.parameter_tag.value_or(0U);
    if (tag == 0)
        return false;
    const bool effect_parameter =
            (tag >= 0x16U && tag <= 0x211U) || (tag >= 0x214U && tag <= 0x292U);
    if (effect_parameter) {
        if (!automation.program_object_selector || !automation.effect_slot ||
                *automation.effect_slot > 7)
            return false;
        const auto selector = *automation.program_object_selector;
        if (selector != 0 && selector != 1)
            return false;
        if (selector == 1 && tag >= 0x1b3U && tag <= 0x1d5U &&
                program.effective_send_levels &&
                program.effective_send_levels->runtime_effect_slot ==
                        *automation.effect_slot) {
            return k1_parameter_tag_matches_object(tag, 0x40c00U);
        }
        const auto effect = std::find_if(program.effects.begin(),
                program.effects.end(), [&](const K1EffectSemantic &value) {
                    const bool legacy_send =
                            value.kind == K1EffectKind::delay ||
                            value.kind == K1EffectKind::chorus ||
                            value.kind == K1EffectKind::flanger ||
                            value.kind == K1EffectKind::phaser ||
                            value.kind == K1EffectKind::reverb;
                    return value.runtime_slot == *automation.effect_slot &&
                           legacy_send == (selector == 0);
                });
        if (effect == program.effects.end())
            return false;
        const auto type = k1_effect_runtime_type(effect->kind);
        return type &&
               k1_parameter_tag_matches_object(tag,
                       0x40000U | (static_cast<std::uint32_t>(*type) << 8U));
    }
    if (tag == 0x29bU || tag == 0x29cU) {
        const auto selector = automation.program_object_selector.value_or(-1);
        return selector >= 3 && selector <= 18;
    }
    return true;
}

void purge_k1_invalid_program_automation(K1ProgramSemantic &program) {
    for (auto iterator = program.automation.begin();
            iterator != program.automation.end();) {
        if (k1_program_automation_is_valid(*iterator, program)) {
            ++iterator;
            continue;
        }
        program.purged_automation.push_back(std::move(*iterator));
        iterator = program.automation.erase(iterator);
    }
}

bool k1_group_automation_is_valid(
        const K1AutomationSemantic &automation, const K1GroupSemantic &group) {
    const auto tag = automation.parameter_tag.value_or(0U);
    if (tag == 0)
        return false;
    if (tag >= 0x16U && tag <= 0x211U) {
        if (!automation.effect_slot || *automation.effect_slot > 7)
            return false;
        const auto effect = std::find_if(group.effects.begin(),
                group.effects.end(), [&](const K1EffectSemantic &value) {
                    return value.runtime_slot == *automation.effect_slot;
                });
        if (effect == group.effects.end())
            return false;
        const auto type = k1_effect_runtime_type(effect->kind);
        return type &&
               k1_parameter_tag_matches_object(tag,
                       0x40000U | (static_cast<std::uint32_t>(*type) << 8U));
    }
    if (tag >= 0x2a8U && tag <= 0x2cbU) {
        if (!automation.modulator_index || *automation.modulator_index < 0 ||
                *automation.modulator_index > 15)
            return false;
        const auto modulator = std::find_if(group.modulators.begin(),
                group.modulators.end(), [&](const K1ModulatorSemantic &value) {
                    return value.modulator_class ==
                                   K1ModulatorClass::internal &&
                           value.index &&
                           *value.index == *automation.modulator_index;
                });
        if (modulator == group.modulators.end())
            return false;
        const auto descriptor = k1_internal_object_descriptor(*modulator);
        return descriptor && k1_parameter_tag_matches_object(tag, *descriptor);
    }
    if (tag >= 2U && tag <= 0x13U) {
        return k1_parameter_tag_matches_object(tag, 0x30000U);
    }
    return true;
}

void purge_k1_invalid_group_automation(K1GroupSemantic &group) {
    auto &automation = group.automation;
    for (auto iterator = automation.begin(); iterator != automation.end();) {
        if (k1_group_automation_is_valid(*iterator, group)) {
            ++iterator;
            continue;
        }
        group.purged_automation.push_back(std::move(*iterator));
        iterator = automation.erase(iterator);
    }
}

std::optional<std::uint32_t> k1_filter_runtime_subtype(
        const K1EffectSemantic &effect) {
    if (effect.kind != K1EffectKind::filter || !effect.type)
        return std::nullopt;
    static constexpr auto types =
            std::to_array<std::pair<std::string_view, std::uint32_t>>({
                    { "lp1pole", 2 },
                    { "hp1pole", 3 },
                    { "lp2pole", 6 },
                    { "hp2pole", 7 },
                    { "bp2pole", 4 },
                    { "lp4pole", 8 },
                    { "hp4pole", 9 },
                    { "bp4pole", 0xa },
                    { "br4pole", 0xb },
                    { "lp6pole", 0xc },
                    { "phaser", 0xd },
                    { "vowelA", 0xe },
                    { "vowelB", 0xf },
                    { "sampleAndHold", 6 },
                    { "versatile", 0x13 },
                    { "eq1band", 0x5f },
                    { "eq2band", 0x60 },
                    { "eq3band", 0x61 },
            });
    const auto found = std::find_if(types.begin(), types.end(),
            [&](const auto &entry) { return entry.first == *effect.type; });
    return found == types.end() ? std::nullopt
                                : std::optional<std::uint32_t>(found->second);
}

bool k1_fx_mod_target_fits(
        const K1EffectSemantic &effect, std::uint32_t target) {
    const auto type = k1_effect_runtime_type(effect.kind);
    if (!type)
        return false;
    if (target == 0x40U)
        return *type == 11;
    if (target == 0x5eU || target == 0x5fU)
        return *type == 10;
    if (target == 0x62U)
        return *type == 7;
    if (target >= 0x65U && target <= 0x68U)
        return *type == 9;
    if (*type != 8)
        return false;
    const auto subtype = k1_filter_runtime_subtype(effect);
    if (!subtype)
        return false;
    if (target == 0x1fU || target == 0x20U)
        return *subtype >= 2 && *subtype <= 0x5c;
    if (target == 0x21U)
        return *subtype == 0x5b || (*subtype & ~3U) == 0x24U;
    if (target == 0x22U)
        return (*subtype & ~3U) == 0x24U;
    if (target >= 0x28U && target <= 0x2aU)
        return *subtype >= 0x5f && *subtype <= 0x61;
    if (target >= 0x2bU && target <= 0x2dU)
        return (*subtype & ~1U) == 0x60U;
    if (target >= 0x2eU && target <= 0x30U)
        return *subtype == 0x61U;
    if (target >= 0x33U && target <= 0x35U)
        return *subtype == 0x13U;
    if (target == 0x37U || target == 0x38U)
        return *subtype == 0x58U || *subtype == 0x5bU;
    if (target == 0x39U || target == 0x3aU)
        return *subtype == 0x5bU;
    return false;
}

bool k1_internal_mod_target_fits(
        const K1ModulatorSemantic &modulator, std::uint32_t target) {
    const auto descriptor = k1_internal_object_descriptor(modulator);
    if (!descriptor)
        return false;
    const auto subtype = (*descriptor >> 8U) & 0xffU;
    const auto discriminator = *descriptor & 0xffU;
    if (target == 0x19U)
        return true;
    if (target == 0x1aU)
        return (subtype & ~2U) == 1U;
    if (target == 0x1bU) {
        if (subtype != 1 || !modulator.lfo || !modulator.lfo->waveform)
            return false;
        const auto waveform =
                static_cast<std::uint32_t>(*modulator.lfo->waveform);
        return waveform <= 6 && ((0x62U >> waveform) & 1U) != 0;
    }
    if (target >= 0x8dU && target <= 0xacU)
        return subtype == 3;
    if (target == 0xb8U || target == 0xb9U || target == 0xbaU ||
            target == 0xbbU || target == 0xbdU)
        return subtype == 2 && discriminator == 0;
    if (target == 0xbfU || target == 0xc0U || target == 0xc2U)
        return subtype == 2 && discriminator == 2;
    if ((target >= 0xc4U && target <= 0xcbU) ||
            (target >= 0xceU && target <= 0xd5U) ||
            (target >= 0xd8U && target <= 0xdfU))
        return subtype == 2 && discriminator == 1;
    return false;
}

bool k1_target_references_internal(std::uint32_t target) {
    return (target >= 0x8dU && target <= 0xacU) ||
           (target >= 0x19U && target <= 0x1bU) || target == 0xb4U ||
           (target >= 0xb7U && target <= 0xe0U);
}

void remove_k1_unused_modulators(K1GroupSemantic &group) {
    const auto target_is_valid = [&](const K1ModulationTarget &target) {
        if (!target.target_id)
            return true;
        const auto id = *target.target_id;
        if (k1_target_references_internal(id)) {
            if (!target.target_mod_index || *target.target_mod_index < 0 ||
                    *target.target_mod_index > 15)
                return false;
            const auto referenced = std::find_if(group.modulators.begin(),
                    group.modulators.end(),
                    [&](const K1ModulatorSemantic &value) {
                        return value.modulator_class ==
                                       K1ModulatorClass::internal &&
                               value.index &&
                               *value.index == *target.target_mod_index;
                    });
            return referenced != group.modulators.end() &&
                   k1_internal_mod_target_fits(*referenced, id);
        }
        if (id < 0x1eU || id >= 0x8bU)
            return true;
        if (!target.slot_index || *target.slot_index < 0 ||
                *target.slot_index > 7)
            return false;
        if (id >= 0x71U && id <= 0x89U && group.effective_send_levels &&
                group.effective_send_levels->runtime_effect_slot ==
                        *target.slot_index)
            return true;
        const auto effect = std::find_if(group.effects.begin(),
                group.effects.end(), [&](const K1EffectSemantic &value) {
                    return value.runtime_slot == *target.slot_index;
                });
        return effect != group.effects.end() &&
               k1_fx_mod_target_fits(*effect, id);
    };

    for (auto iterator = group.modulators.begin();
            iterator != group.modulators.end();) {
        auto &targets = iterator->targets;
        for (auto target = targets.begin(); target != targets.end();) {
            if (target_is_valid(*target)) {
                ++target;
                continue;
            }
            iterator->removed_unused_targets.push_back(std::move(*target));
            target = targets.erase(target);
        }
        iterator->target_count = static_cast<std::uint8_t>(targets.size());
        if (!targets.empty()) {
            ++iterator;
            continue;
        }
        group.removed_unused_modulators.push_back(std::move(*iterator));
        iterator = group.modulators.erase(iterator);
    }
}

void collect_k1_automation(const K1TagElement &element,
        std::vector<K1AutomationSemantic> &automation, bool stop_at_groups) {
    if (stop_at_groups && element.name == "NiSS_Group")
        return;
    if (element.name == "AutObj")
        automation.push_back(parse_k1_automation(element));
    for (const auto &child : element.children) {
        collect_k1_automation(child, automation, stop_at_groups);
    }
}

void collect_k1_voice_limits(const K1TagElement &element,
        std::vector<K1VoiceLimitSemantic> &limits) {
    if (element.name == "NiSS_Group")
        return;
    if (element.name == "VoiceGroup") {
        limits.push_back(parse_k1_voice_limit(element));
    }
    for (const auto &child : element.children)
        collect_k1_voice_limits(child, limits);
}

K1SourceModeSemantic parse_k1_source_mode(const K1TagElement &element) {
    K1SourceModeSemantic out;
    if (const auto *version = k1_attribute(element, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    const auto &values = parameters == element.children.end()
                                 ? element.children
                                 : parameters->children;
    for (const auto &value_tag : values) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto yes = [&] { return *value == "yes"; };
        if (*name == "type") {
            static constexpr std::array<
                    std::pair<std::string_view, std::uint32_t>, 7>
                    types{ { { "tone_machine", 1 }, { "time_machine", 3 },
                            { "streaming", 4 }, { "slice_machine", 5 },
                            { "time_machine2", 6 }, { "sp1200_machine", 7 },
                            { "mpc60_machine", 8 } } };
            const auto type = std::find_if(types.begin(), types.end(),
                    [&](const auto &item) { return item.first == *value; });
            if (type != types.end()) {
                out.type = *value;
                out.runtime_type = type->second;
            }
        } else if (*name == "speed")
            out.speed = real();
        else if (*name == "smooth")
            out.smooth = real();
        else if (*name == "noteValue_speed")
            out.note_value_speed = real();
        else if (*name == "formantShift")
            out.formant_shift = real();
        else if (*name == "grainLength")
            out.grain_length_file_value = real();
        else if (*name == "hiQuality")
            out.high_quality = yes();
        else if (*name == "dcFilter")
            out.dc_filter = yes();
        else if (*name == "retrigger")
            out.retrigger = yes();
        else if (*name == "sliceAttack")
            out.slice_attack = real();
        else if (*name == "sliceRelease")
            out.slice_release = real();
        else if (*name == "sliceAutoPlay")
            out.slice_auto_play = yes();
        else if (*name == "transientCopy")
            out.transient_copy = yes();
        else if (*name == "transientSize")
            out.transient_size = std::atoi(value->c_str());
        else if (*name == "analysisGrainSize") {
            out.analysis_grain_size = std::atoi(value->c_str());
        }
    }
    if (out.formant_shift)
        *out.formant_shift = std::log2(*out.formant_shift);
    if (out.struct_version < 0x70U && out.type == "time_machine" &&
            out.smooth) {
        *out.smooth *= 0.99F;
    }
    out.grain_length_requires_sample_rate_conversion =
            out.struct_version < 0x60U &&
            out.grain_length_file_value.has_value();
    if (out.grain_length_file_value &&
            !out.grain_length_requires_sample_rate_conversion) {
        out.grain_length = *out.grain_length_file_value;
        if (*out.grain_length > 100.0F || *out.grain_length < 0.3F ||
                std::isnan(*out.grain_length)) {
            out.grain_length = 6.0F;
        }
    }
    if (out.runtime_type == 4U) {
        out.requires_loaded_sample_streamability_check = true;
        out.non_streamable_fallback_runtime_type = 0U;
    }
    if (out.runtime_type == 5U) {
        out.missing_slices_require_runtime_grid_initialization = true;
        out.missing_slices_runtime_grid_mode = 1U;
    }
    return out;
}

K1StartCriteriaSemantic parse_k1_start_criteria(const K1TagElement &element) {
    K1StartCriteriaSemantic out;
    if (const auto *version = k1_attribute(element, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    const auto &values = parameters == element.children.end()
                                 ? element.children
                                 : parameters->children;
    for (const auto &value_tag : values) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        if (*name == "mode") {
            static constexpr auto modes = std::to_array<std::string_view>(
                    { "on_key", "on_controller", "cycle_round_robin",
                            "cycle_random", "slice_trigger" });
            if (std::find(modes.begin(), modes.end(), *value) != modes.end())
                out.mode = *value;
        } else if (*name == "key" && out.struct_version < 0x60U) {
            out.key_min = static_cast<std::int16_t>(integer());
            out.key_max = out.key_min;
        } else if (*name == "key_min" && out.struct_version >= 0x60U) {
            out.key_min = static_cast<std::int16_t>(integer());
        } else if (*name == "key_max" && out.struct_version >= 0x60U) {
            out.key_max = static_cast<std::int16_t>(integer());
        } else if (*name == "controller") {
            out.controller = static_cast<std::int16_t>(integer());
        } else if (*name == "cc_min") {
            out.controller_min = static_cast<std::int16_t>(integer());
        } else if (*name == "cc_max") {
            out.controller_max = static_cast<std::int16_t>(integer());
        } else if (*name == "sliceZoneIdx")
            out.slice_zone_index = integer();
        else if (*name == "sliceZoneSliceIdx")
            out.slice_index = integer();
        else if (*name == "sequencerOnly")
            out.sequencer_only = *value == "yes";
        else if (*name == "cycleClass")
            out.cycle_class = integer();
        else if (*name == "nextCriteria" &&
                 (*value == "and" || *value == "or" || *value == "and_not")) {
            out.next_criteria = *value;
        }
    }
    return out;
}

K1GroupParameters parse_k1_group_parameters(
        const K1TagElement &group, const K1TagElement &parameters) {
    K1GroupParameters out;
    if (const auto *version = k1_attribute(group, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    for (const auto &value_tag : parameters.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] {
            return static_cast<std::int32_t>(std::atoi(value->c_str()));
        };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto yes = [&] { return *value == "yes"; };
        if (*name == "m_bMuted")
            out.muted = yes();
        else if (*name == "m_bSolo")
            out.solo = yes();
        else if (*name == "m_iRow")
            out.ui_row = integer();
        else if (*name == "m_iCol")
            out.ui_column = integer();
        else if (*name == "midiChannel")
            out.midi_channel = static_cast<std::int16_t>(integer());
        else if (*name == "batteryLowKey")
            out.battery_low_key = integer();
        else if (*name == "batteryHighKey")
            out.battery_high_key = integer();
        else if (*name == "volume")
            out.volume = real();
        else if (*name == "pan")
            out.pan = real();
        else if (*name == "tune")
            out.tune = real();
        else if (*name == "keyTracking")
            out.key_tracking = yes();
        else if (*name == "reverse")
            out.reverse = yes();
        else if (*name == "releaseTrigger")
            out.release_trigger = yes();
        else if (*name == "releaseTriggerNoteMonophonic") {
            out.release_trigger_note_monophonic = yes();
        } else if (*name == "rlsTrigCounter")
            out.release_trigger_counter = integer();
        else if (*name == "output")
            out.output = integer();
        else if (*name == "voiceGroup")
            out.voice_group = integer();
        else if (*name == "selectedForEdit")
            out.selected_for_edit = yes();
    }
    if (out.pan && out.struct_version < 0x70U)
        *out.pan = *out.pan * 2.0F - 1.0F;
    if (out.release_trigger && *out.release_trigger &&
            out.release_trigger_counter && *out.release_trigger_counter < 1) {
        *out.release_trigger_counter = 1;
    }
    out.effective_midi_channel = out.midi_channel;
    out.effective_selected_for_edit = out.selected_for_edit.value_or(false);
    return out;
}

K1ProgramParameters parse_k1_program_parameters(
        const K1TagElement &program, const K1TagElement &parameters) {
    K1ProgramParameters out;
    if (const auto *version = k1_attribute(program, "version")) {
        out.struct_version = parse_k1_dotted_version(*version).value_or(0);
    }
    for (const auto &value_tag : parameters.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = k1_attribute(value_tag, "name");
        const auto *value = k1_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] {
            return static_cast<std::int32_t>(std::atoi(value->c_str()));
        };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        if (*name == "uiInfo.m_iRows")
            out.ui_rows = integer();
        else if (*name == "uiInfo.m_iCols")
            out.ui_columns = integer();
        else if (*name == "midiChannel")
            out.midi_channel = static_cast<std::int16_t>(integer());
        else if (*name == "masterVolume")
            out.master_volume = real();
        else if (*name == "masterPan")
            out.master_pan = real();
        else if (*name == "masterTune")
            out.master_tune = real();
        else if (*name == "output")
            out.output = static_cast<std::uint32_t>(integer());
        else if (*name == "transpose")
            out.transpose = static_cast<std::int8_t>(integer());
        else if (*name == "lowVelocity")
            out.low_velocity = static_cast<std::int8_t>(integer());
        else if (*name == "highVelocity")
            out.high_velocity = static_cast<std::int8_t>(integer());
        else if (*name == "lowKey")
            out.low_key = static_cast<std::int8_t>(integer());
        else if (*name == "highKey")
            out.high_key = static_cast<std::int8_t>(integer());
        else if (*name == "fingerPrint")
            out.fingerprint = integer();
        else if (*name == "activeGroupIdx")
            out.active_group_index = integer();
    }
    if (out.struct_version < 0x60U) {
        if (out.master_pan)
            *out.master_pan = *out.master_pan * 2.0F - 1.0F;
        if (out.output) {
            auto value = *out.output;
            if (static_cast<std::int32_t>(value) < 1)
                value = 0;
            *out.output = value < 0x40U ? (value | 0x20000U)
                                        : ((value - 0x40U) | 0x10000U);
        }
    }
    out.effective_active_group_index = out.active_group_index;
    return out;
}

void append_k1_battery_layers(const std::vector<K1TagAttribute> &attributes,
        std::vector<K1BatteryLayerSemantic> &layers) {
    K1BatteryLayerSemantic current;
    bool any = false;
    auto flush = [&] {
        if (any)
            layers.push_back(std::move(current));
        current = {};
        any = false;
    };
    for (const auto &attribute : attributes) {
        const bool duplicate =
                (attribute.name == "file" && current.path) ||
                (attribute.name == "lowVelo" && current.low_velocity) ||
                (attribute.name == "highVelo" && current.high_velocity) ||
                (attribute.name == "layerVolume" && current.volume);
        if (duplicate)
            flush();
        if (attribute.name == "file") {
            current.path = attribute.value;
            any = true;
        } else if (attribute.name == "lowVelo") {
            current.low_velocity = static_cast<std::int16_t>(
                    std::atoi(attribute.value.c_str()));
            any = true;
        } else if (attribute.name == "highVelo") {
            current.high_velocity = static_cast<std::int16_t>(
                    std::atoi(attribute.value.c_str()));
            any = true;
        } else if (attribute.name == "layerVolume") {
            current.volume =
                    static_cast<float>(std::atof(attribute.value.c_str()));
            any = true;
        }
    }
    flush();
}

K1BatterySlotSemantic parse_k1_battery_slot(const K1TagElement &element) {
    K1BatterySlotSemantic out;
    out.attributes = element.attributes;
    for (const auto &attribute : element.attributes) {
        const auto integer = [&] { return std::atoi(attribute.value.c_str()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(attribute.value.c_str()));
        };
        if (attribute.name == "label")
            out.label = attribute.value;
        else if (attribute.name == "rootKey")
            out.root_key = integer();
        else if (attribute.name == "lowKey")
            out.low_key = integer();
        else if (attribute.name == "highKey")
            out.high_key = integer();
        else if (attribute.name == "muteGroup") {
            const auto value = integer();
            if (value > 0)
                out.mute_group = value;
        } else if (attribute.name == "volume")
            out.volume = real();
        else if (attribute.name == "pan")
            out.pan = real();
        else if (attribute.name == "pitch")
            out.pitch = real();
        else if (attribute.name == "sstart")
            out.sample_start = integer();
        else if (attribute.name == "fxstart")
            out.effect_start = integer();
        else if (attribute.name == "fxlength")
            out.effect_length = integer();
        else if (attribute.name == "fxcount")
            out.effect_count = integer();
        else if (attribute.name == "vattack")
            out.serialized_velocity_attack = integer();
        else if (attribute.name == "vhold")
            out.serialized_velocity_hold = integer();
        else if (attribute.name == "vdecay")
            out.serialized_velocity_decay = integer();
        else if (attribute.name == "vsustain")
            out.serialized_velocity_sustain = integer();
        else if (attribute.name == "vrelease")
            out.serialized_velocity_release = integer();
        else if (attribute.name == "pdecay1")
            out.serialized_pitch_decay_1 = integer();
        else if (attribute.name == "pdecay2")
            out.serialized_pitch_decay_2 = integer();
        else if (attribute.name == "pbreak" || attribute.name == "pamount") {
            auto value = static_cast<float>(std::log2(real()) / 3.0F);
            value = std::clamp(value, -1.0F, 1.0F);
            if (attribute.name == "pbreak")
                out.pitch_break = value;
            else
                out.pitch_amount = value;
        } else if (attribute.name == "waveshaper") {
            const auto centered = real() * 0.125F - 0.5F;
            if (std::abs(centered) > 0.001F)
                out.waveshaper = centered * 2.0F;
        } else if (attribute.name == "bitreduction") {
            const auto value = std::min(real(), 16.0F);
            if (value >= 1.0F)
                out.bit_reduction = value;
        } else if (attribute.name == "status") {
            out.status = static_cast<std::uint32_t>(
                    std::strtoul(attribute.value.c_str(), nullptr, 10));
        } else if (attribute.name == "midiChannel")
            out.midi_channel = integer();
        else {
            for (std::size_t i = 0; i < out.modulation.size(); ++i) {
                const auto suffix = std::to_string(i);
                if (attribute.name == "modSrc" + suffix) {
                    out.modulation[i].source = integer();
                } else if (attribute.name == "modDest" + suffix) {
                    out.modulation[i].destination = integer();
                } else if (attribute.name == "modAmt" + suffix) {
                    out.modulation[i].amount =
                            static_cast<float>(integer()) / 100.0F;
                }
            }
        }
    }
    append_k1_battery_layers(element.attributes, out.layers);
    for (const auto &child : element.children) {
        append_k1_battery_layers(child.attributes, out.layers);
    }
    return out;
}

K1BatteryProgramSemantic parse_k1_battery_program(const K1TagElement &element) {
    K1BatteryProgramSemantic out;
    out.attributes = element.attributes;
    if (const auto *version = k1_attribute(element, "version")) {
        out.version = parse_k1_dotted_version(*version).value_or(0);
    }
    if (const auto *name = k1_attribute(element, "name"))
        out.name = *name;
    if (const auto *volume = k1_attribute(element, "volume")) {
        out.master_volume = static_cast<float>(std::atof(volume->c_str()));
    }
    for (const auto &child : element.children) {
        if (child.name == "SampleSlot") {
            out.slots.push_back(parse_k1_battery_slot(child));
        }
    }
    return out;
}

void collect_k1_semantics(const K1TagElement &element, K1PatchData &data,
        std::int32_t program_ordinal = -1, std::int32_t group_ordinal = -1) {
    const auto parameters = std::find_if(element.children.begin(),
            element.children.end(), [](const K1TagElement &child) {
                return child.name == "Parameters";
            });
    if (element.name == "NiSS_Program") {
        program_ordinal = static_cast<std::int32_t>(data.programs.size());
        group_ordinal = -1;
        K1ProgramSemantic program;
        program.attributes = element.attributes;
        if (parameters != element.children.end()) {
            program.parameters =
                    parse_k1_program_parameters(element, *parameters);
        }
        for (const auto &child : element.children) {
            collect_k1_voice_limits(child, program.voice_limits);
            collect_k1_automation(child, program.automation, true);
        }
        const auto collect_program_effects =
                [&](const auto &self, const K1TagElement &child) -> void {
            if (child.name == "NiSS_Group")
                return;
            if (const auto kind = k1_effect_kind(child.name)) {
                program.effects.push_back(parse_k1_effect(child, *kind));
            }
            for (const auto &nested : child.children)
                self(self, nested);
        };
        for (const auto &child : element.children) {
            collect_program_effects(collect_program_effects, child);
        }
        assign_k1_effect_slots(program.effects);
        insert_k1_automation_fx_slots(program.automation, program.effects);
        assign_k1_program_automation_object_selectors(program);
        mark_k1_lofi_engine_rate_conversion(program.effects, false);
        data.programs.push_back(std::move(program));
        const auto program_index = data.programs.size() - 1;
        const auto first_group = data.groups.size();
        for (const auto &child : element.children)
            collect_k1_semantics(child, data, program_ordinal, group_ordinal);
        if (data.groups.size() == first_group) {
            K1GroupSemantic generated;
            generated.program_ordinal = program_ordinal;
            generated.group_ordinal = 0;
            generated.generated_by_empty_program_recovery = true;
            generated.parameters.emplace();
            generated.parameters->effective_selected_for_edit = true;
            data.groups.push_back(std::move(generated));
            data.programs[program_index].empty_program_default_group_generated =
                    true;
        }
        auto program_groups =
                std::span<K1GroupSemantic>(data.groups)
                        .subspan(first_group, data.groups.size() - first_group);
        if (data.programs[program_index].parameters &&
                data.programs[program_index].parameters->midi_channel.value_or(
                        -1) >= 0) {
            for (auto &group : program_groups) {
                if (!group.parameters)
                    continue;
                group.parameters->effective_midi_channel = -1;
                group.parameters->midi_channel_overridden_by_program = true;
            }
        }
        if (data.programs[program_index].parameters) {
            auto &program_parameters = *data.programs[program_index].parameters;
            auto active = program_parameters.active_group_index.value_or(-1);
            const auto valid_active =
                    active >= 0 &&
                    static_cast<std::size_t>(active) < program_groups.size() &&
                    program_groups[static_cast<std::size_t>(active)]
                            .parameters &&
                    program_groups[static_cast<std::size_t>(active)]
                            .parameters->effective_selected_for_edit.value_or(
                                    false);
            if (!valid_active) {
                const auto selected = std::find_if(program_groups.begin(),
                        program_groups.end(), [](const K1GroupSemantic &group) {
                            return group.parameters &&
                                   group.parameters->effective_selected_for_edit
                                           .value_or(false);
                        });
                active = selected == program_groups.end()
                                 ? 0
                                 : static_cast<std::int32_t>(
                                           selected - program_groups.begin());
                if (selected == program_groups.end() &&
                        !program_groups.empty() &&
                        program_groups[0].parameters) {
                    program_groups[0].parameters->effective_selected_for_edit =
                            true;
                }
                program_parameters.active_group_index_repaired = true;
            }
            program_parameters.effective_active_group_index = active;
        }
        adapt_k1_pre_v2_send_levels(
                data.programs[program_index], program_groups);
        for (auto &group : program_groups) {
            remove_k1_unused_modulators(group);
            adapt_k1_fx_intensities(group);
            purge_k1_invalid_group_automation(group);
        }
        purge_k1_invalid_program_automation(data.programs[program_index]);
        return;
    }
    if (element.name == "NiSS_Group") {
        group_ordinal = 0;
        for (const auto &existing : data.groups) {
            if (existing.program_ordinal == program_ordinal)
                ++group_ordinal;
        }
        K1GroupSemantic group;
        group.program_ordinal = program_ordinal;
        group.group_ordinal = group_ordinal;
        group.attributes = element.attributes;
        if (parameters != element.children.end()) {
            group.parameters = parse_k1_group_parameters(element, *parameters);
            if (group.parameters->output) {
                K1GroupOutputResolution request;
                request.serialized_output = *group.parameters->output;
                auto encoded = *group.parameters->output;
                if (encoded < 1)
                    encoded = 0;
                if (encoded < 0x40) {
                    request.requested_output_type = 2;
                    request.requested_ordinal =
                            static_cast<std::uint16_t>(encoded);
                } else {
                    request.requested_output_type = 1;
                    request.requested_ordinal =
                            static_cast<std::uint16_t>(encoded - 0x40);
                }
                group.output_resolution = request;
            }
        }
        const auto collect_group_nodes =
                [&](const auto &self, const K1TagElement &child) -> void {
            if (child.name == "Grain") {
                group.source_mode = parse_k1_source_mode(child);
            } else if (child.name == "StartCriteria") {
                group.start_criteria.push_back(parse_k1_start_criteria(child));
            } else if (child.name == "SendLevels") {
                group.send_levels = parse_k1_send_levels(child);
            }
            for (const auto &nested : child.children)
                self(self, nested);
        };
        for (const auto &child : element.children) {
            if (child.name == "IntModulators" ||
                    child.name == "ExtModulators" ||
                    child.name == "StatModulators") {
                collect_k1_modulators(child, group.modulators);
            }
            collect_k1_effects(child, group.effects);
            collect_group_nodes(collect_group_nodes, child);
            collect_k1_automation(child, group.automation, false);
        }
        assign_k1_effect_slots(group.effects);
        insert_k1_automation_fx_slots(group.automation, group.effects);
        insert_k1_legacy_fx_slot_indices(group);
        purge_k1_xsync_modulators(group);
        adapt_k1_wrong_arpeggiator_direction(group);
        mark_k1_lofi_engine_rate_conversion(group.effects, true);
        data.groups.push_back(std::move(group));
    }
    if (element.name == "NiSS_Zone") {
        K1ZoneSemantic zone;
        zone.program_ordinal = program_ordinal;
        zone.group_ordinal = group_ordinal;
        if (const auto *index = k1_attribute(element, "groupIdx")) {
            zone.group_ordinal = std::atoi(index->c_str());
        }
        zone.attributes = element.attributes;
        if (parameters != element.children.end()) {
            zone.parameters = parse_k1_zone_parameters(element, *parameters);
        }
        const auto sample = std::find_if(element.children.begin(),
                element.children.end(), [](const K1TagElement &child) {
                    return child.name == "Sample";
                });
        if (sample != element.children.end())
            zone.sample = parse_k1_sample(*sample);
        const auto loops = std::find_if(element.children.begin(),
                element.children.end(), [](const K1TagElement &child) {
                    return child.name == "Loops";
                });
        if (loops != element.children.end()) {
            for (const auto &loop : loops->children) {
                if (loop.name != "Loop")
                    continue;
                auto parsed = parse_k1_loop(loop);
                if (zone.sample &&
                        static_cast<std::uint32_t>(parsed.mode) > 2U) {
                    if (parsed.start < 0) {
                        parsed.start = 0;
                        parsed.negative_start_clamped = true;
                    }
                    parsed.length_requires_loaded_sample_frame_count = true;
                }
                zone.loops.push_back(std::move(parsed));
            }
        }
        data.zones.push_back(std::move(zone));
    }
    if (element.name == "NiSS_Preset") {
        K1PresetSemantic preset;
        preset.attributes = element.attributes;
        for (const auto &child : element.children) {
            collect_k1_effects(child, preset.effects);
        }
        data.presets.push_back(std::move(preset));
    }
    if (element.name == "NiSS_Bank") {
        K1BankSemantic bank;
        bank.attributes = element.attributes;
        data.banks.push_back(std::move(bank));
    }
    if (element.name == "BatteryPatch") {
        data.battery_programs.push_back(parse_k1_battery_program(element));
    }
    for (const auto &child : element.children)
        collect_k1_semantics(child, data, program_ordinal, group_ordinal);
}

} // namespace

void materialize(K1PatchData &data) {
    data.programs.clear();
    data.groups.clear();
    data.zones.clear();
    data.presets.clear();
    data.banks.clear();
    data.battery_programs.clear();
    for (const auto &element : data.elements)
        collect_k1_semantics(element, data);
}

} // namespace libnki::detail::k1
