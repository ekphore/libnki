// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../internal.h"
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

void parse_k1_tag_stream(std::span<const std::byte> source,
        std::span<const std::string_view> element_names,
        std::span<const std::string_view> attribute_names,
        std::vector<K1TagAttribute> &xml_declaration,
        std::vector<K1TagElement> &elements, std::string_view format_label) {
    xml_declaration.clear();
    elements.clear();
    std::string input;
    input.reserve(source.size());
    for (const auto byte : source) {
        input.push_back(
                static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    struct Reader {
        std::string_view input;
        std::span<const std::string_view> element_names;
        std::span<const std::string_view> attribute_names;
        std::string_view format_label;
        std::size_t pos{};
        std::size_t nodes{};

        [[nodiscard]] std::string error(std::string_view message) const {
            return std::string(format_label) + " " + std::string(message);
        }
        void whitespace() {
            while (pos < input.size() &&
                    (input[pos] == ' ' || input[pos] == '\t' ||
                            input[pos] == '\r' || input[pos] == '\n'))
                ++pos;
        }
        bool consume(std::string_view text) {
            if (input.substr(pos, text.size()) != text)
                return false;
            pos += text.size();
            return true;
        }
        std::string name() {
            const auto begin = pos;
            while (pos < input.size()) {
                const auto c = static_cast<unsigned char>(input[pos]);
                if (!(std::isalnum(c) || c == '_'))
                    break;
                ++pos;
            }
            if (pos == begin)
                throw std::runtime_error(error("tag name expected"));
            return std::string(input.substr(begin, pos - begin));
        }
        std::string quoted() {
            if (pos >= input.size() || input[pos++] != '"') {
                throw std::runtime_error(error("quoted value expected"));
            }
            std::string out;
            while (pos < input.size() && input[pos] != '"') {
                if (input[pos] != '&') {
                    out.push_back(input[pos++]);
                    continue;
                }
                if (consume("&quot;"))
                    out.push_back('"');
                else if (consume("&apos;"))
                    out.push_back('\'');
                else if (consume("&amp;"))
                    out.push_back('&');
                else if (consume("&lt;"))
                    out.push_back('<');
                else if (consume("&#")) {
                    unsigned value = 0;
                    bool any = false;
                    while (pos < input.size() &&
                            std::isdigit(
                                    static_cast<unsigned char>(input[pos]))) {
                        any = true;
                        value = value * 10U +
                                static_cast<unsigned>(input[pos++] - '0');
                    }
                    if (!any || !consume(";")) {
                        throw std::runtime_error(
                                error("invalid numeric character entity"));
                    }
                    out.push_back(static_cast<char>(value));
                } else {
                    throw std::runtime_error(
                            error("unsupported character entity"));
                }
            }
            if (pos >= input.size())
                throw std::runtime_error(error("unterminated value"));
            ++pos;
            return out;
        }
        K1TagAttribute attribute() {
            K1TagAttribute out;
            out.name = name();
            if (std::find(attribute_names.begin(), attribute_names.end(),
                        out.name) == attribute_names.end()) {
                throw std::runtime_error(
                        error("unknown attribute ") + out.name);
            }
            whitespace();
            if (!consume("="))
                throw std::runtime_error(error("attribute '=' expected"));
            whitespace();
            out.value = quoted();
            return out;
        }
        K1TagElement element(std::size_t depth) {
            if (depth > 128 || ++nodes > (1U << 20)) {
                throw std::runtime_error(
                        error("tag nesting/count limit exceeded"));
            }
            if (!consume("<"))
                throw std::runtime_error(error("'<' expected"));
            K1TagElement out;
            out.name = name();
            if (std::find(element_names.begin(), element_names.end(),
                        out.name) == element_names.end()) {
                throw std::runtime_error(error("unknown element ") + out.name);
            }
            for (;;) {
                whitespace();
                if (consume("/>")) {
                    out.self_closing = true;
                    return out;
                }
                if (consume(">"))
                    break;
                out.attributes.push_back(attribute());
            }
            for (;;) {
                whitespace();
                if (consume("</")) {
                    const auto closing = name();
                    whitespace();
                    if (!consume(">") || closing != out.name) {
                        throw std::runtime_error(
                                error("mismatched closing element"));
                    }
                    return out;
                }
                if (pos >= input.size() || input[pos] != '<') {
                    throw std::runtime_error(error("unexpected element text"));
                }
                out.children.push_back(element(depth + 1));
            }
        }
    } reader{ input, element_names, attribute_names, format_label };

    reader.whitespace();
    if (reader.consume("<?")) {
        if (reader.name() != "xml") {
            throw std::runtime_error(reader.error("invalid declaration"));
        }
        for (;;) {
            reader.whitespace();
            if (reader.consume("?>"))
                break;
            xml_declaration.push_back(reader.attribute());
        }
    }
    for (;;) {
        reader.whitespace();
        if (reader.pos == reader.input.size())
            break;
        elements.push_back(reader.element(0));
    }
}

void materialize_k2_semantics(K2PatchData &data);

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

K2ZoneParameters parse_k2_zone_parameters(const K1TagElement &parameters) {
    K2ZoneParameters out;
    for (const auto &value_tag : parameters.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        const auto i16 = [&] { return static_cast<std::int16_t>(integer()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        if (*name == "sampleStart")
            out.sample_start = integer();
        else if (*name == "sampleEnd")
            out.sample_end = integer();
        else if (*name == "sampleStartModRange")
            out.sample_start_modulation_range = integer();
        else if (*name == "lowKey")
            out.low_key = i16();
        else if (*name == "highKey")
            out.high_key = i16();
        else if (*name == "lowVelocity")
            out.low_velocity = i16();
        else if (*name == "highVelocity")
            out.high_velocity = i16();
        else if (*name == "fadeLowKey")
            out.fade_low_key = i16();
        else if (*name == "fadeHighKey")
            out.fade_high_key = i16();
        else if (*name == "fadeLowVelo")
            out.fade_low_velocity = i16();
        else if (*name == "fadeHighVelo")
            out.fade_high_velocity = i16();
        else if (*name == "rootKey")
            out.root_key = i16();
        else if (*name == "zoneVolume")
            out.volume = real();
        else if (*name == "zonePan")
            out.pan = real();
        else if (*name == "zoneTune")
            out.tune = real();
        else if (*name == "morphGroupIdx")
            out.morph_group_index = integer();
        else if (*name == "gridMode") {
            if (*value == "grid_mode_none")
                out.grid_mode = K2GridMode::none;
            else if (*value == "grid_mode_fixed")
                out.grid_mode = K2GridMode::fixed;
            else if (*value == "grid_mode_auto")
                out.grid_mode = K2GridMode::automatic;
        } else if (*name == "fixedUnitNum")
            out.fixed_unit_numerator = integer();
        else if (*name == "fixedUnitDenom")
            out.fixed_unit_denominator = integer();
        else if (*name == "measureNum")
            out.measure_numerator = integer();
        else if (*name == "measureDenom")
            out.measure_denominator = integer();
        else if (*name == "tempoScaling")
            out.tempo_scaling = real();
        else if (*name == "propagateToSliceList")
            out.propagate_to_slice_list_present = true;
        else if (*name == "slicerSens")
            out.slicer_sensitivity = real();
        else if (*name == "isReferenceZone")
            out.reference_zone = *value == "yes";
        else if (*name == "selected")
            out.selected = *value == "yes";
        else if (*name == "zoomScaleX")
            out.zoom_scale_x = integer();
        else if (*name == "zoomScaleY")
            out.zoom_scale_y = real();
        else if (*name == "selectedLoopIdx")
            out.selected_loop_index = i16();
        else if (*name == "zleIdxDisplayed")
            out.displayed_zle_index = i16();
        else if (*name == "grooveBoxID")
            out.groove_box_id = integer();
        else if (*name == "batteryMapPos")
            out.battery_map_position = integer();
        else if (*name == "batteryMapPosGrabStart")
            out.battery_map_grab_start = integer();
        else if (*name == "curEditorTab")
            out.current_editor_tab = integer();
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    if (out.low_velocity)
        *out.low_velocity = std::clamp<std::int16_t>(*out.low_velocity, 1, 127);
    if (out.high_velocity)
        *out.high_velocity = std::min<std::int16_t>(*out.high_velocity, 127);
    if (out.low_velocity && out.high_velocity &&
            *out.low_velocity > *out.high_velocity) {
        *out.low_velocity = *out.high_velocity;
    }
    if (out.low_key)
        *out.low_key = std::clamp<std::int16_t>(*out.low_key, 0, 127);
    if (out.high_key)
        *out.high_key = std::min<std::int16_t>(*out.high_key, 127);
    if (out.low_key && out.high_key && *out.low_key > *out.high_key)
        *out.low_key = *out.high_key;
    if (out.root_key)
        *out.root_key = std::clamp<std::int16_t>(*out.root_key, 0, 127);
    if (out.sample_start && *out.sample_start < 1)
        *out.sample_start = 0;
    if (out.sample_end && *out.sample_end >= 0)
        *out.sample_end = 0;
    if (out.current_editor_tab == 3)
        out.current_editor_tab = 0;
    return out;
}

K2SampleSemantic parse_k2_sample(const K1TagElement &sample) {
    K2SampleSemantic out;
    for (const auto &value_tag : sample.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        if (*name == "file_ex2")
            out.path = *value;
        else if (*name == "file_pbn")
            out.preferred_base_name = *value;
        else if (*name == "lastFileModified")
            out.last_file_modified = std::strtoll(value->c_str(), nullptr, 10);
        else if (*name == "isVolatile")
            out.volatile_sample = *value == "yes";
        else if (*name == "purged")
            out.purged = *value == "yes";
        else if (*name == "uniqueID")
            out.unique_id = integer();
        else if (*name == "lastPlayed")
            out.last_played = std::strtoll(value->c_str(), nullptr, 10);
        else if (*name == "sampleDataType")
            out.sample_data_type = static_cast<std::uint32_t>(integer());
        else if (*name == "sampleRate")
            out.sample_rate = integer();
        else if (*name == "numChannels")
            out.channel_count = integer();
        else if (*name == "numFrames")
            out.frame_count = integer();
        else if (*name == "fileOffsetAudio")
            out.audio_offset = integer();
        else if (*name == "fileOffsetContainer")
            out.container_offset = integer();
        else if (*name == "rootNote")
            out.root_note = integer();
        else if (*name == "tuning")
            out.tuning = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "littleEndian")
            out.little_endian = *value == "yes";
        else if (*name == "expectedDataSize")
            out.expected_data_size = integer();
    }
    return out;
}

K2LoopSemantic parse_k2_loop(const K1TagElement &loop) {
    K2LoopSemantic out;
    out.attributes = loop.attributes;
    for (const auto &value_tag : loop.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "loopStart")
            out.start = std::atoi(value->c_str());
        else if (*name == "loopLength")
            out.length = std::atoi(value->c_str());
        else if (*name == "loopCount")
            out.count = std::atoi(value->c_str());
        else if (*name == "mode" &&
                 (*value == "until_end" || *value == "until_release" ||
                         *value == "oneshot")) {
            out.mode = *value;
        } else if (*name == "alternatingLoop")
            out.alternating = *value == "yes";
        else if (*name == "loopTuning")
            out.tuning = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "xfadeLength")
            out.crossfade_length = std::atoi(value->c_str());
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    return out;
}

K2GroupParameters parse_k2_group_parameters(const K1TagElement &parameters) {
    K2GroupParameters out;
    std::optional<float> serialized_tune;
    for (const auto &value_tag : parameters.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto yes = [&] { return *value == "yes"; };
        if (*name == "volume")
            out.volume = real();
        else if (*name == "pan")
            out.pan = real();
        else if (*name == "tune")
            serialized_tune = real();
        else if (*name == "keyTracking")
            out.key_tracking = yes();
        else if (*name == "reverse")
            out.reverse = yes();
        else if (*name == "releaseTrigger")
            out.release_trigger = yes();
        else if (*name == "releaseTriggerNoteMonophonic")
            out.release_trigger_note_monophonic = yes();
        else if (*name == "rlsTrigCounter")
            out.release_trigger_counter = integer();
        else if (*name == "outputMask")
            out.raw_output_mask = integer();
        else if (*name == "midiChannel")
            out.midi_channel = static_cast<std::int16_t>(integer());
        else if (*name == "voiceGroup")
            out.voice_group = integer();
        else if (*name == "groupPurged")
            out.purged = yes();
        else if (name->starts_with("outRouting_")) {
            const auto index = std::atoi(name->c_str() + 11);
            if (index >= 1 && index <= 16)
                out.output_routing[static_cast<std::size_t>(index - 1)] =
                        *value;
        } else if (*name == "fxIdxAmpSplitPoint")
            out.amp_fx_split_point = integer();
        else if (*name == "selectedForEdit")
            out.selected_for_edit = yes();
        else if (*name == "selectedInGroupEditor")
            out.selected_in_group_editor = yes();
        else if (*name == "zonesVisibleInMapListView")
            out.zones_visible_in_map_list_view = yes();
        else if (*name == "batteryCellColor")
            out.battery_cell_color = integer();
        else if (*name == "batteryLowKey")
            out.battery_low_key = integer();
        else if (*name == "batteryHighKey")
            out.battery_high_key = integer();
        else if (*name == "fxBeingEdited")
            out.fx_being_edited = yes();
        else if (*name == "idxFXBeingEdited")
            out.edited_fx_index = integer();
        else if (*name == "grooveBoxID")
            out.groove_box_id = integer();
        else if (*name == "interpQuality") {
            if (*value == "normal")
                out.interpolation_quality = K2InterpolationQuality::normal;
            else if (*value == "high")
                out.interpolation_quality = K2InterpolationQuality::high;
            else if (*value == "ultra")
                out.interpolation_quality = K2InterpolationQuality::ultra;
        } else if (*name == "muted")
            out.muted = yes();
        else if (*name == "soloed")
            out.soloed = yes();
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    if (serialized_tune) {
        out.tune = out.parsed_version && *out.parsed_version > 0x008f
                           ? std::exp2(*serialized_tune)
                           : *serialized_tune;
    }
    if (out.parsed_version && *out.parsed_version < 0x0080 &&
            out.midi_channel == 0) {
        out.midi_channel = -1;
    }
    return out;
}

K2ProgramParameters parse_k2_program_parameters(
        const K1TagElement &parameters) {
    K2ProgramParameters out;
    std::optional<float> serialized_tune;
    for (const auto &value_tag : parameters.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto yes = [&] { return *value == "yes"; };
        if (*name == "numBytesSamplesTotal")
            out.total_sample_bytes = std::atof(value->c_str());
        // useGroupMIDIChannel carries no program state here
        else if (*name == "transpose")
            out.transpose = static_cast<std::uint8_t>(integer());
        else if (*name == "volume")
            out.volume = real();
        else if (*name == "pan")
            out.pan = real();
        else if (*name == "tune")
            serialized_tune = real();
        else if (*name == "lowVelocity")
            out.low_velocity = static_cast<std::uint8_t>(integer());
        else if (*name == "highVelocity")
            out.high_velocity = static_cast<std::uint8_t>(integer());
        else if (*name == "lowKey")
            out.low_key = static_cast<std::uint8_t>(integer());
        else if (*name == "highKey")
            out.high_key = static_cast<std::uint8_t>(integer());
        else if (*name == "defaultKeyKeySwitch")
            out.default_key_switch = static_cast<std::int16_t>(integer());
        else if (*name == "dfdChannelPreloadSize")
            out.dfd_channel_preload_size = integer();
        else if (*name == "libraryID")
            out.serialized_library_id = static_cast<std::uint32_t>(integer());
        else if (*name == "loadingFlags")
            out.loading_flags = static_cast<std::uint32_t>(integer());
        else if (*name == "groupSolo")
            out.group_solo = yes();
        else if (*name == "cc64Mode") {
            if (*value == "cc64_mode_sustain_plus_controller")
                out.cc64_mode = K2Cc64Mode::sustain_plus_controller;
            else if (*value == "cc64_mode_sustain_without_controller")
                out.cc64_mode = K2Cc64Mode::sustain_without_controller;
            else if (*value == "cc64_mode_controller_only")
                out.cc64_mode = K2Cc64Mode::controller_only;
        } else if (*name == "useStdCC_7_10" || *name == "createStdCCAutObj") {
            out.use_standard_cc_7_10 = yes();
        } else if (*name == "useStdCC_120_123")
            out.use_standard_cc_120_123 = yes();
        else if (*name == "cc7MaxVolume")
            out.cc7_max_volume = integer();
        else if (*name == "autoLoadMode")
            out.auto_load_mode = yes();
        else if (*name == "activeGroupIdx")
            out.active_group_index = integer();
        else if (*name == "scriptIdxEdited")
            out.edited_script_index = integer();
        else if (*name == "ifxBeingEdited")
            out.instrument_fx_being_edited = yes();
        else if (*name == "idxIFXBeingEdited")
            out.edited_instrument_fx_index = integer();
        else if (*name == "sfxBeingEdited")
            out.send_fx_being_edited = yes();
        else if (*name == "idxSFXBeingEdited")
            out.edited_send_fx_index = integer();
        else if (*name == "mapEditListMode")
            out.map_editor_list_mode = yes();
        // mapEditAutoSelectGroups carries no program state here
        else if (*name == "mapEditLocked")
            out.map_editor_locked = yes();
        else if (*name == "routersOpenSource")
            out.source_routers_open = yes();
        else if (*name == "routersOpenAmp")
            out.amp_routers_open = yes();
        else if (*name == "upDownMixOpenGroup")
            out.up_down_mix_open_group = yes();
        else if (*name == "editorOpenMap")
            out.map_editor_open = yes();
        else if (*name == "editorOpenSample")
            out.sample_editor_open = yes();
        else if (*name == "editorOpenGroup")
            out.group_editor_open = yes();
        else if (*name == "editorOpenScript")
            out.script_editor_open = yes();
        else if (*name == "editorOpenProp")
            out.properties_editor_open = yes();
        else if (*name == "mapEditSelGroupsOnly")
            out.map_editor_selected_groups_only = yes();
        else if (*name == "ifxVisible")
            out.instrument_fx_visible = yes();
        else if (*name == "sfxVisible")
            out.send_fx_visible = yes();
        else if (*name == "modVisible")
            out.modulation_visible = yes();
        else if (*name == "masterZoneIdx")
            out.master_zone_index = integer();
        else if (*name == "batteryNumRowsVisible")
            out.battery_visible_rows = integer();
        else if (*name == "batteryNumColumnsVisible")
            out.battery_visible_columns = integer();
        else if (*name == "batteryIRCVisible")
            out.battery_irc_visible = yes();
        else if (*name == "perfViewScriptIdx")
            out.performance_view_script_index =
                    static_cast<std::int16_t>(integer());
        else if (*name == "catIconIdx")
            out.category_icon_index = integer();
        else if (*name == "instrumentCredits")
            out.instrument_credits = *value;
        else if (*name == "instrumentAuthor")
            out.instrument_author = *value;
        else if (*name == "instrumentURL")
            out.instrument_url = *value;
        else if (*name == "instrumentCat1")
            out.instrument_category_1 = static_cast<std::int16_t>(integer());
        else if (*name == "instrumentCat2")
            out.instrument_category_2 = static_cast<std::int16_t>(integer());
        else if (*name == "instrumentCat3")
            out.instrument_category_3 = static_cast<std::int16_t>(integer());
        else if (*name == "wallpaperFile")
            out.serialized_wallpaper_path = *value;
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    if (serialized_tune) {
        out.tune = out.parsed_version && *out.parsed_version > 0x006f
                           ? std::exp2(*serialized_tune)
                           : *serialized_tune;
    }
    return out;
}

K2VoiceLimitSemantic parse_k2_voice_limit(const K1TagElement &element) {
    K2VoiceLimitSemantic out;
    out.attributes = element.attributes;
    for (const auto &value_tag : element.children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "name")
            out.name = *value;
        else if (*name == "mode") {
            if (*value == "kill_any")
                out.mode = K2VoiceStealMode::any;
            else if (*value == "kill_oldest")
                out.mode = K2VoiceStealMode::oldest;
            else if (*value == "kill_newest")
                out.mode = K2VoiceStealMode::newest;
            else if (*value == "kill_highest")
                out.mode = K2VoiceStealMode::highest;
            else if (*value == "kill_lowest")
                out.mode = K2VoiceStealMode::lowest;
        } else if (*name == "preferReleased")
            out.prefer_released = *value == "yes";
        else if (*name == "maxNumVoices")
            out.maximum_voices = std::atoi(value->c_str());
        else if (*name == "msFadeTime")
            out.fade_time_ms = std::atoi(value->c_str());
        else if (*name == "exclusionGroup")
            out.exclusion_group = std::atoi(value->c_str());
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    return out;
}

K2StartCriteriaSemantic parse_k2_start_criteria(const K1TagElement &element) {
    K2StartCriteriaSemantic out;
    out.attributes = element.attributes;
    const auto *values = &element;
    for (const auto &child : element.children)
        if (child.name == "Parameters")
            values = &child;
    for (const auto &value_tag : values->children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        if (*name == "mode") {
            if (*value == "on_key")
                out.mode = K2StartMode::on_key;
            else if (*value == "on_controller")
                out.mode = K2StartMode::on_controller;
            else if (*value == "cycle_round_robin")
                out.mode = K2StartMode::cycle_round_robin;
            else if (*value == "cycle_random")
                out.mode = K2StartMode::cycle_random;
            else if (*value == "slice_trigger")
                out.mode = K2StartMode::slice_trigger;
        } else if (*name == "key_min")
            out.minimum_key = static_cast<std::int16_t>(integer());
        else if (*name == "key_max")
            out.maximum_key = static_cast<std::int16_t>(integer());
        else if (*name == "controller")
            out.controller = static_cast<std::int16_t>(integer());
        else if (*name == "cc_min")
            out.minimum_cc = static_cast<std::int16_t>(integer());
        else if (*name == "cc_max")
            out.maximum_cc = static_cast<std::int16_t>(integer());
        else if (*name == "cycleClass")
            out.cycle_class = integer();
        else if (*name == "sliceZoneIdx")
            out.slice_zone_index = integer();
        else if (*name == "sliceZoneSliceIdx")
            out.slice_index = integer();
        else if (*name == "sequencerOnly")
            out.sequencer_only = *value == "yes";
        else if (*name == "nextCriteria") {
            if (*value == "and")
                out.next_criteria = K2NextCriteria::and_also;
            else if (*value == "and_not")
                out.next_criteria = K2NextCriteria::and_not;
            else if (*value == "or")
                out.next_criteria = K2NextCriteria::or_else;
        } else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    return out;
}

K2SourceModeSemantic parse_k2_source_mode(const K1TagElement &element) {
    K2SourceModeSemantic out;
    out.attributes = element.attributes;
    const auto *values = &element;
    for (const auto &child : element.children)
        if (child.name == "Parameters")
            values = &child;
    std::optional<float> serialized_formant;
    for (const auto &value_tag : values->children) {
        if (value_tag.name != "V")
            continue;
        const auto *name = tag_attribute(value_tag, "name");
        const auto *value = tag_attribute(value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto yes = [&] { return *value == "yes"; };
        if (*name == "type") {
            if (*value == "tone_machine")
                out.mode = K2SourceMode::tone_machine;
            else if (*value == "time_machine")
                out.mode = K2SourceMode::time_machine;
            else if (*value == "streaming")
                out.mode = K2SourceMode::streaming;
            else if (*value == "slice_machine")
                out.mode = K2SourceMode::slice_machine;
            else if (*value == "time_machine2")
                out.mode = K2SourceMode::time_machine_2;
            else if (*value == "sp1200_machine")
                out.mode = K2SourceMode::sp1200_machine;
            else if (*value == "mpc60_machine")
                out.mode = K2SourceMode::mpc60_machine;
        } else if (*name == "speed")
            out.speed = real();
        else if (*name == "smooth")
            out.smooth = real();
        else if (*name == "retrigger")
            out.serialized_retrigger = yes();
        else if (*name == "legato")
            out.legato = yes();
        else if (*name == "sp1200Filter")
            out.sp1200_filter = integer();
        else if (*name == "zoneLockedSpeed")
            out.zone_locked_speed = yes();
        else if (*name == "noteValue_speed") {
            out.note_value_speed = real();
            out.note_value_speed_enabled = *out.note_value_speed > 1.0e-9F;
        } else if (*name == "formantShift")
            serialized_formant = real();
        else if (*name == "grainLength")
            out.grain_length = real();
        else if (*name == "dcFilter")
            out.dc_filter = yes();
        else if (*name == "hiQuality")
            out.high_quality = yes();
        else if (*name == "sliceAttack")
            out.slice_attack = real();
        else if (*name == "sliceRelease")
            out.slice_release = real();
        else if (*name == "sliceAutoPlay")
            out.slice_auto_play = yes();
        else if (*name == "transientCopy")
            out.transient_copy = yes();
        else if (*name == "transientSize")
            out.transient_size = integer();
        else if (*name == "analysisGrainSize")
            out.analysis_grain_size = integer();
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    if (out.parsed_version && *out.parsed_version < 0x0090 &&
            out.serialized_retrigger) {
        out.legato = out.serialized_retrigger;
    }
    if (serialized_formant) {
        out.formant_shift = out.parsed_version && *out.parsed_version < 0x0100
                                    ? std::log2(*serialized_formant)
                                    : *serialized_formant;
    }
    if (out.mode == K2SourceMode::streaming) {
        out.requires_loaded_sample_streamability_check = true;
        out.non_streamable_fallback_runtime_type = 0U;
    }
    if (out.mode == K2SourceMode::slice_machine) {
        out.missing_slices_require_runtime_grid_initialization = true;
        out.missing_slices_runtime_grid_mode = 1U;
    }
    return out;
}

void collect_k2_value_tags(const K1TagElement &element,
        std::vector<const K1TagElement *> &values) {
    for (const auto &child : element.children) {
        if (child.name == "V")
            values.push_back(&child);
        else
            collect_k2_value_tags(child, values);
    }
}

K2SliceSemantic parse_k2_slice(const K1TagElement &element) {
    K2SliceSemantic out;
    out.attributes = element.attributes;
    if (const auto *index = tag_attribute(element, "index"))
        out.index = std::atoi(index->c_str());
    std::vector<const K1TagElement *> values;
    collect_k2_value_tags(element, values);
    for (const auto *value_tag : values) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "index")
            out.index = std::atoi(value->c_str());
        else if (*name == "pos")
            out.position = std::atoi(value->c_str());
        else if (*name == "flags")
            out.flags = std::atoi(value->c_str());
    }
    return out;
}

std::optional<std::pair<std::uint32_t, bool>> resolve_k2_mod_target(
        std::string_view name) {
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
                    { "legacyAddIntensity", 0xf4 },
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
                    { "crywahPedal", 0x3d },
                    { "dyx_morph", 0x43 },
                    { "dyx_dry", 0x44 },
                    { "skr_tone", 0x47 },
                    { "skr_drive", 0x48 },
                    { "sslgeq_hp_freq", 0x55 },
                    { "sslgeq_lf_gain", 0x4b },
                    { "sslgeq_lf_freq", 0x4c },
                    { "sslgeq_lmf_gain", 0x4d },
                    { "sslgeq_lmf_freq", 0x4e },
                    { "sslgeq_lmf_q", 0x4f },
                    { "sslgeq_hmf_gain", 0x50 },
                    { "sslgeq_hmf_freq", 0x51 },
                    { "sslgeq_hmf_q", 0x52 },
                    { "sslgeq_hf_gain", 0x53 },
                    { "sslgeq_hf_freq", 0x54 },
                    { "sslgeq_lp_freq", 0x56 },
                    { "tape_gain", 0x59 },
                    { "tape_warmth", 0x5a },
                    { "tape_hfrolloff", 0x5b },
                    { "stereoSpreadIntensity", 0x5e },
                    { "stereoPan", 0x5f },
                    { "shaper", 0x62 },
                    { "bitdepth", 0x65 },
                    { "downsample", 0x66 },
                    { "noiselevel", 0x67 },
                    { "noisecolor", 0x68 },
                    { "off_distance", 0x6b },
                    { "off_azimuth", 0x6c },
                    { "off_x", 0x6d },
                    { "off_y", 0x6e },
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
            [name](const auto &entry) { return entry.first == name; });
    if (found != direct.end())
        return std::pair{ found->second, true };
    const auto decimal_suffix =
            [&](std::string_view prefix) -> std::optional<unsigned> {
        if (!name.starts_with(prefix) || name.size() == prefix.size())
            return std::nullopt;
        unsigned value = 0;
        for (const char c : name.substr(prefix.size())) {
            if (c < '0' || c > '9')
                return std::nullopt;
            value = value * 10U + static_cast<unsigned>(c - '0');
        }
        return value;
    };
    if (const auto index = decimal_suffix("sendLevel"); index && *index <= 7) {
        return std::pair{ 0x71U + *index, true };
    }
    if (name.starts_with("scLevelB") && name.size() == 10) {
        const auto tens = name[8] - '0';
        const auto ones = name[9] - '0';
        if (tens >= 0 && tens <= 9 && ones >= 0 && ones <= 9) {
            const auto index = static_cast<unsigned>(tens * 10 + ones);
            if (index <= 15)
                return std::pair{ 0x79U + index, true };
        }
    }
    if (name == "scLevelPGM")
        return std::pair{ 0x89U, true };
    for (const auto &[prefix, base] :
            std::to_array<std::pair<std::string_view, unsigned>>(
                    { { "fm7_level", 0xc3 }, { "fm7_time", 0xcd },
                            { "fm7_slope", 0xd7 } })) {
        if (const auto index = decimal_suffix(prefix);
                index && *index >= 1 && *index <= 8) {
            return std::pair{ base + *index, true };
        }
    }
    if (const auto index = decimal_suffix("arp32step_v");
            index && *index >= 1 && *index <= 32) {
        return std::pair{ 0x8cU + *index, true };
    }
    if (name == "intensity_nc")
        return std::pair{ 0x19U, true };
    if (name == "intensity_upper")
        return std::pair{ 0x19U, false };
    if (name == "sendLevelDelay")
        return std::pair{ 0x71U, true };
    if (name == "sendLevelChorus")
        return std::pair{ 0x72U, true };
    if (name == "sendLevelFlanger")
        return std::pair{ 0x73U, true };
    if (name == "sendLevelPhaser")
        return std::pair{ 0x74U, true };
    if (name == "sendLevelReverb")
        return std::pair{ 0x75U, true };
    return std::nullopt;
}

K2ZleSemantic parse_k2_zle(const K1TagElement &element) {
    K2ZleSemantic out;
    out.attributes = element.attributes;
    if (const auto *index = tag_attribute(element, "index"))
        out.index = std::atoi(index->c_str());
    std::vector<const K1TagElement *> values;
    collect_k2_value_tags(element, values);
    for (const auto *value_tag : values) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "index")
            out.index = std::atoi(value->c_str());
        else if (*name == "extModIdx")
            out.external_modulator_index =
                    static_cast<std::int16_t>(std::atoi(value->c_str()));
        else if (*name == "loopStart")
            out.loop_start = std::atoi(value->c_str());
        else if (*name == "loopLength")
            out.loop_length = std::atoi(value->c_str());
        else if (*name == "loopActive")
            out.loop_active = *value == "yes";
        else if (*name == "speedLock")
            out.speed_lock = *value == "yes";
        else if (*name == "target") {
            out.serialized_target = *value;
            if (const auto target = resolve_k2_mod_target(*value)) {
                out.target_id = target->first;
                out.target_lower_polarity = target->second;
            }
        } else if (*name == "targetIdx")
            out.target_index =
                    static_cast<std::uint8_t>(std::atoi(value->c_str()));
        else if (!name->empty() && ((*name)[0] == 'x' || (*name)[0] == 'y' ||
                                           (*name)[0] == 'c')) {
            const auto segment_index = std::atoi(name->c_str() + 1);
            if (segment_index < 0)
                continue;
            const auto size = static_cast<std::size_t>(segment_index) + 1;
            if (out.segments.size() < size)
                out.segments.resize(size);
            auto &segment =
                    out.segments[static_cast<std::size_t>(segment_index)];
            segment.index = segment_index;
            if ((*name)[0] == 'x')
                segment.x = std::atoi(value->c_str());
            else if ((*name)[0] == 'y')
                segment.y = static_cast<float>(std::atof(value->c_str()));
            else
                segment.curve = static_cast<float>(std::atof(value->c_str()));
        }
    }
    return out;
}

K2ModTargetSemantic parse_k2_mod_target(const K1TagElement &element) {
    K2ModTargetSemantic out;
    out.attributes = element.attributes;
    if (const auto *index = tag_attribute(element, "index"))
        out.index = std::atoi(index->c_str());
    std::vector<const K1TagElement *> values;
    collect_k2_value_tags(element, values);
    bool table_seen = false;
    int previous_table_index = -1;
    bool curve_seen = false;
    for (const auto *value_tag : values) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        if (*name == "index")
            out.index = integer();
        else if (*name == "target") {
            out.serialized_target = *value;
            if (const auto target = resolve_k2_mod_target(*value)) {
                out.target_id = target->first;
                out.target_lower_polarity = target->second;
            }
        } else if (*name == "intensity")
            out.intensity = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "slotIdx")
            out.slot_index = static_cast<std::int16_t>(integer());
        else if (*name == "flags")
            out.flags = static_cast<std::uint8_t>(integer());
        else if (*name == "smoothingCoef")
            out.smoothing_coefficient = static_cast<std::int16_t>(integer());
        else if (*name == "targetObjIdx")
            out.target_object_index = static_cast<std::uint8_t>(integer());
        else if (*name == "name")
            out.name = *value;
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "tableOpen")
            out.table_open = *value == "yes";
        else if (*name == "tableActive")
            out.table_active = *value == "yes";
        else if (*name == "curveActive")
            out.curve_active = *value == "yes";
        else {
            int parsed_index{};
            if (std::sscanf(name->c_str(), "t%d", &parsed_index) == 1) {
                if (!table_seen) {
                    for (std::size_t i = 0; i < out.table.size(); ++i) {
                        out.table[i] = static_cast<float>(i) / 128.0F;
                    }
                    table_seen = true;
                }
                const auto index = std::clamp(parsed_index, 0, 127);
                const auto current =
                        static_cast<float>(std::atof(value->c_str()));
                if (previous_table_index >= 0 &&
                        previous_table_index + 1 != index &&
                        previous_table_index <= index) {
                    const auto first = out.table[static_cast<std::size_t>(
                            previous_table_index)];
                    const auto delta = current - first;
                    const auto distance = index - previous_table_index;
                    for (int i = previous_table_index; i < index; ++i) {
                        // clang-format off
                        out.table[static_cast<std::size_t>(i)] = first + delta *
                                static_cast<float>(i - previous_table_index) /
                                static_cast<float>(distance);
                        // clang-format on
                    }
                }
                out.table[static_cast<std::size_t>(index)] = current;
                previous_table_index = index;
            } else {
                char coordinate{};
                if ((std::sscanf(name->c_str(), "%c%d", &coordinate,
                             &parsed_index) == 2) &&
                        (coordinate == 'x' || coordinate == 'y' ||
                                coordinate == 'c')) {
                    if (!curve_seen) {
                        out.curve = { { 0.0F, 0.0F, 0.0F },
                            { 1.0F, 1.0F, 0.0F } };
                        curve_seen = true;
                    }
                    const auto index = std::clamp(parsed_index, 0, 31);
                    if (out.curve.size() <= static_cast<std::size_t>(index)) {
                        out.curve.resize(static_cast<std::size_t>(index) + 1);
                    }
                    auto &point = out.curve[static_cast<std::size_t>(index)];
                    const auto real =
                            static_cast<float>(std::atof(value->c_str()));
                    if (coordinate == 'x')
                        point.x = real;
                    else if (coordinate == 'y')
                        point.y = real;
                    else
                        point.curve = real;
                }
            }
        }
    }
    out.has_table = table_seen;
    out.has_curve = curve_seen;
    if (out.flags)
        *out.flags = static_cast<std::uint8_t>(*out.flags | 0x10U);
    return out;
}

void collect_k2_mod_targets(const K1TagElement &element,
        std::vector<K2ModTargetSemantic> &targets) {
    if (element.name == "Target")
        targets.push_back(parse_k2_mod_target(element));
    for (const auto &child : element.children)
        collect_k2_mod_targets(child, targets);
}

std::vector<const K1TagElement *> k2_mod_parameter_values(
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

K2LfoSemantic parse_k2_lfo(const K1TagElement &element) {
    K2LfoSemantic out;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        if (*name == "type") {
            if (*value == "sine")
                out.waveform = K2LfoWaveform::sine;
            else if (*value == "rectangle")
                out.waveform = K2LfoWaveform::rectangle;
            else if (*value == "triangle")
                out.waveform = K2LfoWaveform::triangle;
            else if (*value == "sawtooth")
                out.waveform = K2LfoWaveform::sawtooth;
            else if (*value == "random")
                out.waveform = K2LfoWaveform::random;
            else if (*value == "multi")
                out.waveform = K2LfoWaveform::multi;
        } else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "delay")
            out.delay = real();
        else if (*name == "frequency")
            out.frequency = real();
        else if (*name == "pulseWidth")
            out.pulse_width = real();
        else if (*name == "startPhase")
            out.start_phase = real();
        else if (*name == "normalizeMultiLFO")
            out.normalize_multi_lfo = *value == "yes";
        else if (*name == "noteValue_frequency") {
            out.note_value_frequency = real();
            out.note_value_frequency_enabled =
                    *out.note_value_frequency > 1.0e-9F;
        } else if (*name == "noteValue_delay") {
            out.note_value_delay = real();
            out.note_value_delay_enabled = *out.note_value_delay > 1.0e-9F;
        } else if (*name == "levelSine")
            out.sine_level = real();
        else if (*name == "levelRectangle")
            out.rectangle_level = real();
        else if (*name == "levelTriangle")
            out.triangle_level = real();
        else if (*name == "levelSawtooth")
            out.sawtooth_level = real();
        else if (*name == "levelRandom")
            out.random_level = real();
    }
    return out;
}

K2EnvelopeSemantic parse_k2_envelope(const K1TagElement &element) {
    K2EnvelopeSemantic out;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        const auto integer = [&] { return std::atoi(value->c_str()); };
        if (*name == "type") {
            if (*value == "ahdsr")
                out.type = K2EnvelopeType::ahdsr;
            else if (*value == "fm7")
                out.type = K2EnvelopeType::fm7;
            else if (*value == "dbd")
                out.type = K2EnvelopeType::dbd;
        } else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "atkCurving")
            out.attack_curving = real();
        else if (*name == "attack")
            out.attack = real();
        else if (*name == "decay")
            out.decay = real();
        else if (*name == "hold")
            out.hold = real();
        else if (*name == "release")
            out.release = real();
        else if (*name == "sustain")
            out.sustain = real();
        else if (*name == "noteOffLessMode")
            out.note_off_less_mode = *value == "yes";
        else if (*name == "notevalue_attack")
            out.note_value_attack = real();
        else if (*name == "notevalue_decay")
            out.note_value_decay = real();
        else if (*name == "notevalue_hold")
            out.note_value_hold = real();
        else if (*name == "notevalue_release")
            out.note_value_release = real();
        else if (*name == "decay1")
            out.decay_1 = real();
        else if (*name == "break")
            out.break_level = real();
        else if (*name == "decay2")
            out.decay_2 = real();
        else if (*name == "notevalue_decay1")
            out.note_value_decay_1 = real();
        else if (*name == "notevalue_decay2")
            out.note_value_decay_2 = real();
        else if (*name == "releaseEnd")
            out.release_end = integer();
        else if (*name == "loopStart")
            out.loop_start = integer();
        else if (*name == "loopEnd")
            out.loop_end = integer();
        else if (*name == "loopEnabled")
            out.loop_enabled = *value == "yes";
        else if (*name == "oneshotMode")
            out.one_shot_mode = *value == "yes";
        else if (*name == "notevalue_grid")
            out.note_value_grid = real();
        else {
            int index{};
            if (std::sscanf(name->c_str(), "time%d", &index) == 1 &&
                    index >= 0 && index < 32) {
                out.times[static_cast<std::size_t>(index)] = real();
            } else if (std::sscanf(name->c_str(), "level%d", &index) == 1 &&
                       index >= 0 && index < 32) {
                out.levels[static_cast<std::size_t>(index)] = real();
            } else if (std::sscanf(name->c_str(), "slope%d", &index) == 1 &&
                       index >= 0 && index < 32) {
                out.slopes[static_cast<std::size_t>(index)] = real();
            }
        }
    }
    return out;
}

K2EnvelopeFollowerSemantic parse_k2_envelope_follower(
        const K1TagElement &element) {
    K2EnvelopeFollowerSemantic out;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto real = [&] {
            return static_cast<float>(std::atof(value->c_str()));
        };
        // the follower's type tag doesn't select any persistent state
        if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "attack")
            out.attack = real();
        else if (*name == "decay")
            out.decay = real();
        else if (*name == "gain")
            out.gain = real();
        else if (*name == "adaptionSpeed")
            out.adaptation_speed = real();
    }
    if (out.parsed_version && *out.parsed_version < 0x0060 &&
            out.adaptation_speed && *out.adaptation_speed > 0.0F) {
        *out.adaptation_speed = std::log2(*out.adaptation_speed) * 6.0F;
    }
    return out;
}

K2GlideSemantic parse_k2_glide(const K1TagElement &element) {
    K2GlideSemantic out;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "type") {
            if (*value == "speed")
                out.type = K2GlideType::speed;
            else if (*value == "time")
                out.type = K2GlideType::time;
        } else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "coef")
            out.coefficient = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "notevalue_coef") {
            out.note_value_coefficient =
                    static_cast<float>(std::atof(value->c_str()));
            out.note_value_coefficient_enabled =
                    *out.note_value_coefficient > 1.0e-9F;
        }
    }
    return out;
}

K2ArpeggiatorSemantic parse_k2_arpeggiator(const K1TagElement &element) {
    K2ArpeggiatorSemantic out;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "type")
            out.recognized_32_step_type = *value == "_32step";
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "snapTo12")
            out.snap_to_12 = *value == "yes";
        else if (*name == "numSteps")
            out.step_count = std::atoi(value->c_str());
        else if (*name == "singleTrigger")
            out.single_trigger = *value == "yes";
        else if (*name == "frequency")
            out.frequency = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "noteValue_frequency") {
            out.note_value_frequency =
                    static_cast<float>(std::atof(value->c_str()));
            out.note_value_frequency_enabled =
                    *out.note_value_frequency > 1.0e-9F;
        } else {
            int index{};
            if (std::sscanf(name->c_str(), "step_%d", &index) == 1 &&
                    index >= 0 && index < 32) {
                out.steps[static_cast<std::size_t>(index)] =
                        static_cast<float>(std::atof(value->c_str()));
            }
        }
    }
    return out;
}

K2ExternalModSemantic parse_k2_external_mod(const K1TagElement &element) {
    K2ExternalModSemantic out;
    out.attributes = element.attributes;
    collect_k2_mod_targets(element, out.targets);
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        const auto integer = [&] { return std::atoi(value->c_str()); };
        if (*name == "type") {
            if (*value == "extMod")
                out.type = K2ExternalModType::external;
            else if (*value == "zenvMod")
                out.type = K2ExternalModType::zone_envelope;
        } else if (*name == "source") {
            if (*value == "pitchBend")
                out.source = K2ExternalModSource::pitch_bend;
            else if (*value == "polyAfterTouch")
                out.source = K2ExternalModSource::poly_aftertouch;
            else if (*value == "monoAfterTouch")
                out.source = K2ExternalModSource::mono_aftertouch;
            else if (*value == "midiCC")
                out.source = K2ExternalModSource::midi_cc;
            else if (*value == "keyPos")
                out.source = K2ExternalModSource::key_position;
            else if (*value == "velocity")
                out.source = K2ExternalModSource::velocity;
            else if (*value == "releaseVelocity")
                out.source = K2ExternalModSource::release_velocity;
            else if (*value == "rlsTrigCounter")
                out.source = K2ExternalModSource::release_trigger_counter;
            else if (*value == "constVal")
                out.source = K2ExternalModSource::constant;
            else if (*value == "randomValUni")
                out.source = K2ExternalModSource::random_unipolar;
            else if (*value == "randomValBi")
                out.source = K2ExternalModSource::random_bipolar;
        } else if (*name == "ccNumber")
            out.cc_number = static_cast<std::uint8_t>(integer());
        else if (*name == "bypass")
            out.bypass = *value == "yes";
        // legacyStatModBehaviour only counts as a compatibility tag
        else if (*name == "simulateK2EnvTimeModulation")
            out.simulate_k2_envelope_time_modulation = *value == "yes";
        else if (*name == "classID")
            out.class_id = integer();
        else if (*name == "name")
            out.name = *value;
        else if (*name == "delay")
            out.serialized_delay =
                    static_cast<float>(std::atof(value->c_str()));
        else if (*name == "initialValue")
            out.initial_value = static_cast<std::int16_t>(integer());
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }
    if (out.parsed_version && *out.parsed_version < 0x0100) {
        out.simulate_k2_envelope_time_modulation = true;
        out.class_id = -1;
        if (out.initial_value && *out.initial_value >= 0) {
            *out.initial_value = static_cast<std::int16_t>(
                    (static_cast<std::int32_t>(*out.initial_value) * 127) /
                    100);
        }
        for (auto &target : out.targets) {
            if (target.intensity && target.flags) {
                if (*target.intensity < 0.0F) {
                    *target.intensity = -*target.intensity;
                    *target.flags =
                            static_cast<std::uint8_t>(*target.flags | 0x02U);
                } else {
                    *target.flags =
                            static_cast<std::uint8_t>(*target.flags & ~0x02U);
                }
            }
            if (target.flags) {
                const auto flags = *target.flags;
                const auto migrated_polarity =
                        static_cast<std::uint8_t>((flags >> 1U) & 0x04U);
                *target.flags = static_cast<std::uint8_t>(
                        migrated_polarity | (flags & 0xf3U));
                if (out.initial_value && *out.initial_value < 0 &&
                        target.target_id &&
                        ((*target.target_id >= 0x71U &&
                                 *target.target_id <= 0x89U) ||
                                (*target.target_id == 0x19U &&
                                        migrated_polarity == 0))) {
                    *out.initial_value = 0;
                }
            }
            if (out.serialized_delay) {
                target.smoothing_coefficient = static_cast<std::int16_t>(
                        static_cast<std::int32_t>(*out.serialized_delay));
            }
            const bool remap_table =
                    out.source == K2ExternalModSource::pitch_bend ||
                    out.source == K2ExternalModSource::key_position ||
                    out.source == K2ExternalModSource::random_bipolar;
            if (remap_table && target.has_table && target.table_active) {
                for (auto &entry : target.table)
                    entry = entry * 0.5F + 0.5F;
            }
        }
    }
    return out;
}

K2InternalModSemantic parse_k2_internal_mod(const K1TagElement &element) {
    K2InternalModSemantic out;
    out.attributes = element.attributes;
    collect_k2_mod_targets(element, out.targets);
    for (const auto &child : element.children) {
        if (child.name == "LFO") {
            out.kind = K2InternalModSemantic::Kind::lfo;
            out.lfo = parse_k2_lfo(child);
        } else if (child.name == "Envelope") {
            out.kind = K2InternalModSemantic::Kind::envelope;
            out.envelope = parse_k2_envelope(child);
        } else if (child.name == "Arpegg") {
            out.kind = K2InternalModSemantic::Kind::arpeggiator;
            out.arpeggiator = parse_k2_arpeggiator(child);
        } else if (child.name == "EnvFollow") {
            out.kind = K2InternalModSemantic::Kind::envelope_follower;
            out.envelope_follower = parse_k2_envelope_follower(child);
        } else if (child.name == "Glide") {
            out.kind = K2InternalModSemantic::Kind::glide;
            out.glide = parse_k2_glide(child);
        }
    }
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "routersOpen")
            out.routers_open = *value == "yes";
        else if (*name == "noteValue_frequency")
            out.serialized_note_value_frequency =
                    static_cast<float>(std::atof(value->c_str()));
        else if (*name == "bypass")
            out.bypass = *value == "yes";
        else if (*name == "retrigger")
            out.retrigger = *value == "yes";
        // legacyVolumeEnvBehaviour only counts as a compatibility tag
        else if (*name == "classID")
            out.class_id = std::atoi(value->c_str());
        else if (*name == "name")
            out.name = *value;
        else if (*name == "frequency")
            out.serialized_frequency =
                    static_cast<float>(std::atof(value->c_str()));
        else if (*name == "pulseWidth")
            out.serialized_pulse_width =
                    static_cast<float>(std::atof(value->c_str()));
        else if (*name == "simulateK2DFDVolModulation")
            out.simulate_k2_dfd_volume_modulation = *value == "yes";
        else if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
    }

    // use the LFO's version here, not the enclosing modulator's
    if (out.kind == K2InternalModSemantic::Kind::lfo && out.lfo &&
            out.lfo->parsed_version && *out.lfo->parsed_version <= 0x006f) {
        out.lfo->normalize_multi_lfo = true;
        if (out.lfo->waveform == K2LfoWaveform::sine) {
            out.lfo->pulse_width = 0.5F;
        } else if (out.lfo->waveform == K2LfoWaveform::triangle) {
            out.lfo->pulse_width = 0.75F;
        } else if (out.lfo->waveform == K2LfoWaveform::rectangle) {
            for (auto &target : out.targets) {
                if (target.flags)
                    *target.flags =
                            static_cast<std::uint8_t>(*target.flags ^ 0x02U);
            }
        }
    }

    if (out.kind == K2InternalModSemantic::Kind::envelope && out.envelope &&
            out.envelope->type == K2EnvelopeType::dbd && out.parsed_version &&
            *out.parsed_version < 0x0070) {
        for (auto &target : out.targets) {
            if (target.target_id == 6U && target.intensity)
                *target.intensity /= 3.0F;
        }
    }

    if (out.parsed_version && *out.parsed_version < 0x0080) {
        out.simulate_k2_dfd_volume_modulation = true;
        out.class_id = -1;
        for (auto &target : out.targets) {
            if (target.intensity && target.flags) {
                if (*target.intensity < 0.0F) {
                    *target.intensity = -*target.intensity;
                    *target.flags =
                            static_cast<std::uint8_t>(*target.flags | 0x02U);
                } else {
                    *target.flags =
                            static_cast<std::uint8_t>(*target.flags & ~0x02U);
                }
            }
            if (target.flags) {
                const auto flags = *target.flags;
                *target.flags = static_cast<std::uint8_t>(
                        ((flags >> 1U) & 0x04U) | (flags & 0xf3U));
            }
            const bool remap_table =
                    out.kind == K2InternalModSemantic::Kind::lfo ||
                    out.kind == K2InternalModSemantic::Kind::arpeggiator ||
                    out.kind == K2InternalModSemantic::Kind::glide ||
                    (out.kind == K2InternalModSemantic::Kind::envelope &&
                            out.envelope &&
                            out.envelope->type == K2EnvelopeType::dbd);
            if (remap_table && target.has_table && target.table_active) {
                for (auto &entry : target.table)
                    entry = entry * 0.5F + 0.5F;
            }
        }
    }
    return out;
}

K2ScriptSemantic parse_k2_script(const K1TagElement &element) {
    K2ScriptSemantic out;
    out.attributes = element.attributes;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "sourceText")
            out.source_text = *value;
        else if (*name == "sourceEditorOpen")
            out.source_editor_open = *value == "yes";
        else if (*name == "touchedButNotApplied")
            out.touched_but_not_applied = *value == "yes";
        else if (*name == "bypass")
            out.bypass = *value == "yes";
        else if (*name == "password")
            out.serialized_password = *value;
        else if (*name == "description")
            out.description = *value;
        else if (*name == "textFileName")
            out.text_file_name = *value;
        else if (name->starts_with("persistent_var_")) {
            K2ScriptPersistentVariable variable;
            variable.serialized_name_suffix = name->substr(15);
            variable.serialized_value = *value;
            variable.combined_value =
                    variable.serialized_name_suffix + " " + *value;
            out.persistent_variables.push_back(std::move(variable));
        }
    }
    return out;
}

K2MorphGroupSemantic parse_k2_morph_group(const K1TagElement &element) {
    K2MorphGroupSemantic out;
    out.attributes = element.attributes;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "id")
            out.id = std::atoi(value->c_str());
        else if (*name == "name")
            out.name = *value;
        else if (*name == "smoothing")
            out.smoothing = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "left")
            out.left = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "right")
            out.right = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "tonal")
            out.tonal = *value == "yes";
        else if (*name == "rootKeyShift")
            out.root_key_shift =
                    static_cast<std::int16_t>(std::atoi(value->c_str()));
    }
    return out;
}

K2MorphMapSemantic parse_k2_morph_map(const K1TagElement &element) {
    K2MorphMapSemantic out;
    out.attributes = element.attributes;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "type") {
            if (*value == "velocity")
                out.type = K2MorphMapType::velocity;
            else if (*value == "articulation")
                out.type = K2MorphMapType::articulation;
        } else if (*name == "id")
            out.id = std::atoi(value->c_str());
        else if (*name == "name")
            out.name = *value;
        else {
            int index{};
            char tail{};
            if (std::sscanf(name->c_str(), "morph_group_id_%d%c", &index,
                        &tail) == 1 &&
                    index >= 0 && index < 64) {
                out.morph_group_ids[static_cast<std::size_t>(index)] =
                        std::atoi(value->c_str());
            }
        }
    }
    return out;
}

std::optional<std::uint32_t> resolve_k2_automation_parameter_tag(
        std::string_view name) {
    static constexpr auto tags =
            std::to_array<std::pair<std::string_view, std::uint32_t>>({
#include "tables/k2_automation_tags.inc"
            });
    const auto found = std::find_if(tags.begin(), tags.end(),
            [name](const auto &entry) { return entry.first == name; });
    if (found == tags.end())
        return std::nullopt;
    return found->second;
}

K2AutomationSemantic parse_k2_automation(const K1TagElement &element,
        std::int32_t program_index, std::int32_t group_index,
        std::int32_t program_ordinal, std::int32_t group_ordinal) {
    K2AutomationSemantic out;
    out.attributes = element.attributes;
    out.program_index = program_index;
    out.group_index = group_index;
    out.program_ordinal = program_ordinal;
    out.group_ordinal = group_ordinal;
    for (const auto *value_tag : k2_mod_parameter_values(element)) {
        const auto *name = tag_attribute(*value_tag, "name");
        const auto *value = tag_attribute(*value_tag, "value");
        if (name == nullptr || value == nullptr)
            continue;
        if (*name == "version")
            out.parsed_version = parse_k2_dotted_version(*value);
        else if (*name == "adressMode") {
            if (*value == "unknown")
                out.address_mode = K2AutomationAddressMode::unknown;
            else if (*value == "midi_ctrl")
                out.address_mode = K2AutomationAddressMode::midi_controller;
            else if (*value == "host_par")
                out.address_mode = K2AutomationAddressMode::host_parameter;
        } else if (*name == "softTakeOver")
            out.soft_takeover = *value == "yes";
        else if (*name == "programSendFXIsInInsertChain") {
            out.program_send_fx_is_in_insert_chain = *value == "yes";
        } else if (*name == "adress") {
            out.address = static_cast<std::int16_t>(std::atoi(value->c_str()));
        } else if (*name == "parTag") {
            out.serialized_parameter_tag = *value;
            out.parameter_tag_id = resolve_k2_automation_parameter_tag(*value);
        } else if (*name == "objIdx")
            out.object_index = std::atoi(value->c_str());
        else if (*name == "rangeFrom")
            out.range_from = static_cast<float>(std::atof(value->c_str()));
        else if (*name == "rangeTo")
            out.range_to = static_cast<float>(std::atof(value->c_str()));
    }
    if (out.parsed_version && *out.parsed_version < 0x0070 &&
            out.parameter_tag_id == 0x296U) {
        const auto migrate = [](float value) {
            return value >= 0.5F ? (value - 0.5F) / 3.0F + 0.5F
                                 : (0.5F - value) / -3.0F + 0.5F;
        };
        if (out.range_from)
            *out.range_from = migrate(*out.range_from);
        if (out.range_to)
            *out.range_to = migrate(*out.range_to);
    }
    if (out.parameter_tag_id) {
        std::int32_t selector{};
        if (group_index >= 0) {
            selector = 0;
        } else {
            const auto tag = *out.parameter_tag_id;
            std::int32_t serialized =
                    out.program_send_fx_is_in_insert_chain.value_or(false) ? 1
                                                                           : 0;
            if (tag < 0x214U || tag > 0x292U)
                serialized = -1;
            selector = tag >= 0x16U && tag <= 0x211U ? 1 : serialized;
        }
        out.effective_program_object_selector = selector;
        out.effective_program_send_fx_is_in_insert_chain = selector;
    }
    return out;
}

void collect_k2_semantics(const K1TagElement &element, K2PatchData &data,
        std::int32_t program_index = -1, std::int32_t group_index = -1,
        std::int32_t program_ordinal = -1, std::int32_t group_ordinal = -1,
        std::optional<std::int32_t> program_effect_selector = std::nullopt,
        std::int32_t zone_ordinal = -1) {
    if (element.name == "K2_Program") {
        program_ordinal = static_cast<std::int32_t>(data.programs.size());
        if (const auto *index = tag_attribute(element, "index")) {
            program_index = std::atoi(index->c_str());
        }
        group_index = -1;
        group_ordinal = -1;
        zone_ordinal = -1;
        program_effect_selector.reset();
    } else if (element.name == "K2_Group") {
        group_ordinal = 0;
        for (const auto &group : data.groups) {
            if (group.program_ordinal == program_ordinal)
                ++group_ordinal;
        }
        if (const auto *index = tag_attribute(element, "index")) {
            group_index = std::atoi(index->c_str());
        }
        program_effect_selector.reset();
        zone_ordinal = -1;
    } else if (element.name == "K2_Zone") {
        zone_ordinal = static_cast<std::int32_t>(data.zones.size());
    } else if (element.name == "ProgramInsertFX") {
        program_effect_selector = 1;
    } else if (element.name == "ProgramSendFX") {
        program_effect_selector = 0;
    } else if (element.name == "GroupInsertFX") {
        program_effect_selector.reset();
    }
    if (element.name == "K2_Program") {
        K2ProgramSemantic program;
        program.program_ordinal = program_ordinal;
        program.attributes = element.attributes;
        for (const auto &child : element.children) {
            if (child.name == "Parameters")
                program.parameters = parse_k2_program_parameters(child);
        }
        data.programs.push_back(std::move(program));
    }
    if (element.name == "K2_Group") {
        K2GroupSemantic group;
        group.program_ordinal = program_ordinal;
        group.group_ordinal = group_ordinal;
        group.attributes = element.attributes;
        for (const auto &child : element.children) {
            if (child.name == "Parameters")
                group.parameters = parse_k2_group_parameters(child);
        }
        group.effective_selected_for_edit =
                group.parameters && group.parameters->selected_for_edit
                        ? *group.parameters->selected_for_edit
                        : true;
        data.groups.push_back(std::move(group));
    }
    if (element.name == "K2_Zone") {
        K2ZoneSemantic zone;
        zone.zone_ordinal = zone_ordinal;
        zone.program_ordinal = program_ordinal;
        zone.group_ordinal = group_ordinal;
        zone.attributes = element.attributes;
        for (const auto &child : element.children) {
            if (child.name == "Parameters")
                zone.parameters = parse_k2_zone_parameters(child);
            else if (child.name == "Sample")
                zone.sample = parse_k2_sample(child);
            else if (child.name == "Loops") {
                for (const auto &loop : child.children) {
                    if (loop.name == "Loop")
                        zone.loops.push_back(parse_k2_loop(loop));
                }
            }
        }
        zone.removed_by_close_due_to_absent_serialized_sample =
                !zone.sample.has_value();
        data.zones.push_back(std::move(zone));
    }
    if (element.name == "Polyphony" || element.name == "VoiceGroup") {
        auto limit = parse_k2_voice_limit(element);
        limit.program_ordinal = program_ordinal;
        limit.global = element.name == "Polyphony";
        data.voice_limits.push_back(std::move(limit));
    } else if (element.name == "StartCriteria") {
        auto criterion = parse_k2_start_criteria(element);
        criterion.program_ordinal = program_ordinal;
        criterion.group_ordinal = group_ordinal;
        data.start_criteria.push_back(std::move(criterion));
    } else if (element.name == "PlaybackMode") {
        auto source = parse_k2_source_mode(element);
        source.program_ordinal = program_ordinal;
        source.group_ordinal = group_ordinal;
        data.source_modes.push_back(std::move(source));
    } else if (element.name == "Slice") {
        auto slice = parse_k2_slice(element);
        slice.zone_ordinal = zone_ordinal;
        data.slices.push_back(std::move(slice));
    } else if (element.name == "ZLE") {
        data.zles.push_back(parse_k2_zle(element));
    } else if (element.name == "K2_IntMod") {
        auto modulator = parse_k2_internal_mod(element);
        modulator.program_ordinal = program_ordinal;
        modulator.group_ordinal = group_ordinal;
        if (const auto *index = tag_attribute(element, "index")) {
            modulator.serialized_index = std::atoi(index->c_str());
        }
        data.internal_modulators.push_back(std::move(modulator));
    } else if (element.name == "K2_ExtMod") {
        auto modulator = parse_k2_external_mod(element);
        modulator.program_ordinal = program_ordinal;
        modulator.group_ordinal = group_ordinal;
        if (const auto *index = tag_attribute(element, "index")) {
            modulator.serialized_index = std::atoi(index->c_str());
        }
        data.external_modulators.push_back(std::move(modulator));
    } else if (element.name == "Script") {
        data.scripts.push_back(parse_k2_script(element));
    } else if (element.name == "MorphGroup") {
        data.morph_groups.push_back(parse_k2_morph_group(element));
    } else if (element.name == "MorphMap") {
        data.morph_maps.push_back(parse_k2_morph_map(element));
    } else if (element.name == "AutObj") {
        data.automation.push_back(parse_k2_automation(element, program_index,
                group_index, program_ordinal, group_ordinal));
    } else if (element.name == "K2_Effect") {
        auto effect = detail::parse_k2_effect(element);
        effect.program_ordinal = program_ordinal;
        effect.group_ordinal = group_ordinal;
        effect.program_object_selector = program_effect_selector;
        if (const auto *index = tag_attribute(element, "index")) {
            effect.serialized_index = std::atoi(index->c_str());
        }
        data.effects.push_back(std::move(effect));
    } else if (element.name == "K2_Bank") {
        data.banks.push_back(detail::parse_k2_bank(element));
    } else if (element.name == "K2_Container") {
        data.containers.push_back(detail::parse_k2_program_container(element));
    } else if (element.name == "Outputs" ||
               element.name == "OutputsNextPlugin") {
        data.output_configurations.push_back(
                detail::parse_k2_output_configuration(element));
    } else if (element.name == "Output") {
        data.output_partitions.push_back(
                detail::parse_k2_output_partition(element));
    }
    for (const auto &child : element.children) {
        collect_k2_semantics(child, data, program_index, group_index,
                program_ordinal, group_ordinal, program_effect_selector,
                zone_ordinal);
    }
}

void materialize_k2_semantics(K2PatchData &data) {
    data.programs.clear();
    data.groups.clear();
    data.zones.clear();
    data.voice_limits.clear();
    data.start_criteria.clear();
    data.source_modes.clear();
    data.slices.clear();
    data.zles.clear();
    data.internal_modulators.clear();
    data.external_modulators.clear();
    data.scripts.clear();
    data.morph_groups.clear();
    data.morph_maps.clear();
    data.automation.clear();
    data.effective_automation.clear();
    data.purged_automation.clear();
    data.effects.clear();
    data.banks.clear();
    data.containers.clear();
    data.output_configurations.clear();
    data.output_partitions.clear();
    for (const auto &element : data.elements)
        collect_k2_semantics(element, data);
    detail::apply_k2_close_semantics(data);
}

#include "tables/k1_grammar.inc"

std::uint16_t k1_fixed_token(std::string_view spelling) {
    static constexpr auto tokens = std::to_array<
            std::pair<std::string_view, std::uint16_t>>({ { "xml", 10 },
            { "NiSS_Bank", 11 }, { "NiSS_Program", 12 }, { "NiSS_Group", 13 },
            { "NiSS_Zone", 14 }, { "NiSS_IntMod", 15 }, { "NiSS_ExtMod", 16 },
            { "NiSS_StatMod", 17 }, { "NiSS_Preset", 18 }, { "Loop", 19 },
            { "V", 25 }, { "Parameters", 60 }, { "Sample", 62 },
            { "SendLevels", 61 }, { "Groups", 54 }, { "Zones", 55 },
            { "Loops", 56 }, { "Polyphony", 44 }, { "GroupStart", 46 },
            { "IntModulators", 57 }, { "ExtModulators", 58 },
            { "StatModulators", 59 }, { "PlayPosOffset", 27 },
            { "LoopOffset", 28 }, { "Filter", 29 }, { "Grain", 30 },
            { "StartCriteria", 31 }, { "VoiceGroup", 45 },
            { "FXCompressor", 32 }, { "FXInverter", 33 }, { "FXLoFi", 34 },
            { "FXShaper", 35 }, { "FXStereo", 36 }, { "FXFilter", 37 },
            { "FXDistortion", 38 }, { "FXDelay", 39 }, { "FXChorus", 40 },
            { "FXFlanger", 41 }, { "FXPhaser", 42 }, { "FXReverb", 43 },
            { "LFO", 47 }, { "Envelope", 48 }, { "Arpegg", 49 },
            { "EnvFollow", 50 }, { "Glide", 51 }, { "XSync", 52 },
            { "ModTable", 53 }, { "Automation", 63 }, { "AutObj", 64 },
            { "BatteryPatch", 65 }, { "SampleSlot", 67 }, { "name", 20 },
            { "index", 21 }, { "type", 22 }, { "groupIdx", 23 },
            { "version", 24 }, { "value", 26 }, { "volume", 66 },
            { "label", 68 }, { "pan", 69 }, { "output", 70 },
            { "muteGroup", 71 }, { "midiChannel", 72 }, { "rootKey", 73 },
            { "status", 74 }, { "lowKey", 75 }, { "highKey", 76 },
            { "vattack", 77 }, { "vhold", 78 }, { "vdecay", 79 },
            { "vsustain", 80 }, { "vrelease", 81 }, { "pdecay1", 82 },
            { "pdecay2", 83 }, { "pbreak", 84 }, { "pamount", 85 },
            { "pitch", 86 }, { "fxstart", 87 }, { "fxlength", 88 },
            { "fxcount", 89 }, { "sstart", 90 }, { "fxstartUnit", 91 },
            { "fxlengthUnit", 92 }, { "sstartUnit", 93 }, { "tuningUnit", 94 },
            { "masterAmount", 95 }, { "modPresetName", 96 }, { "modSrc0", 97 },
            { "modDest0", 98 }, { "modAmt0", 99 }, { "modSrc1", 100 },
            { "modDest1", 101 }, { "modAmt1", 102 }, { "modSrc2", 103 },
            { "modDest2", 104 }, { "modAmt2", 105 }, { "modSrc3", 106 },
            { "modDest3", 107 }, { "modAmt3", 108 }, { "modSrc4", 109 },
            { "modDest4", 110 }, { "modAmt4", 111 }, { "modSrc5", 112 },
            { "modDest5", 113 }, { "modAmt5", 114 }, { "modSrc6", 115 },
            { "modDest6", 116 }, { "modAmt6", 117 }, { "modSrc7", 118 },
            { "modDest7", 119 }, { "modAmt7", 120 }, { "waveshaper", 121 },
            { "bitreduction", 122 }, { "file", 123 }, { "lowVelo", 124 },
            { "highVelo", 125 }, { "layerVolume", 126 } });
    const auto found = std::find_if(tokens.begin(), tokens.end(),
            [spelling](const auto &entry) { return entry.first == spelling; });
    if (found == tokens.end())
        throw std::runtime_error("K1 grammar token is unmapped");
    return found->second;
}

void append_k1_attribute_tokens(
        const K1TagAttribute &attribute, std::vector<std::uint16_t> &tokens) {
    tokens.push_back(k1_fixed_token(attribute.name));
    tokens.push_back(127); // '=' token
    tokens.push_back(3);   // quoted-string token
}

void append_k1_element_tokens(
        const K1TagElement &element, std::vector<std::uint16_t> &tokens) {
    const auto tag = k1_fixed_token(element.name);
    tokens.push_back(6);
    tokens.push_back(tag);
    for (const auto &attribute : element.attributes) {
        append_k1_attribute_tokens(attribute, tokens);
    }
    if (element.self_closing) {
        tokens.push_back(9);
        return;
    }
    tokens.push_back(7);
    for (const auto &child : element.children)
        append_k1_element_tokens(child, tokens);
    tokens.push_back(8);
    tokens.push_back(tag);
    tokens.push_back(7);
}

void validate_k1_binary_grammar_surface(const K1PatchData &data) {
    std::vector<std::uint16_t> tokens{ 4, 10 };
    for (const auto &attribute : data.xml_declaration) {
        append_k1_attribute_tokens(attribute, tokens);
    }
    tokens.push_back(5);
    for (const auto &element : data.elements)
        append_k1_element_tokens(element, tokens);
    tokens.push_back(0);

    struct Item {
        std::uint16_t rule;
        std::uint16_t dot;
        std::uint32_t origin;
        bool operator==(const Item &) const = default;
    };
    std::vector<std::vector<Item>> chart(tokens.size() + 1);
    const auto append_unique = [](std::vector<Item> &destination, Item item) {
        if (std::find(destination.begin(), destination.end(), item) ==
                destination.end()) {
            destination.push_back(item);
        }
    };
    append_unique(chart[0], { 1, 0, 0 });
    for (std::size_t position = 0; position <= tokens.size(); ++position) {
        for (std::size_t cursor = 0; cursor < chart[position].size();
                ++cursor) {
            const auto item = chart[position][cursor];
            const auto &rule = kK1GrammarRules[item.rule];
            if (rule.begin + item.dot < rule.end) {
                const auto symbol = kK1GrammarRhs[rule.begin + item.dot];
                if (symbol >= 128) {
                    for (std::uint16_t candidate = 1;
                            candidate < kK1GrammarRules.size(); ++candidate) {
                        if (kK1GrammarRules[candidate].lhs == symbol) {
                            append_unique(chart[position],
                                    { candidate, 0,
                                            static_cast<std::uint32_t>(
                                                    position) });
                        }
                    }
                } else if (position < tokens.size() &&
                           tokens[position] == symbol) {
                    append_unique(chart[position + 1],
                            { item.rule,
                                    static_cast<std::uint16_t>(item.dot + 1),
                                    item.origin });
                }
                continue;
            }
            const auto completed_symbol = rule.lhs;
            for (std::size_t parent_index = 0;
                    parent_index < chart[item.origin].size(); ++parent_index) {
                const auto parent = chart[item.origin][parent_index];
                const auto &parent_rule = kK1GrammarRules[parent.rule];
                if (parent_rule.begin + parent.dot < parent_rule.end &&
                        kK1GrammarRhs[parent_rule.begin + parent.dot] ==
                                completed_symbol) {
                    append_unique(chart[position],
                            { parent.rule,
                                    static_cast<std::uint16_t>(parent.dot + 1),
                                    parent.origin });
                }
            }
        }
    }
    const auto &start = kK1GrammarRules[1];
    const Item accepted{ 1, static_cast<std::uint16_t>(start.end - start.begin),
        0 };
    if (std::find(chart[tokens.size()].begin(), chart[tokens.size()].end(),
                accepted) == chart[tokens.size()].end()) {
        std::size_t furthest = 0;
        for (std::size_t i = 0; i < chart.size(); ++i) {
            if (!chart[i].empty())
                furthest = i;
        }
        const auto next = furthest < tokens.size() ? tokens[furthest] : 0xffffU;
        throw std::runtime_error("K1 tag stream is rejected by Kontakt's "
                                 "generated grammar at token " +
                                 std::to_string(furthest) + " (symbol " +
                                 std::to_string(next) + ")");
    }
}

} // namespace detail::patch

void parse_k2_tag_stream(K2PatchData &data) {
    static constexpr auto element_names = std::to_array<std::string_view>(
            { "K2_Bank", "K2_Container", "K2_Program", "K2_Group", "K2_Zone",
                    "K2_IntMod", "K2_ExtMod", "K2_Effect", "K2_Preset", "Slots",
                    "Programs", "Loop", "V", "Parameters", "Sample", "Groups",
                    "Zones", "Loops", "Polyphony", "GroupStart",
                    "IntModulators", "ExtModulators", "StatModulators",
                    "GroupInsertFX", "ProgramInsertFX", "ProgramSendFX",
                    "FXChain", "PlayPosOffset", "LoopOffset", "PlaybackMode",
                    "StartCriteria", "VoiceGroup", "Targets", "Target",
                    "Slices", "Slice", "ZLEs", "ZLE", "Segment", "Outputs",
                    "OutputsNextPlugin", "Output", "Scripts", "Script",
                    "Compressor", "Inverter", "Dyx", "Limiter", "Gainer",
                    "SurroundPanner", "LoFi", "Shaper", "Stereo", "Filter",
                    "Distortion", "Skreamer", "Rotator", "Twang", "Cabinet",
                    "Delay", "Chorus", "Flanger", "Phaser", "Reverb",
                    "SendLevels", "IRC", "LFO", "Envelope", "Arpegg",
                    "EnvFollow", "Glide", "ModTable", "ModCurve", "Automation",
                    "AutObj", "MorphGroups", "MorphGroup", "MorphMaps",
                    "MorphMap" });
    static constexpr std::array<std::string_view, 6> attribute_names{ { "name",
            "index", "type", "groupIdx", "version", "value" } };
    parse_k1_tag_stream(data.decompressed, element_names, attribute_names,
            data.xml_declaration, data.elements, "K2");
    materialize_k2_semantics(data);
}

K1PatchData parse_k1_patch_data(std::span<const std::byte> bytes) {
    static constexpr auto element_names =
            std::to_array<std::string_view>({ "NiSS_Bank", "NiSS_Program",
                    "NiSS_Group", "NiSS_Zone", "NiSS_IntMod", "NiSS_ExtMod",
                    "NiSS_StatMod", "NiSS_Preset", "Loop", "V", "Parameters",
                    "Sample", "SendLevels", "Groups", "Zones", "Loops",
                    "Polyphony", "GroupStart", "IntModulators", "ExtModulators",
                    "StatModulators", "PlayPosOffset", "LoopOffset", "Filter",
                    "Grain", "StartCriteria", "VoiceGroup", "FXCompressor",
                    "FXInverter", "FXLoFi", "FXShaper", "FXStereo", "FXFilter",
                    "FXDistortion", "FXDelay", "FXChorus", "FXFlanger",
                    "FXPhaser", "FXReverb", "LFO", "Envelope", "Arpegg",
                    "EnvFollow", "Glide", "XSync", "ModTable", "Automation",
                    "AutObj", "BatteryPatch", "SampleSlot" });
    static constexpr auto attribute_names = std::to_array<std::string_view>(
            { "name", "index", "type", "groupIdx", "version", "value", "volume",
                    "label", "pan", "output", "muteGroup", "midiChannel",
                    "rootKey", "status", "lowKey", "highKey", "vattack",
                    "vhold", "vdecay", "vsustain", "vrelease", "pdecay1",
                    "pdecay2", "pbreak", "pamount", "pitch", "fxstart",
                    "fxlength", "fxcount", "sstart", "fxstartUnit",
                    "fxlengthUnit", "sstartUnit", "tuningUnit", "masterAmount",
                    "modPresetName", "modSrc0", "modSrc1", "modSrc2", "modSrc3",
                    "modSrc4", "modSrc5", "modSrc6", "modSrc7", "modDest0",
                    "modDest1", "modDest2", "modDest3", "modDest4", "modDest5",
                    "modDest6", "modDest7", "modAmt0", "modAmt1", "modAmt2",
                    "modAmt3", "modAmt4", "modAmt5", "modAmt6", "modAmt7",
                    "waveshaper", "bitreduction", "file", "lowVelo", "highVelo",
                    "layerVolume" });
    if (bytes.size() < K1PatchHeader::serialized_size) {
        throw std::runtime_error("truncated K1 patch header");
    }
    K1PatchData out;
    std::copy_n(bytes.begin(), K1PatchHeader::serialized_size,
            out.header.normalized_bytes.begin());
    auto header = std::span<std::byte>(out.header.normalized_bytes);
    const auto raw_magic = u32le(header, 0);
    if (!legacy_patch_magic(raw_magic) &&
            !legacy_patch_magic(byteswap32(raw_magic))) {
        throw std::runtime_error("unsupported K1 patch magic");
    }
    out.header.byte_swapped = !legacy_patch_magic(raw_magic);
    if (out.header.byte_swapped) {
        auto swap16_at = [&](std::size_t offset) {
            std::swap(header[offset], header[offset + 1]);
        };
        auto swap32_at = [&](std::size_t offset) {
            std::swap(header[offset], header[offset + 3]);
            std::swap(header[offset + 1], header[offset + 2]);
        };
        // only these fields swap; the four-byte tail stays in file byte order
        for (const auto offset : { 0U, 8U, 12U, 20U, 24U, 28U })
            swap32_at(offset);
        for (const auto offset : { 4U, 6U, 16U, 18U })
            swap16_at(offset);
    }
    out.header.magic = u32le(header, 0);
    out.header.field_04 = u16le(header, 4);
    out.header.field_06 = u16le(header, 6);
    out.header.format_version = u32le(header, 8);
    out.header.confirmed_u32_fields = { u32le(header, 12), u32le(header, 20),
        u32le(header, 24), u32le(header, 28) };
    std::copy_n(header.begin() + 32, 4, out.header.unswapped_tail.begin());

    // sample slots stop at 0x50, banks/programs at 0x80; only the low u16 is
    // checked
    const auto maximum_version =
            (out.header.magic == 0x10874353U || out.header.magic == 0x74b5a69bU)
                    ? 0x50U
                    : 0x80U;
    if (u16le(header, 8) > maximum_version) {
        throw std::runtime_error("unsupported K1 patch version");
    }
    const auto stored_payload = bytes.subspan(K1PatchHeader::serialized_size);
    if (stored_payload.size() >= 2 && u8(stored_payload, 0) == 0x78U) {
        // tags are zlib at +0x24 on disk, but you can also pass them already
        // inflated, so check the header first
        z_stream stream{};
        stream.next_in = reinterpret_cast<Bytef *>(
                const_cast<std::byte *>(stored_payload.data()));
        stream.avail_in = static_cast<uInt>(stored_payload.size());
        if (inflateInit(&stream) != Z_OK) {
            throw std::runtime_error("cannot initialize K1 zlib stream");
        }
        std::array<std::byte, 65536> block{};
        int status = Z_OK;
        while (status == Z_OK) {
            stream.next_out = reinterpret_cast<Bytef *>(block.data());
            stream.avail_out = static_cast<uInt>(block.size());
            status = inflate(&stream, Z_NO_FLUSH);
            const auto produced = block.size() - stream.avail_out;
            out.payload.insert(out.payload.end(), block.begin(),
                    block.begin() + static_cast<std::ptrdiff_t>(produced));
        }
        const auto trailing = stream.avail_in;
        inflateEnd(&stream);
        if (status != Z_STREAM_END || trailing != 0) {
            throw std::runtime_error("invalid or trailing K1 zlib payload");
        }
    } else {
        out.payload.assign(stored_payload.begin(), stored_payload.end());
    }
    parse_k1_tag_stream(out.payload, element_names, attribute_names,
            out.xml_declaration, out.elements, "K1");
    validate_k1_binary_grammar_surface(out);
    detail::k1::materialize(out);
    return out;
}

std::optional<std::pair<std::uint32_t, bool>> resolve_modulation_target_name(
        std::string_view name) {
    return resolve_k2_mod_target(name);
}

} // namespace libnki
