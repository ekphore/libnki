// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "libnki/nki.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace libnki {

struct Document;
struct NicntProductHints;
struct NicntContainer;
struct MonolithContainer;
struct NkcCache;
struct NcwInfo;

// same view for every version, the wire layouts are in nki.h
enum class SourceGeneration : std::uint8_t { unknown, k1, k2, k42, modern };

// 0 is linear, 1 the 9 tap windowed sinc and 2 the 25 tap one
enum class InterpolationQuality : std::uint8_t {
    normal = 0,
    high = 1,
    ultra = 2
};

struct KeyVelocityRange {
    std::optional<std::int16_t> low_key;
    std::optional<std::int16_t> high_key;
    std::optional<std::int16_t> low_velocity;
    std::optional<std::int16_t> high_velocity;
    std::optional<std::int16_t> root_key;
    std::optional<std::int16_t> fade_low_key;
    std::optional<std::int16_t> fade_high_key;
    std::optional<std::int16_t> fade_low_velocity;
    std::optional<std::int16_t> fade_high_velocity;
};

struct SampleLoop {
    std::optional<std::int32_t> start;
    std::optional<std::int32_t> length;
    std::optional<std::int32_t> count;
    std::optional<std::int32_t> crossfade_length;
    std::optional<float> tuning;
    std::optional<bool> alternating;
    std::optional<std::string> mode;
};

struct SampleSliceInfo {
    std::int32_t start{};
    std::int32_t end{};
    std::optional<std::uint32_t> flags;
    // output duration comes from this F32 difference, not the PCM positions.
    // missing in legacy files without markers
    std::optional<float> start_position_f32;
    std::optional<float> end_position_f32;
};

enum class SerializedPathPayloadKind : std::uint8_t {
    none,
    text,
    legacy_decimal_u16,
    signed_s16,
};

struct SerializedPathSegment {
    std::int8_t serialized_kind{};
    std::int16_t kind{};
    SerializedPathPayloadKind payload_kind{ SerializedPathPayloadKind::none };
    std::optional<std::string> text;
    std::optional<std::int16_t> value;
};

enum class PathResolutionBase : std::uint8_t {
    unknown,
    empty,
    read_context,
    content_directory,
    factory_directory,
    platform_volume,
    container_inner,
};

struct SerializedPathInfo {
    // kontakt throws these away, keep the text but don't treat it as a path
    std::optional<std::string> discarded_legacy_path;
    std::vector<SerializedPathSegment> segments;
    std::optional<std::int32_t> kontakt_path_type;
    PathResolutionBase resolution_base{ PathResolutionBase::unknown };
};

struct PathResolutionContext {
    std::optional<std::filesystem::path> read_context;
    std::optional<std::filesystem::path> content_directory;
    std::optional<std::filesystem::path> factory_directory;
};

enum class PathResolutionStatus : std::uint8_t {
    empty,
    resolved,
    missing_context_root,
    unavailable_special_root,
    container_or_device,
    platform_volume,
    unsupported_segment,
};

struct ContainerOrDevicePathInfo {
    std::int16_t marker_kind{}; // 8=container file, 9=device
    std::size_t marker_index{};
    // the delimiter becomes a kind-4 final-file segment in the enclosing path
    SerializedPathInfo enclosing_path;
    // segments after the delimiter belong to the inner path
    SerializedPathInfo inner_path;
    PathResolutionStatus enclosing_status{ PathResolutionStatus::empty };
    std::optional<std::filesystem::path> resolved_enclosing_path;
};

struct PlatformVolumePathInfo {
    std::string volume_name;
    SerializedPathInfo path_within_volume;
};

struct ResolvedPathInfo {
    PathResolutionStatus status{ PathResolutionStatus::empty };
    std::optional<std::filesystem::path> path;
    std::optional<ContainerOrDevicePathInfo> container_or_device;
    std::optional<PlatformVolumePathInfo> platform_volume;
};

// content/factory roots have to exist before we substitute them,
// container/device paths keep their markers so you can resolve both halves
ResolvedPathInfo resolve_path(const SerializedPathInfo &serialized,
        const PathResolutionContext &context);

struct SampleInfo {
    std::optional<std::string> path;
    std::optional<SerializedPathInfo> serialized_path;
    std::optional<SerializedPathInfo> secondary_serialized_path;
    std::optional<std::string> preferred_name;
    std::optional<std::int32_t> sample_rate;
    std::optional<std::int32_t> channel_count;
    std::optional<std::int32_t> frame_count;
    std::optional<std::int32_t> root_note;
    // linear pitch ratio
    std::optional<float> tuning;
    std::optional<std::int32_t> file_table_index;
    std::optional<std::uint64_t> timestamp;
    std::vector<SampleLoop> loops;
    // v3 path roots: 1 selects the registered library, 2 shared application
    // data
    std::optional<std::int32_t> content_file_path_mode;
    std::optional<std::uint32_t> content_file_library_id;
};

enum class SampleReferenceStatus : std::uint8_t {
    absent,
    empty,
    resolved,
    out_of_range,
};

struct ZoneEnvelopePoint {
    std::int32_t position{};
    float level{};
    float curve{};
};

struct ZoneEnvelopeInfo {
    std::uint8_t index{};
    // index into the external parameter array, add 16 for the global slot
    std::optional<std::int16_t> external_modulator_index;
    std::optional<std::int32_t> loop_start;
    std::optional<std::int32_t> loop_length;
    std::optional<bool> loop_active;
    std::optional<bool> speed_lock;
    std::optional<std::string> target_xml_name;
    std::optional<std::int8_t> target_index;
    std::vector<ZoneEnvelopePoint> points;
};

struct ZoneInfo {
    // opaque zone handle for KSP get_zone_id, attach_zone and find_zone
    std::optional<std::int32_t> ksp_id;
    std::optional<std::string> name;
    KeyVelocityRange range;
    // index into InstrumentInfo::groups, empty if there's no valid group
    std::optional<std::size_t> group_index;
    std::optional<std::size_t> sample_index;
    // program-level AET/DYX morph group, not the sampler group
    std::optional<std::int32_t> dyx_morph_group_id;
    std::optional<std::int32_t> sample_file_table_index;
    SampleReferenceStatus sample_reference_status{
        SampleReferenceStatus::absent
    };
    std::optional<std::int32_t> sample_start;
    std::optional<std::int32_t> sample_end;
    std::optional<std::int32_t> sample_start_modulation_range;
    // whether negative playPos ranges start enabled, unrelated to group purge
    // or residency. empty if the load didn't set live state
    std::optional<bool> sample_start_modulation_purged;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    // not a BPM, the reference tempo comes from these and the sample length
    std::optional<std::uint8_t> grid_unit_numerator;
    std::optional<std::uint8_t> grid_unit_denominator;
    std::optional<float> grid_tempo_scaling;
    // exposed read-only to KSP as $ZONE_PAR_SELECTED
    std::optional<bool> selected;
    std::vector<SampleLoop> loops;
    // modern boundary arrays become adjacent [start,end) pairs, legacy pairs
    // stay as they are
    std::vector<SampleSliceInfo> slices;
    // kept even if the player doesn't support the destination
    std::vector<ZoneEnvelopeInfo> envelopes;
    // DFD preload uses the stored bit depth, not the decoder's
    std::optional<std::int32_t> sample_bit_depth;
    // source speed reference, nothing to do with UI selection
    std::optional<bool> reference_zone;
};

enum class StartMode : std::uint8_t {
    none = 0,
    on_key = 1,
    on_controller = 2,
    cycle_round_robin = 3,
    cycle_random = 4,
    slice_trigger = 5,
};

enum class NextStartCriterion : std::uint8_t {
    and_also = 0,
    and_not = 1,
    or_else = 2,
};

struct StartCriterion {
    StartMode mode{ StartMode::none };
    NextStartCriterion next{ NextStartCriterion::and_also };
    std::optional<std::int16_t> minimum_key;
    std::optional<std::int16_t> maximum_key;
    std::optional<std::int16_t> controller;
    std::optional<std::int16_t> minimum_controller_value;
    std::optional<std::int16_t> maximum_controller_value;
    std::optional<std::int32_t> slice_zone_index;
    std::optional<std::int32_t> slice_index;
    std::optional<std::int32_t> cycle_class;
    bool sequencer_only{};
};

struct ModulationTargetInfo {
    std::optional<std::string> name;
    std::optional<std::uint32_t> id;
    std::optional<float> amount;
    std::optional<bool> inverted;
    std::optional<std::int32_t> modulator_index;
    std::optional<std::int16_t> slot_index;
    std::optional<std::string> assignment;
    std::optional<std::int16_t> smoothing_coefficient;
    std::optional<std::uint8_t> transformation_kind;
    std::optional<bool> transformation_enabled;
    std::vector<float> transformation_values;
    // name for lookup, the resolved expression is in assignment
    std::optional<std::string> assignment_name;
    // these flags can select an alternate target25 intensity law
    std::optional<std::uint8_t> native_flags;
};

struct AhdsrEnvelopeInfo {
    std::optional<float> attack_curving;
    std::optional<float> attack;
    std::optional<float> hold;
    std::optional<float> decay;
    std::optional<float> sustain;
    std::optional<float> release;
    std::optional<bool> note_off_less_mode;
    std::optional<float> note_value_attack;
    std::optional<float> note_value_hold;
    std::optional<float> note_value_decay;
    std::optional<float> note_value_release;
};

// raw FM7 points, no units or defaults applied
struct Fm7EnvelopeInfo {
    std::optional<std::int32_t> release_end;
    std::optional<std::int32_t> loop_start;
    std::optional<std::int32_t> loop_end;
    std::optional<bool> loop_enabled;
    std::optional<bool> one_shot_mode;
    std::array<std::optional<float>, 32> times{};
    std::array<std::optional<float>, 32> levels{};
    std::array<std::optional<float>, 32> slopes{};
    std::optional<float> note_value_grid;
    std::optional<float> note_value_min_ms, note_value_max_ms;
    std::optional<bool> note_value_clamp_below_one;
};

// keep the stored DBD parameters without converting their units
struct DbdEnvelopeInfo {
    std::optional<float> decay_1;
    std::optional<float> break_level;
    std::optional<float> decay_2;
    std::optional<float> note_value_decay_1;
    std::optional<float> note_value_decay_2;
    std::optional<bool> zero_break_and_decay_2;
};

// kept even if the player doesn't support them, missing legacy fields stay
// empty instead of guessing
struct LfoInfo {
    std::optional<std::int32_t> waveform;
    std::optional<float> delay;
    std::optional<float> frequency;
    std::optional<float> pulse_width;
    std::optional<float> start_phase;
    std::optional<bool> normalize_multi_lfo;
    std::optional<float> note_value_frequency;
    std::optional<bool> note_value_frequency_enabled;
    std::optional<float> note_value_delay;
    std::optional<bool> note_value_delay_enabled;
    // note duration tails, we don't know their units
    std::array<std::optional<float>, 2> note_frequency_metadata{};
    std::array<std::optional<float>, 2> note_delay_metadata{};
    std::optional<bool> note_frequency_mode;
    std::optional<bool> note_delay_mode;
    std::array<std::optional<float>, 5>
            levels{}; // sine, rect, tri, saw, random
    std::optional<std::uint16_t> serialized_version;
    std::optional<bool> serialized_flag_1d;
};

struct InternalModulatorInfo {
    std::optional<std::string> name;
    std::optional<bool> bypass;
    std::vector<ModulationTargetInfo> targets;
    std::optional<AhdsrEnvelopeInfo> ahdsr;
    std::optional<Fm7EnvelopeInfo> fm7;
    std::optional<LfoInfo> lfo;
    std::optional<bool> retrigger;
    // slot in the file, NOT the position in our compacted vector, modulator
    // targets like target25 intensity need it
    std::optional<std::int32_t> source_slot;
    std::optional<DbdEnvelopeInfo> dbd;
    // flags[3] picks the direct volume law for type2/subtype<2 target2, empty
    // if the legacy layout doesn't have it
    std::optional<bool> source_fourth_flag;
};

enum class ExternalModulatorType : std::uint8_t {
    external = 1,
    zone_envelope = 2,
};

enum class ExternalModulatorSource : std::uint8_t {
    pitch_bend = 1,
    poly_aftertouch = 2,
    mono_aftertouch = 3,
    midi_cc = 4,
    key_position = 7,
    velocity = 8,
    release_velocity = 9,
    release_trigger_counter = 10,
    constant = 11,
    random_unipolar = 12,
    random_bipolar = 13,
};

struct ExternalModulatorInfo {
    std::optional<std::string> name;
    std::optional<bool> bypass;
    std::optional<ExternalModulatorType> type;
    std::optional<ExternalModulatorSource> source;
    std::optional<std::uint8_t> controller;
    std::optional<float> delay;
    std::optional<std::int16_t> initial_value;
    std::vector<ModulationTargetInfo> targets;
    // second private bool, legacy cubic envelope composition including FM7
    // levels. empty means we don't know
    std::optional<bool> simulate_k2_env_time_modulation;
    // 16 + the modern external array index, whatever compaction does. legacy
    // slots are unknown for now
    std::optional<std::int32_t> source_slot;
};

enum class FilterType : std::uint32_t {
    low_pass_1_pole = 2,
    high_pass_1_pole = 3,
    band_pass_2_pole = 4,
    low_pass_2_pole = 6,
    high_pass_2_pole = 7,
    low_pass_4_pole = 8,
    high_pass_4_pole = 9,
    band_pass_4_pole = 10,
    band_reject_4_pole = 11,
    low_pass_6_pole = 12,
    phaser = 13,
    vowel_a = 14,
    vowel_b = 15,
    pro_52 = 16,
    ladder = 17,
    versatile = 19,
    // same nonlinear SVF kernel, these pick the LP/BP/HP output tap
    state_variable_2_low_pass = 46,
    state_variable_2_band_pass = 47,
    state_variable_2_high_pass = 48,
    // ladder LP then DJ HP, both extended range, each with its own cutoff
    simple_lp_hp = 0x58,
    // subtypes 0x16..0x21, not the legacy `ladder`
    ladder_current = 0x100,
    blue_monark_low_pass_1 = 36,
    blue_monark_low_pass_2 = 37,
    blue_monark_low_pass_4 = 38,
    blue_monark_band_pass_2_4 = 39,
    state_variable_1_low_pass = 42,
    state_variable_1_high_pass = 43,
    state_variable_4_low_pass = 51,
    state_variable_4_band_pass = 52,
    state_variable_4_high_pass = 53,
    state_variable_4_notch = 54,
    state_variable_6_low_pass = 57,
    state_variable_6_band_pass = 58,
    state_variable_6_high_pass = 59,
    state_variable_6_notch = 60,
    multi_state_variable_low_pass = 63,
    multi_state_variable_band_pass = 64,
    multi_state_variable_high_pass = 65,
    daft_low_pass = 68,
    daft_high_pass = 69,
    formant_a = 72,
    formant_b = 73,
    dj_a_low_pass = 76,
    dj_a_band_pass = 77,
    dj_a_high_pass = 78,
    dj_b_low_pass = 79,
    dj_b_band_pass = 80,
    dj_b_high_pass = 81,
    dj_c_low_pass = 82,
    dj_c_band_pass = 83,
    dj_c_high_pass = 84,
    eq_1_band = 0x5f,
    eq_2_band = 0x60,
    eq_3_band = 0x61,
};

struct FilterInfo {
    std::optional<FilterType> type;
    // filter enum before the versioned conversion, kept apart from
    // serialized_type so unknown aliases don't all turn into zero
    std::optional<std::uint32_t> serialized_fix_type;
    // raw subtype, several of these share one DSP family so don't collapse
    // them
    std::optional<std::uint32_t> serialized_type;
    std::optional<float> cutoff;
    std::optional<float> resonance;
    std::optional<float> low_pass_cutoff;
    std::optional<float> high_pass_cutoff;
    // formant filter, subtype 72/73 picks table A/B
    std::optional<float> formant_position;
    std::optional<float> formant_shift;
    std::optional<float> formant_sharpness;
    // multi-mode SVF width, 1..64 notes
    std::optional<float> multi_bandwidth;
    // ladder drive, NOT the output gain
    std::optional<float> input_gain;
    std::optional<bool> high_quality;
    std::optional<bool> legacy_smoothing;
    std::optional<float> gain;
    std::array<std::optional<float>, 3> frequency{};
    std::array<std::optional<float>, 3> bandwidth{};
    std::array<std::optional<float>, 3> band_gain{};
    std::array<std::optional<float>, 3> shift{};
    std::array<std::optional<float>, 3> band_resonance{};
    std::array<std::optional<float>, 3> band_type{};
    std::array<std::optional<float>, 3> band_bypass{};
};

enum class GroupEffectType : std::uint8_t {
    filter,
    gainer,
    inverter,
    stereo_spread,
    shaper,
    lo_fi,
    distortion,
    compressor,
    limiter,
    transparent_limiter,
    dyx,
    irc,
    send_levels,
    tape,
    transient_master,
    delay,
    chorus,
    flanger,
    legacy_phaser,
    phasis,
    flair,
    supercharger,
    bass_invader,
    reverb,
    galois_reverb,
    plate_reverb,
    surround_panner,
    skreamer,
    rotator,
    ring_modulator,
    twang,
    jump,
    van51,
    ac_box,
    hot_solo,
    bass_pro,
    cat,
    d_stortion,
    cry_wah,
    cabinet,
    feedback_compressor,
    solid_g_eq,
    solid_bus_compressor,
    choral,
    replika_delay,
    psyche_delay,
    twin_delay,
    raum,
    bite,
    dirt,
    freak,
    vibrato_chorus,
    wow_flutter,
    ep_preamps,
    fuzz,
    big_fuzz,
    stereo_tune,
    beat_masher,
    beat_slicer,
    gater,
    reverse_grain,
    transpose_stretch,
    super_fast_100,
    chainsaw,
    skreamer_deluxe,
    kolor,
    reverb_delight,
};

enum class ShaperModel : std::uint8_t {
    classic,
    drums,
    enhanced,
};

enum class DistortionModel : std::uint8_t {
    tube,
    transistor,
};

enum class CompressorModel : std::uint8_t {
    classic,
    enhanced,
    pro,
};

struct SurroundPannerPoint {
    float x{};
    float y{};
    std::uint8_t role{};
};

struct GroupEffectInfo {
    std::optional<GroupEffectType> type;
    std::optional<std::size_t> slot_index;
    std::optional<std::uint32_t> internal_type;
    std::optional<bool> bypass;
    std::optional<float> output_level;
    std::optional<float> dry_output_level;
    // wire order, so a new effect doesn't need a parser change
    std::vector<float> raw_parameters;
    std::vector<std::int32_t> raw_integer_parameters;
    std::vector<std::uint32_t> raw_unsigned_parameters;
    std::vector<std::uint8_t> raw_byte_parameters;
    std::vector<bool> raw_boolean_parameters;
    // surround panner v0x70, first points are the speaker layout, then the
    // source layout
    std::vector<SurroundPannerPoint> surround_output_points;
    std::vector<SurroundPannerPoint> surround_input_points;
    std::optional<float> surround_lfe_crossover_frequency;
    std::optional<float> surround_lfe_volume;
    std::optional<float> surround_size;
    std::optional<float> surround_divergence;
    std::optional<float> surround_air_amount;
    std::optional<float> surround_delay_amount;
    std::optional<std::int32_t> surround_volume_algorithm;
    std::optional<std::int32_t> surround_mouse_mode;
    std::optional<bool> surround_use_speaker_delays;
    std::optional<bool> surround_use_air_absorption;
    std::optional<bool> surround_use_doppler_effect;
    std::optional<float> surround_offset_distance;
    std::optional<float> surround_offset_azimuth;
    std::optional<float> surround_offset_x;
    std::optional<float> surround_offset_y;
    std::optional<std::int32_t> surround_preset_speaker_setup;
    // solid G-EQ v0x10/v0x11, the cut filters are empty on v0x10
    std::optional<float> solid_g_eq_high_frequency;
    std::optional<float> solid_g_eq_high_gain;
    std::optional<bool> solid_g_eq_high_bell;
    std::optional<float> solid_g_eq_high_mid_frequency;
    std::optional<float> solid_g_eq_high_mid_gain;
    std::optional<float> solid_g_eq_high_mid_q;
    std::optional<float> solid_g_eq_low_mid_frequency;
    std::optional<float> solid_g_eq_low_mid_gain;
    std::optional<float> solid_g_eq_low_mid_q;
    std::optional<float> solid_g_eq_low_frequency;
    std::optional<float> solid_g_eq_low_gain;
    std::optional<bool> solid_g_eq_low_bell;
    std::optional<float> solid_g_eq_high_pass_frequency;
    std::optional<float> solid_g_eq_low_pass_frequency;
    std::optional<bool> solid_g_eq_high_pass_active;
    std::optional<bool> solid_g_eq_low_pass_active;
    // legacy delay v0x50/v0x51, the note value fields are still only in
    // raw_parameters/raw_boolean_parameters
    std::optional<float> delay_time;
    std::optional<float> delay_feedback;
    std::optional<float> delay_panning;
    std::optional<float> delay_damping;
    // legacy skreamer v0x50
    std::optional<float> skreamer_tone;
    std::optional<float> skreamer_drive;
    std::optional<float> skreamer_bass;
    std::optional<float> skreamer_bright;
    std::optional<float> skreamer_mix;
    // legacy cabinet v0x50
    std::optional<float> cabinet_size;
    std::optional<float> cabinet_air;
    std::optional<float> cabinet_treble;
    std::optional<float> cabinet_bass;
    std::optional<std::int32_t> cabinet_type;
    // legacy phaser v0x50/v0x51
    std::optional<float> phaser_depth;
    std::optional<float> phaser_feedback;
    std::optional<float> phaser_speed;
    std::optional<float> phaser_phase;
    std::optional<float> phaser_note_value_speed;
    std::optional<bool> phaser_note_value_enabled;
    // legacy reverb v0x50
    std::optional<float> reverb_pre_delay;
    std::optional<float> reverb_room_size;
    std::optional<float> reverb_stereo;
    std::optional<float> reverb_color;
    std::optional<float> reverb_filter;
    // solid bus compressor v0x10..v0x12
    std::optional<float> solid_bus_threshold;
    std::optional<float> solid_bus_makeup;
    std::optional<float> solid_bus_attack;
    std::optional<float> solid_bus_release;
    std::optional<float> solid_bus_ratio;
    std::optional<float> solid_bus_mix;
    std::optional<bool> solid_bus_stereo_link;
    std::optional<bool> solid_bus_sidechain;
    // legacy chorus v0x50/v0x51
    std::optional<float> chorus_depth;
    std::optional<float> chorus_speed;
    std::optional<float> chorus_phase;
    std::optional<float> chorus_note_value_speed;
    std::optional<bool> chorus_note_value_enabled;
    // legacy flanger v0x50/v0x51
    std::optional<float> flanger_depth;
    std::optional<float> flanger_feedback;
    std::optional<float> flanger_speed;
    std::optional<float> flanger_phase;
    std::optional<float> flanger_color;
    std::optional<float> flanger_note_value_speed;
    std::optional<float> flanger_note_modifier;
    std::optional<float> flanger_note_tempo;
    std::optional<bool> flanger_note_enabled;
    // legacy rotator v0x50
    std::optional<float> rotator_speed;
    std::optional<float> rotator_balance;
    std::optional<float> rotator_acceleration_high;
    std::optional<float> rotator_acceleration_low;
    std::optional<float> rotator_distance;
    std::optional<float> rotator_mix;
    // feedback compressor v0x10
    std::optional<float> feedback_compressor_input;
    std::optional<float> feedback_compressor_makeup;
    std::optional<float> feedback_compressor_attack;
    std::optional<float> feedback_compressor_release;
    std::optional<float> feedback_compressor_ratio;
    std::optional<float> feedback_compressor_mix;
    std::optional<float> feedback_compressor_amount;
    std::optional<bool> feedback_compressor_high_quality;
    std::optional<bool> feedback_compressor_stereo_link;
    std::optional<bool> feedback_compressor_sidechain;
    // psyche delay v0x10 doesn't label its three mode flags, so they're named
    // after what they do in the DSP
    std::optional<float> psyche_delay_time;
    std::optional<float> psyche_delay_feedback;
    std::optional<float> psyche_delay_detune;
    std::optional<float> psyche_delay_pitch;
    std::optional<float> psyche_delay_lr_offset;
    std::optional<float> psyche_delay_cross_feedback;
    std::optional<bool> psyche_delay_right_direction_toggle;
    std::optional<bool> psyche_delay_right_detune_bypass;
    std::optional<bool> psyche_delay_left_direction;
    std::optional<float> psyche_delay_note_value;
    std::optional<float> psyche_delay_note_modifier;
    std::optional<float> psyche_delay_note_tempo;
    std::optional<bool> psyche_delay_note_enabled;
    // Choral v0x51 stores feedback polarity (ID7) before voice routing (ID6);
    // the UI labels for those switches are still unknown
    std::optional<float> choral_amount;
    std::optional<float> choral_rate;
    std::optional<float> choral_delay;
    std::optional<float> choral_voices;
    std::optional<float> choral_width;
    std::optional<float> choral_feedback;
    std::optional<float> choral_mix;
    std::optional<bool> choral_routing_switch;
    std::optional<bool> choral_feedback_polarity;
    std::optional<std::int32_t> choral_mode;
    // replika delay v0x10..0x12
    std::optional<std::int32_t> replika_style;
    std::optional<float> replika_time;
    std::optional<float> replika_feedback;
    std::optional<float> replika_low_cut;
    std::optional<float> replika_high_cut;
    std::optional<float> replika_saturate;
    std::optional<float> replika_tape_age;
    std::optional<float> replika_flutter;
    std::optional<float> replika_quality;
    std::optional<float> replika_depth;
    std::optional<float> replika_rate;
    std::optional<bool> replika_style_modulation_enabled;
    std::optional<bool> replika_tape_noise_enabled;
    std::optional<bool> replika_routing_enabled;
    std::optional<float> replika_note_value;
    std::optional<float> replika_note_modifier;
    std::optional<float> replika_note_tempo;
    std::optional<bool> replika_note_enabled;
    std::optional<float> replika_bbd_type;
    std::optional<float> replika_diffusion_amount;
    std::optional<float> replika_diffusion_size;
    std::optional<float> replika_diffusion_mod;
    std::optional<bool> replika_diffusion_enabled;
    std::optional<float> replika_shuffle;
    std::optional<float> replika_feel;
    std::optional<float> replika_accent;
    std::optional<float> replika_pan;
    std::optional<float> replika_width;
    std::optional<float> replika_lr_offset;
    std::optional<float> replika_ducking_sensitivity;
    std::optional<float> replika_ducking_release;
    std::optional<float> replika_ducking_amount;
    std::optional<bool> replika_routing_variant;
    std::optional<float> gain;
    std::optional<bool> phase;
    std::optional<bool> panorama;
    std::optional<float> spread;
    std::optional<float> pan;
    std::optional<bool> pseudo;
    std::optional<float> shape;
    std::optional<ShaperModel> shaper_model;
    std::optional<float> lo_fi_bits;
    std::optional<float> lo_fi_down_sample;
    std::optional<bool> lo_fi_sample_hold_integer;
    std::optional<float> lo_fi_noise_level;
    std::optional<float> lo_fi_noise_color;
    bool lo_fi_down_sample_requires_engine_rate_conversion{};
    std::optional<DistortionModel> distortion_model;
    std::optional<float> distortion_drive;
    std::optional<float> distortion_damping;
    std::optional<CompressorModel> compressor_model;
    std::optional<float> compressor_threshold;
    std::optional<float> compressor_ratio;
    std::optional<float> compressor_attack;
    std::optional<float> compressor_release;
    std::optional<bool> compressor_stereo_link;
    std::optional<float> limiter_input_gain;
    std::optional<float> limiter_release_time;
    // transparent limiter, NOT the legacy `limiter`
    std::optional<float> transparent_limiter_input;
    std::optional<float> transparent_limiter_release;
    std::optional<float> transparent_limiter_ceiling;
    std::optional<bool> transparent_limiter_external_sidechain;
    std::optional<float> tape_gain;
    std::optional<float> tape_warmth;
    std::optional<float> tape_rolloff;
    std::optional<bool> tape_high_quality;
    std::optional<float> transient_attack;
    std::optional<float> transient_sustain;
    std::optional<float> transient_gain;
    std::optional<std::int32_t> transient_mode;
    std::optional<float> dyx_morph;
    std::optional<float> dyx_dry;
    std::optional<std::int32_t> dyx_morph_map_index;
    std::optional<bool> dyx_linear_phase;
    std::optional<float> irc_sample_rate_decimation_factor;
    std::optional<std::int32_t> irc_serialized_convolution_block_size;
    std::optional<std::int32_t> irc_effective_convolution_block_size;
    std::optional<float> irc_pre_delay;
    std::optional<float> irc_early_length_ratio;
    std::optional<float> irc_early_high_pass_frequency;
    std::optional<float> irc_early_low_pass_frequency;
    std::optional<float> irc_late_length_ratio;
    std::optional<float> irc_late_high_pass_frequency;
    std::optional<float> irc_late_low_pass_frequency;
    std::optional<float> irc_early_late_crosspoint;
    std::optional<bool> irc_reverse;
    std::optional<bool> irc_auto_gain;
    std::optional<bool> irc_preserve_ir_length;
    std::optional<bool> irc_bypass_latency_compensation;
    std::optional<bool> irc_envelope_active;
    std::array<std::optional<float>, 8> irc_envelope_times{};
    std::array<std::optional<float>, 8> irc_envelope_levels{};
    std::optional<std::int32_t> irc_filename_table_index;
    // already resolved into InstrumentInfo::samples, in the file it's relative
    // to special_filename_base on v2
    std::optional<std::size_t> irc_sample_index;
    // 8 sends, then 16 bus sidechains and the program sidechain
    std::array<std::optional<float>, 8> send_levels{};
    std::array<std::optional<float>, 17> sidechain_send_levels{};
    std::optional<FilterInfo> filter;
};

struct InsertBusInfo {
    std::optional<std::string> name;
    std::optional<float> level;
    std::optional<float> pan;
    std::optional<std::int32_t> destination;
    std::optional<bool> phase_invert;
    std::optional<bool> swap_stereo;
    std::vector<GroupEffectInfo> effects;
};

struct DyxMorphGroupInfo {
    std::optional<std::size_t> program_index;
    std::optional<std::int32_t> id;
    std::optional<std::string> name;
    std::optional<float> smoothing;
    std::optional<float> left;
    std::optional<float> right;
    std::optional<bool> tonal;
    std::optional<std::int16_t> root_key_shift;
};

enum class DyxMorphMapType : std::uint8_t {
    velocity = 1,
    articulation = 2,
};

struct DyxMorphMapInfo {
    std::optional<std::size_t> program_index;
    std::optional<DyxMorphMapType> type;
    std::optional<std::int32_t> id;
    std::optional<std::string> name;
    // missing K2 attributes and anything past the stored count stay empty
    std::array<std::optional<std::int32_t>, 64> morph_group_ids{};
};

enum class VoiceStealMode : std::uint8_t {
    any = 0,
    oldest = 1,
    newest = 2,
    highest = 3,
    lowest = 4,
};

struct VoiceLimitInfo {
    std::optional<std::size_t> program_index;
    // empty for the program limit, voice groups are 0..127
    std::optional<std::uint8_t> group_index;
    std::optional<std::string> name;
    std::optional<std::int32_t> maximum_voices;
    std::optional<VoiceStealMode> mode;
    std::optional<bool> prefer_released;
    std::optional<std::int32_t> fade_time_ms;
    std::optional<std::int32_t> exclusion_group;
};

// don't renumber, the engine and KSP slice queries check these values
enum class PlaybackMode : std::int32_t {
    sampler = 0,
    tone_machine = 1,
    wavetable = 2,
    time_machine = 3,
    streaming = 4,
    slice_machine = 5,
    time_machine_2 = 6,
    sp1200_machine = 7,
    mpc60_machine = 8,
    time_machine_pro = 9,
};

// empty means an older version didn't have it, which isn't the same as zero
struct WavetableSourceInfo {
    std::optional<float> position;
    std::optional<float> warp1;
    std::optional<float> phase_seed;
    std::optional<float> phase_randomization;
    // NOT a warp mode yet, convert it first
    std::optional<std::int32_t> serialized_warp1_mode;
    std::optional<std::uint32_t> warp1_mode;
    std::optional<std::uint32_t> quality;
    std::optional<bool> inharmonic_enabled;
    std::optional<float> inharmonic_amount;
    std::optional<float> warp2;
    std::optional<std::int32_t> serialized_warp2_mode;
    std::optional<std::uint32_t> warp2_mode;
    std::optional<std::uint32_t> modulation_selector;
    std::optional<std::uint32_t> fm_waveform;
    std::optional<float> modulation_amount;
    // normalized, not Hz, the custom unit decides the conversion
    std::optional<float> modulation_tune;
    std::optional<std::uint32_t> modulation_custom_unit;
    std::optional<float> modulation_unit_metadata1;
    std::optional<float> modulation_unit_metadata2;
    std::optional<bool> modulation_unit_metadata_flag;
    std::optional<bool> modulation_use_custom_unit;
};

// ms stay ms until init gives us the rate, pre-0x60 K1 values aren't ms at all
struct TimeMachineSourceInfo {
    std::optional<float> smooth;
    std::optional<float> grain_length_ms;
    std::optional<float> grain_length_file_value;
    bool grain_length_requires_sample_rate_conversion{};
    std::optional<bool> high_quality;
    // we don't know if the DSP uses these
    std::optional<bool> dc_filter;
    std::optional<bool> serialized_retrigger;
    std::optional<bool> legato;
    std::optional<std::int32_t> analysis_grain_size;
};

// mode-9 authored values; the DSP parameter update converts envelope order
struct TimeMachineProSourceInfo {
    std::optional<std::uint32_t> strategy; // bool stored as 0/1
    // multiplies the envelope factor by current pitch; absent in v0x100,
    // which stores a discarded S32 instead
    std::optional<bool> formant_follow_pitch;
    std::optional<float> envelope_amount; // before trunc(amount*504)+8
    std::optional<float> formant_amount;  // before factor conversion
};

struct SliceMachineSourceInfo {
    std::optional<float> attack_ms;
    std::optional<float> release_ms;
    std::optional<bool> auto_play;
    // separate from autoplay in modern layouts
    std::optional<bool> legacy_playback_mode;
};

struct SourceModeInfo {
    PlaybackMode mode{ PlaybackMode::sampler };
    // speed multiplier and its note-duration value
    std::optional<float> speed;
    std::optional<float> note_value_speed;
    bool note_value_speed_enabled{};
    std::optional<WavetableSourceInfo> wavetable;
    std::optional<TimeMachineSourceInfo> time_machine;
    std::optional<TimeMachineProSourceInfo> time_machine_pro;
    // note-duration mode flag, separate from the multiplier-floor flag
    bool note_value_speed_converter{ true };
    std::optional<SliceMachineSourceInfo> slice_machine;
    // overrides per-voice speed with master tempo / effective zone reference
    // tempo
    std::optional<bool> zone_locked_speed;
};

struct GroupInfo {
    std::optional<std::string> name;
    std::optional<std::size_t> program_index;
    // K2 batteryCellColor before KSP maps it to a keyboard color constant
    std::optional<std::int32_t> keyboard_color;
    // 0x400..0x40f are insert buses 0..15, -1 goes through the program
    std::optional<std::int32_t> output;
    std::optional<std::int16_t> midi_channel;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    std::optional<bool> key_tracking;
    std::optional<bool> reverse;
    // v0x92 private bool[0], flips at the voice amp, not the Inverter effect
    std::optional<bool> phase_invert;
    std::optional<InterpolationQuality> interpolation_quality;
    std::optional<bool> release_trigger;
    std::optional<bool> release_trigger_note_monophonic;
    std::optional<std::int32_t> release_trigger_counter;
    std::optional<bool> muted;
    std::optional<bool> solo;
    // initial purge state, actually purging is up to the engine
    std::optional<bool> purged;
    std::optional<std::int32_t> voice_group;
    // slots below this go before the voice amp, the rest after, 6 by default
    std::optional<std::int32_t> pre_amplifier_insert_count;
    std::optional<SourceModeInfo> source_mode;
    std::vector<StartCriterion> start_criteria;
    std::vector<InternalModulatorInfo> internal_modulators;
    std::vector<ExternalModulatorInfo> external_modulators;
    std::vector<GroupEffectInfo> effects;
};

using KspPersistentValue = std::variant<std::int64_t, double, std::string,
        std::vector<std::int64_t>, std::vector<double>,
        std::vector<std::string>>;

struct KspPersistentVariable {
    std::string serialized_value;
    std::optional<std::string> name;
    std::optional<std::string> value;
    std::optional<KspPersistentValue> parsed_value;
};

struct KspScriptInfo {
    bool multi_script{};
    std::optional<std::string> source_text;
    std::optional<std::string> description;
    std::optional<std::string> text_file_name;
    std::optional<bool> source_editor_open;
    std::optional<bool> touched_but_not_applied;
    std::optional<bool> bypass;
    std::optional<std::string> legacy_password;
    std::vector<std::byte> password_hash;
    std::vector<KspPersistentVariable> persistent_variables;
};

struct ProgramInfo {
    std::optional<std::string> name;
    std::optional<std::string> author;
    std::optional<std::string> credits;
    std::optional<std::string> website;
    std::optional<std::int16_t> midi_channel;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    // selected KSP performance view slot
    std::optional<std::int16_t> performance_view_script_index;
    // K2/K4 store the wallpaper here instead of setting it from KSP
    std::optional<std::string> wallpaper_path;
    // resource container path with its markers, not the NKI or the wallpaper
    std::optional<SerializedPathInfo> resource_container_path;
    std::vector<GroupEffectInfo> insert_effects;
    std::vector<GroupEffectInfo> send_effects;
    std::vector<GroupEffectInfo> main_effects;
    std::vector<InsertBusInfo> insert_buses;
    std::vector<std::size_t> script_indices;
    // before load overrides and DFD rounding, samples can end up with another
    // size
    std::optional<std::int32_t> dfd_channel_preload_size;
    // seeds system-script key-select ranges; negative selectors stay inactive
    std::optional<std::int16_t> initial_key_select_note;
    // root policy for the resource path
    std::optional<std::int32_t> resource_container_path_mode;
    std::optional<std::uint32_t> resource_container_library_id;
};

struct InstrumentInfo {
    SourceGeneration generation{ SourceGeneration::unknown };
    std::optional<std::string> name;
    std::optional<std::string> author;
    std::optional<std::string> version;
    std::vector<ProgramInfo> programs;
    std::vector<GroupInfo> groups;
    std::vector<ZoneInfo> zones;
    std::vector<SampleInfo> samples;
    std::vector<KspScriptInfo> scripts;
    std::vector<VoiceLimitInfo> voice_limits;
    std::vector<DyxMorphGroupInfo> dyx_morph_groups;
    std::vector<DyxMorphMapInfo> dyx_morph_maps;
};

struct ProductInfo {
    std::string name;
    std::string type;
    std::string snpid;
    std::string upid;
    std::string company;
    std::string vendor;
    std::string website;
    std::string engine;
    std::string engine_version;
};

struct ContentInfo {
    std::string name;
    std::uint32_t id{};
    std::uint32_t revision{};
    std::uint64_t offset{};
    std::uint64_t size{};
};

struct ResourceInfo {
    std::string name;
    std::uint16_t type{};
    std::uint64_t offset{};
    std::uint64_t size{};
};

struct AudioInfo {
    std::uint32_t sample_rate{};
    std::uint16_t channel_count{};
    std::uint16_t bits_per_sample{};
    std::uint32_t sample_count{};
};

struct EmbeddedAudioInfo {
    std::uint32_t sample_index{};
    std::uint32_t frame_count{};
    std::uint32_t channel_count{};
    std::vector<std::vector<float>> channels;
};

struct InternalResourceReferenceInfo {
    std::uint32_t resource_type{};
    std::uint32_t reference_id{};
};

struct ExternalFileReferenceInfo {
    std::uint32_t value_code{};
    std::string snpid;
    std::string string_0;
    std::string string_1;
};

struct PictureInfo {
    std::uint32_t picture_type{};
    std::string filename;
    std::vector<std::byte> data;
    std::vector<std::string> legacy_filename_components;
    std::string legacy_filename_uri;
};

struct BinaryResourceInfo {
    std::vector<std::byte> data;
    std::uint32_t context_id{};
};

struct ResourceCollectionInfo {
    std::uint32_t num_samples{};
    std::uint32_t num_pictures{};
    std::uint32_t num_generic_binaries{};
};

struct PerformanceViewMenuEntryInfo {
    std::string text;
    std::int64_t value{};
    bool show{ true };
};

struct PerformanceViewAxisAutomationInfo {
    std::optional<bool> on;
    std::optional<std::int32_t> id;
    std::optional<std::string> name;
};

struct PerformanceViewControlInfo {
    std::uint32_t type_index{};
    std::string id;
    std::int32_t x{};
    std::int32_t y{};
    std::int32_t width{};
    std::int32_t height{};
    std::int32_t z_layer{};
    bool show{ true };
    std::string image;
    std::optional<std::int32_t> image_frame;
    std::string text;
    std::int32_t text_alignment{};
    std::int32_t text_position_y{};
    std::int32_t font_type_off{};
    std::int32_t font_type_on{};
    std::string font_name_off;
    std::string font_name_on;
    std::uint32_t waveform_color{};
    std::uint32_t table_bar_color{};
    std::uint32_t table_zero_color{};
    std::int32_t table_steps{};
    std::int32_t table_visible_steps{};
    std::int32_t table_maximum{};
    bool table_bipolar{};
    std::optional<std::int64_t> minimum;
    std::optional<std::int64_t> maximum;
    std::optional<std::int64_t> default_value;
    // designer metadata, not the saved automation objects
    std::optional<bool> host_automation_on;
    std::optional<std::int32_t> host_automation_id;
    std::optional<std::string> automation_name;
    std::optional<bool> disable_user_automation_assignment;
    // designer XY cursors, x then y
    std::vector<double> xy_values;
    std::vector<PerformanceViewAxisAutomationInfo> xy_automation;
    std::vector<std::string> xy_cursor_images;
    std::vector<PerformanceViewMenuEntryInfo> menu_entries;
    std::vector<PerformanceViewControlInfo> children;
};

struct PerformanceViewInfo {
    std::uint32_t format_version{};
    std::int32_t width{ 633 };
    std::int32_t height{ 350 };
    std::uint32_t background_color{};
    std::string background_image;
    std::vector<PerformanceViewControlInfo> controls;
};

[[nodiscard]] PerformanceViewInfo parse_performance_view(
        std::span<const std::byte> bytes);

struct GenericItemInfo {
    std::string domain;
    std::uint32_t item_id{};
    std::uint32_t version{};
    std::vector<std::byte> derived_payload;
};

struct ModuleInfo {
    std::uint32_t authorization_level{};
    std::vector<std::string> product_bindings;
    std::string watermark;
    std::string authoring_application_version;
};

struct AuthorizationInfo {
    std::uint32_t level{};
    std::vector<std::string> product_bindings;
    std::string watermark;
};

struct RepositoryBaseItemInfo {
    std::uint32_t child_count{};
};

struct ModuleBankInfo {
    std::string name;
};

struct RepositoryBankInfo {
    std::string name;
};

struct RepositoryBankContainerInfo {
    std::uint32_t selected_bank_index{};
    std::uint32_t child_count{};
};

struct RepositoryPresetContainerInfo {
    std::uint32_t child_count{};
};

struct Model {
    std::vector<InstrumentInfo> instruments;
    std::vector<ProductInfo> products;
    std::vector<ContentInfo> contents;
    std::vector<ResourceInfo> resources;
    std::optional<AudioInfo> audio;
    std::vector<EmbeddedAudioInfo> embedded_audio_samples;
    std::vector<ExternalFileReferenceInfo> external_file_references;
    std::vector<InternalResourceReferenceInfo> internal_resource_references;
    std::vector<PictureInfo> pictures;
    std::vector<BinaryResourceInfo> binary_resources;
    std::vector<ResourceCollectionInfo> resource_collections;
    std::vector<GenericItemInfo> generic_items;
    std::vector<ModuleInfo> modules;
    std::vector<AuthorizationInfo> authorizations;
    std::vector<RepositoryBaseItemInfo> repository_base_items;
    std::vector<ModuleBankInfo> module_banks;
    std::vector<RepositoryBankInfo> repository_banks;
    std::vector<RepositoryBankContainerInfo> repository_bank_containers;
    std::vector<RepositoryPresetContainerInfo> repository_preset_containers;
    std::vector<std::string> diagnostics;
};

[[nodiscard]] Model normalize(const Document &document);
struct InstrumentSnapshotInfo {
    SampleInfo parent_instrument;
    SnapshotPayload state;
    std::vector<SampleInfo> files;
    std::optional<std::uint32_t> special_filename_base;
    std::optional<std::string> name;
};

[[nodiscard]] InstrumentSnapshotInfo parse_instrument_snapshot_file(
        const std::filesystem::path &path);
[[nodiscard]] InstrumentSnapshotInfo parse_instrument_snapshot_file(
        const std::filesystem::path &path,
        std::span<const std::byte> private_key);
// doesn't need a key
[[nodiscard]] bool requires_encryption_private_key(
        const std::filesystem::path &path);
// only overwrites the snapshot parameters, zones/mappings/scripts stay
void apply_instrument_snapshot(
        InstrumentInfo &instrument, const InstrumentSnapshotInfo &snapshot);
[[nodiscard]] Model normalize(const NicntProductHints &product_hints);
[[nodiscard]] Model normalize(const NicntContainer &container);
[[nodiscard]] Model normalize(const MonolithContainer &container);
[[nodiscard]] Model normalize(const NkcCache &cache);
[[nodiscard]] Model normalize(const NcwInfo &audio);
[[nodiscard]] Model parse_model(std::span<const std::byte> bytes,
        std::span<const std::byte> encryption_key = {});
[[nodiscard]] Model parse_model_file(const std::filesystem::path &path);
[[nodiscard]] Model parse_model_file_with_private_key(
        const std::filesystem::path &path,
        std::span<const std::byte> private_key);
[[nodiscard]] Model parse_model_file(const std::filesystem::path &path,
        std::span<const std::byte> encryption_key);
[[nodiscard]] Model parse_nicnt_model(std::span<const std::byte> bytes);
[[nodiscard]] Model parse_monolith_model(
        std::span<const std::byte> bytes, std::size_t root_offset = 0);
[[nodiscard]] Model parse_nkc_model(std::span<const std::byte> bytes);
[[nodiscard]] Model parse_ncw_model(
        std::span<const std::byte> bytes, std::size_t file_offset = 0);

} // namespace libnki
