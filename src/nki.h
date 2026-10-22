// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace libnki {

// pa shortname database, also works on one embedded in a NICNT. we never make
// up initials or truncate the name
[[nodiscard]] std::optional<std::string> product_short_name(
        std::span<const std::byte> database, std::string_view product,
        std::string_view resource = "VB_shortname");

enum class Format {
    unknown,
    nisound_hsin,
    legacy_ni_fc_mtd,
    monolith_hitemfolder,
};

enum class PatchGeneration : std::uint8_t {
    unknown = 0,
    k1 = 1,
    k2 = 2,
    k42 = 3,
    k43_nisound = 4,
};

struct Error {
    std::size_t offset{};
    std::string message;
};

struct Frame {
    std::size_t offset{};
    std::uint64_t size{};
    std::uint32_t header_version{};
    std::uint32_t schema_version{};
    std::uint32_t header_flags{};
    std::string uuid_hex;
    // first payload u64, only for the opaque frame probe
    std::optional<std::uint64_t> payload_prefix_size;
    std::optional<std::uint32_t> item_id;
    std::size_t depth{};
};

enum class Support {
    unsupported,
    supported,
};

enum class ProtectedItemKind : std::uint8_t {
    compressed_subtree = 115,
    encryption_item = 116,
    app_specific = 117,
};

struct ProtectedItem {
    std::size_t frame_index{};
    std::size_t offset{};
    std::uint64_t frame_size{};
    ProtectedItemKind kind{};
    std::uint32_t base_payload_version{};
    std::uint32_t subtree_payload_version{};
    bool uses_compression{};
    std::optional<std::size_t> nested_item_offset;
    std::optional<std::uint64_t> nested_item_size;
    std::optional<std::uint32_t> uncompressed_size;
    std::optional<std::uint32_t> compressed_size;
    std::optional<std::size_t> compressed_data_offset;
    std::optional<std::uint32_t> encryption_payload_version;
    std::optional<bool> xor_enabled;
    std::optional<std::uint32_t> app_payload_version;
    std::optional<std::uint32_t> app_field_98;
    std::optional<std::string> authoring_application_version;
    std::uint32_t child_container_version{};
    std::uint32_t child_count{};
};

[[nodiscard]] Support supports_zone_struct_version(
        std::uint16_t version) noexcept;
[[nodiscard]] Support supports_file_table_version(
        std::uint16_t version) noexcept;
[[nodiscard]] Support supports_parameter_array_version(
        std::uint16_t version) noexcept;
[[nodiscard]] Support supports_source_mode_version(
        std::uint16_t version) noexcept;
[[nodiscard]] Support supports_program_struct_version(
        std::uint16_t version) noexcept;
[[nodiscard]] Support supports_par_script_version(
        std::uint16_t version) noexcept;
[[nodiscard]] Support supports_group_struct_version(
        std::uint16_t version) noexcept;
struct Metadata {
    std::optional<std::string> product;
    std::optional<std::string> version;
    std::optional<std::string> name;
    std::optional<std::string> author;
    std::optional<std::string> vendor;
    std::optional<std::string> description;
};

struct FileReference {
    std::uint32_t version{};
    std::uint32_t kind{};
    std::string path;
    std::string secondary_path;
    std::string snpid;
};

struct LicenseInfoPayload {
    std::uint32_t version{};
    std::vector<std::string> product_bindings;
    // between the product bindings and the watermark, the license checksum
    // covers it
    std::uint32_t license_metadata_word{};
    std::string watermark;
    std::uint32_t checksum{};
    bool checksum_valid{};
};

struct AuthorizationItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t payload_version{};
    std::uint32_t level{};
    std::optional<LicenseInfoPayload> license_info;
    std::uint32_t child_container_version{};
    std::uint32_t child_count{};
};

struct BaseItem {
    std::size_t frame_index{};
    std::uint32_t payload_version{};
    std::uint32_t child_container_version{};
    std::uint32_t child_count{};
};

struct RepositoryRoot {
    std::size_t payload_offset{};
    std::size_t container_offset{};
    std::uint32_t authorization_mode{};
    std::string authorization_snpid;
    std::optional<LicenseInfoPayload> license_info;
    std::uint32_t version{};
    std::uint32_t creator_version_packed{};
    std::uint32_t repository_magic{};
    std::uint32_t repository_type{};
    FileReference file_reference;
    std::string repository_uuid_hex;
};

struct PresetInfo {
    std::size_t frame_index{};
    std::size_t payload_offset{};
    std::size_t container_offset{};
    std::uint32_t authorization_mode{};
    std::string authorization_snpid;
    std::optional<LicenseInfoPayload> license_info;
    std::uint32_t version{};
    bool factory_content{};
    std::uint32_t authoring_application_id{};
    std::uint32_t authoring_info_version{};
    std::string creator_version;
    std::uint16_t kontakt_extension_version{};
    std::uint32_t child_container_version{};
    std::uint32_t child_count{};
};

struct SoundInfoItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t payload_version{};
    std::array<std::uint32_t, 2> leading_u32{};
    std::array<std::string, 5> strings{};
    std::array<std::uint32_t, 6> trailing_u32{};
    std::int32_t trailing_s32{};
    std::vector<std::vector<std::string>> bank_chain_strings;
    std::vector<std::string> tags;
    std::vector<std::pair<std::string, std::string>> user_set_attributes;
    std::vector<std::pair<std::string, std::string>> final_string_map;
};

struct AudioSampleItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t sample_index{};
    std::uint32_t audio_block_version{};
    std::uint32_t frame_count{};
    std::uint32_t channel_count{};
    // one F32 vector per channel, same as on the wire
    std::vector<std::vector<float>> channels;
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct InternalResourceReferenceItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t resource_type{};
    std::uint32_t reference_id{};
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct ExternalFileReferenceItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t file_reference_version{};
    std::uint32_t value_code{};
    std::string string_0;
    std::string string_1;
    std::string snpid;
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct PictureItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t binary_chunk_item_version{};
    std::uint32_t binary_chunk_version{};
    std::size_t binary_data_offset{};
    std::uint64_t binary_data_size{};
    std::vector<std::byte> binary_data;
    std::uint32_t context_id{};
    std::uint32_t picture_payload_version{};
    std::uint32_t picture_type{};
    std::string filename;
    std::optional<std::uint32_t> legacy_filename_version;
    std::optional<std::uint8_t> legacy_filename_format;
    std::optional<std::uint8_t> legacy_filename_kind;
    std::vector<std::string> legacy_filename_components;
    std::string legacy_filename_uri;
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct BinaryChunkItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t binary_chunk_version{};
    std::size_t binary_data_offset{};
    std::uint64_t binary_data_size{};
    std::vector<std::byte> binary_data;
    std::uint32_t context_id{};
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct ResourcesItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t container_version{};
    std::uint32_t child_count{};
    std::vector<std::size_t> sample_frames;
    std::vector<std::size_t> picture_frames;
    std::vector<std::size_t> generic_binary_frames;
    std::uint32_t num_samples{};
    std::uint32_t num_pictures{};
    std::uint32_t num_generic_binaries{};
};

// raw records for items kontakt doesn't know either, we don't guess at them
struct GenericDerivedRecord {
    std::uint64_t declared_size{};
    std::string domain;
    std::uint32_t item_id{};
    std::uint32_t version{};
};

struct GenericItem {
    std::size_t frame_index{};
    std::vector<GenericDerivedRecord> derived_records;
    std::uint32_t base_payload_version{};
    std::vector<std::byte> derived_payload;
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct ModuleItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t authorization_payload_version{};
    std::uint32_t authorization_level{};
    std::optional<LicenseInfoPayload> license_info;
    std::uint32_t module_payload_version{};
    std::uint32_t authoring_application_id{};
    std::uint32_t authoring_info_version{};
    std::string authoring_application_version;
    // nothing reads this as far as we know
    std::uint32_t module_flags{};
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct ModuleBankItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::string name;
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct BankItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t bank_payload_version{};
    std::string name;
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct BankContainerItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t container_payload_version{};
    // UINT32_MAX by default, no property name for it
    std::uint32_t selected_bank_index{};
    std::uint32_t child_container_version{};
    std::uint32_t child_count{};
};

struct PresetContainerItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t container_payload_version{};
    std::uint32_t child_container_version{};
    std::uint32_t child_count{};
};

struct ParameterDescriptor {
    std::uint32_t version{};
    std::array<std::string, 2> strings{};
    std::array<float, 3> values{};
};

struct AutomationParameters {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t payload_version{};
    std::vector<ParameterDescriptor> descriptors;
};

struct ControllerAssignment {
    std::uint32_t version{};
    std::string name;
    std::array<float, 2> f32{};
    std::array<std::uint32_t, 2> u32{};
};

struct ControllerGroupAssignments {
    std::uint32_t version{};
    std::string name;
    std::vector<ControllerAssignment> assignments;
};

struct ControllerAssignments {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t payload_version{};
    std::uint32_t collection_version{};
    std::vector<ControllerGroupAssignments> groups;
};

struct BNISoundHeader {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::array<std::byte, 0xde> verified_bytes{};
    std::uint16_t artifact_kind{};
};

struct PresetChunkItem {
    std::size_t frame_index{};
    std::uint32_t base_payload_version{};
    std::uint32_t item_payload_version{};
    std::uint32_t preset_chunk_version{};
    std::uint32_t binary_chunk_version{};
    std::size_t binary_data_offset{};
    std::uint64_t binary_data_size{};
    // the first context ID is stored; the second is checked against the load
    // context
    std::uint32_t context_id{};
    std::uint32_t item_context_id{};
    std::uint32_t container_version{};
    std::uint32_t child_count{};
};

struct ChunkHeader {
    std::size_t offset{};
    std::uint16_t type{};
    std::uint32_t payload_size{};
    std::size_t payload_offset{};
};

enum class FileNameSegmentPayloadKind : std::uint8_t {
    none,
    text,
    legacy_decimal_u16,
    signed_s16,
};

struct FileNameSegment {
    std::int8_t serialized_kind{};
    std::int16_t kind{};
    FileNameSegmentPayloadKind payload_kind{ FileNameSegmentPayloadKind::none };
    std::optional<std::string> text;
    std::optional<std::int16_t> value;
};

struct SerializedFileName {
    // kontakt reads these but leaves the filename empty
    std::optional<std::string> discarded_legacy_path;
    std::vector<FileNameSegment> segments;
};

struct ContentFileInfo {
    std::int32_t field_00{};
    std::int32_t field_04{};
    SerializedFileName selected_path;
    SerializedFileName secondary_path;
    std::uint64_t timestamp{};
    std::int32_t field_250{};
    std::int32_t field_254{};
};

struct FileTable {
    std::uint16_t chunk_type{};
    std::uint16_t version{};
    // v2 sample/special indices start after the first/second filename runs;
    // v3 uses zero for both bases
    std::optional<std::uint32_t> sample_filename_base;
    std::optional<std::uint32_t> special_filename_base;
    std::vector<ContentFileInfo> files;
};

struct SerializableHeader {
    std::size_t offset{};
    bool structured{};
    std::uint16_t version{};
    std::size_t payload_offset{};
};

struct PresetImplPrefix {
    ChunkHeader chunk;
    SerializableHeader serializable;
    bool saved_group_iteration_flag{};
    std::uint8_t saved_preset_kind{};
    std::size_t implementation_payload_offset{};
};

struct GroupArrayHeader {
    ChunkHeader chunk;
    std::int32_t group_count{};
    std::size_t groups_offset{};
};

struct GroupSnapshotPrefix {
    SerializableHeader serializable;
    std::array<float, 3> leading_f32{};
    std::array<bool, 4> flags{};
    std::int32_t field_after_flags{};
    std::int32_t mode{};
    std::size_t child_serializables_offset{};
};

struct ParameterArrayPrefix {
    SerializableHeader serializable;
    std::int32_t entry_count{};
    bool version_0x11_context_ids{};
    std::size_t entries_offset{};
};

struct SourceModePrefix {
    SerializableHeader serializable;
    std::int32_t serialized_mode{};
    std::int32_t internal_mode{};
    float field_after_mode{};
    bool flag_after_field{};
    std::int32_t range_1_to_5{};
    bool second_flag{};
    std::array<float, 3> versioned_f32{};
    bool version_0x102_flag{};
    std::size_t variant_payload_offset{};
};

struct SourceModePayload {
    SourceModePrefix prefix;
    std::vector<float> variant_f32;
    std::vector<std::int32_t> variant_s32;
    std::vector<std::uint32_t> variant_u32;
    std::vector<bool> variant_bool;
    std::size_t end_offset{};
};

enum class ParFxChildKind {
    delay,
    chorus,
    flanger,
    phaser,
    phasis,
    flair,
    gainer,
    hilbert_limiter,
    supercharger,
    bass_invader,
    reverb,
    galois_reverb,
    plate_reverb,
    limiter,
    compressor,
    inverter,
    dyx,
    surround_panner,
    lo_fi,
    shaper,
    stereo_spread,
    distortion,
    filter,
    send_levels,
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
    tape,
    transient_master,
    feedback_compressor,
    solid_g_eq,
    solid_bus_compressor,
    choral,
    replika_delay,
    irc,
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
    skreamer_dlx,
    kolor,
    reverb_delight
};

struct ParFxChildPayload {
    ParFxChildKind kind{};
    SerializableHeader serializable;
    std::vector<float> f32;
    std::vector<std::int32_t> s32;
    std::vector<std::int32_t> converted_type;
    std::vector<std::uint32_t> u32;
    std::vector<std::uint8_t> u8;
    std::vector<bool> boolean;
    std::size_t end_offset{};
};

struct ParFxPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    std::int32_t serialized_fix_type{};
    std::optional<std::int32_t> internal_type;
    std::vector<float> private_f32;
    std::vector<std::int32_t> private_s32;
    std::vector<bool> private_bool;
    std::optional<ChunkHeader> child_chunk;
    std::optional<ParFxChildPayload> parsed_child;
    std::size_t end_offset{};
};

struct ParFxTypeMapping {
    std::int32_t serialized_fix_type{};
    std::int32_t internal_type{};
};

// kontakt 8 effect IDs, your mappings win if another version differs
[[nodiscard]] std::span<const ParFxTypeMapping>
kontakt8_runtime_par_fx_type_mappings() noexcept;

struct InternalModulatorPayload;
struct ExternalModulatorPayload;

struct ParameterArrayEntry {
    bool present{};
    std::optional<std::int32_t> context_id;
    std::optional<ChunkHeader> chunk;
    std::optional<ParFxPayload> par_fx;
    std::shared_ptr<InternalModulatorPayload> internal_modulator;
    std::shared_ptr<ExternalModulatorPayload> external_modulator;
};

struct ParameterArrayPayload {
    ParameterArrayPrefix prefix;
    std::vector<ParameterArrayEntry> entries;
    std::size_t end_offset{};
};

struct GroupSnapshotPayload {
    GroupSnapshotPrefix prefix;
    ParameterArrayPayload effect_array;
    SourceModePayload source_mode;
    std::array<bool, 2> flags_after_source_mode{};
    ParameterArrayPayload internal_modulator_array;
    ParameterArrayPayload external_modulator_array;
    std::optional<bool> samples_purged;
    std::vector<std::int32_t> version_4_s32;
    std::size_t end_offset{};
};

struct InsertBusPayload {
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    std::string name;
    std::array<float, 2> level_pan{};
    std::optional<std::int32_t> version_0x11_s32;
    std::vector<bool> version_0x12_flags;
    std::optional<ChunkHeader> effect_array_chunk;
    ParameterArrayPayload effect_array;
    std::size_t end_offset{};
};

struct SnapshotPayload {
    SerializableHeader serializable;
    std::optional<std::int32_t> version_3_discriminator;
    std::optional<GroupArrayHeader> group_array;
    std::vector<GroupSnapshotPayload> groups;
    std::optional<ParameterArrayPayload> master_effect_array;
    std::optional<ParameterArrayPayload> program_effect_array;
    std::vector<InsertBusPayload> insert_buses;
    std::array<std::vector<std::optional<std::string>>, 5> string_arrays;
    std::optional<ParameterArrayPayload> third_effect_array;
    std::size_t end_offset{};
};

struct SnapshotMetadataPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::int32_t translated_filename_table_index{};
    std::string wide_string_0;
    std::string wide_string_1;
    std::size_t end_offset{};
};

struct SnapshotPresetPayload {
    PresetImplPrefix preset_prefix;
    SnapshotPayload snapshot;
    std::size_t end_offset{};
};

enum class PresetKind : std::uint8_t {
    insert_fx = 0,
    send_fx = 1,
    internal_modulator = 2,
    modulation_table = 3,
    source_mode = 4,
    insert_fx_chain = 5,
    send_fx_chain = 6,
    script = 7,
    multi_script = 8,
    snapshot = 9,
};

enum class ModulationTransformationKind : std::uint8_t {
    none = 0,
    table = 1,
    curve = 2,
};

struct ModulationTransformationPayload {
    std::uint8_t serialized_kind{};
    std::optional<ModulationTransformationKind> kind;
    std::optional<bool> enabled;
    std::vector<float> values;
    std::size_t end_offset{};
};

struct InternalModLfoPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::int32_t waveform{};
    std::vector<float> values;
    std::vector<bool> flags;
    std::size_t end_offset{};
};

struct InternalModChildPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::vector<std::int32_t> s32;
    std::vector<std::uint32_t> u32;
    std::vector<float> f32;
    std::vector<bool> flags;
    std::size_t end_offset{};
};

struct InternalModEnvelopePayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    std::int32_t envelope_type{};
    InternalModChildPayload child;
    std::size_t end_offset{};
};

struct InternalModTargetPayload {
    std::string target_xml_name;
    float amount{};
    std::int16_t s16_a{};
    std::uint8_t u8{};
    std::int16_t s16_b{};
    std::string assignment;
    std::optional<std::int8_t> target_s8;
    bool flag{};
    ModulationTransformationPayload transformation;
};

struct InternalModulatorPayload {
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    std::uint16_t base_layout_version{};
    std::int32_t target_count{};
    std::vector<InternalModTargetPayload> targets;
    std::array<bool, 4> flags{};
    std::int32_t s32{};
    std::optional<std::string> name;
    std::int32_t modulator_type{};
    std::optional<InternalModLfoPayload> lfo;
    std::optional<InternalModEnvelopePayload> envelope;
    std::optional<InternalModChildPayload> arp;
    std::optional<InternalModChildPayload> env_f;
    std::optional<InternalModChildPayload> glide;
    std::size_t end_offset{};
};

struct ExternalModulatorPayload {
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    std::uint16_t base_layout_version{};
    std::int32_t target_count{};
    std::vector<InternalModTargetPayload> targets;
    std::string name;
    std::int32_t mode{};
    std::optional<std::int32_t> serialized_source;
    std::optional<std::int32_t> source;
    std::optional<std::uint8_t> controller;
    std::optional<std::int32_t> source_parameter;
    std::optional<std::int16_t> s16;
    std::array<bool, 4> flags{};
    std::size_t flag_count{};
    std::int32_t s32{};
    std::size_t end_offset{};
};

struct VoiceLimitPayload {
    SerializableHeader serializable;
    std::string name;
    std::int16_t s16{};
    bool flag{};
    std::array<std::int32_t, 3> s32{};
    std::size_t end_offset{};
};

struct IndexedVoiceLimit {
    std::uint8_t index{};
    VoiceLimitPayload value;
};

struct VoiceGroupChunkPayload {
    ChunkHeader chunk;
    VoiceLimitPayload global_limit;
    std::array<std::uint8_t, 16> presence_mask{};
    std::vector<IndexedVoiceLimit> active_limits;
    std::size_t end_offset{};
};

struct ParScriptPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::optional<std::string> source_text;
    bool source_editor_open{};
    bool touched_but_not_applied{};
    bool bypass{};
    // v0x50 stores password text; v0x60 stores the binary hash
    std::optional<std::string> version_0x50_password;
    std::vector<std::byte> password_hash;
    std::optional<std::string> description;
    std::optional<std::string> text_file_name;
    // each persistent_var_* legacy tag becomes a "name value" string
    std::vector<std::optional<std::string>> persistent_variables;
    std::size_t end_offset{};
};

// the common payload's U8 kind selects one child; only that child is populated
struct PresetPayload {
    PresetImplPrefix prefix;
    PresetKind kind{};
    std::optional<ParFxPayload> par_fx;
    std::optional<SourceModePayload> source_mode;
    std::optional<ParameterArrayPayload> effect_chain;
    std::optional<ParScriptPayload> script;
    std::optional<SnapshotPayload> snapshot;
    std::optional<ModulationTransformationPayload> transformation;
    std::optional<InternalModulatorPayload> internal_modulator;
    std::size_t end_offset{};
};

struct QuickBrowseDataPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::int32_t value{};
    std::size_t end_offset{};
};

struct GroupPublicPayload {
    std::string name;
    std::array<float, 3> f32{};
    std::array<bool, 4> flags{};
    std::int32_t s32_before_s16{};
    std::int16_t s16{};
    std::array<std::int32_t, 2> s32_after_s16{};
    std::array<bool, 2> trailing_flags{};
    std::int32_t enum_0_to_2{};
    std::size_t end_offset{};
};

struct StartCriteriaPayload {
    SerializableHeader serializable;
    std::int32_t enum_0_to_5{};
    std::int32_t enum_0_to_2{};
    std::array<std::int16_t, 5> s16{};
    // cycle class, slice zone index, slice index
    std::array<std::int32_t, 3> s32{};
    bool flag{};
    std::size_t end_offset{};
};

struct GroupDynamicsPayload {
    SerializableHeader serializable;
    std::array<float, 64> values{};
    std::size_t end_offset{};
};

struct GroupChildrenPayload {
    std::array<ChunkHeader, 2> parameter_array_chunks;
    std::array<ParameterArrayPayload, 2> parameter_arrays;
    ChunkHeader start_criteria_chunk;
    std::uint8_t start_criteria_presence_mask{};
    std::vector<std::pair<std::uint8_t, StartCriteriaPayload>> start_criteria;
    std::optional<ChunkHeader> dynamics_chunk;
    std::optional<GroupDynamicsPayload> dynamics;
    std::size_t end_offset{};
};

struct AutomationObjectPayload {
    SerializableHeader serializable;
    std::int32_t enum_0_to_2{};
    bool flag{};
    std::optional<bool> version_0x70_boolean;
    std::uint16_t u16{};
    std::int32_t first_s32{};
    std::optional<std::int32_t> version_0x71_second_s32;
    std::array<float, 2> f32{};
    std::string parameter_tag;
    std::size_t end_offset{};
};

struct FixedByteRunPayload {
    std::uint32_t declared_count{};
    std::vector<std::uint8_t> values;
};

struct GroupPrivatePayload {
    std::array<FixedByteRunPayload, 136> byte_runs;
    std::array<bool, 3> leading_flags{};
    std::array<std::int32_t, 3> leading_s32{};
    bool flag_before_s32_pair{};
    std::array<std::int32_t, 2> s32_pair{};
    ParameterArrayPayload parameter_array;
    bool flag_after_parameter_array{};
    SourceModePayload source_mode;
    std::uint32_t automation_capacity{};
    std::optional<std::uint32_t> automation_serialized_count;
    std::vector<AutomationObjectPayload> automation_objects;
    std::optional<std::int32_t> version_0x91_s32;
    std::array<std::optional<bool>, 2> version_0x92_flags;
    std::optional<bool> version_0x93_flag;
    std::array<std::optional<std::int32_t>, 2> version_0x94_s32;
    std::optional<std::uint8_t> version_0x95_u8;
    std::int32_t final_s32{};
    std::size_t end_offset{};
};

struct GroupPayload {
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    GroupPrivatePayload private_payload;
    GroupPublicPayload public_payload;
    GroupChildrenPayload children;
    std::size_t end_offset{};
};

struct ProgramGroupChunkPayload {
    ChunkHeader chunk;
    std::int32_t group_count{};
    std::vector<GroupPayload> groups;
    std::size_t end_offset{};
};

struct SampleSettingsPayload {
    std::array<std::int32_t, 2> leading_s32{};
    std::uint8_t u8{};
    std::array<std::int32_t, 2> middle_s32{};
    std::optional<std::int32_t> pre_0x96_s32;
    std::int32_t trailing_s32{};
    float f32{};
    bool flag{};
    std::int32_t final_s32{};
    std::size_t end_offset{};
};

struct ZonePublicPayload {
    std::int32_t sample_start{};
    std::int32_t sample_end{};
    std::int32_t sample_start_modulation_range{};
    std::int16_t low_velocity{};
    std::int16_t high_velocity{};
    std::int16_t low_key{};
    std::int16_t high_key{};
    std::int16_t fade_low_velocity{};
    std::int16_t fade_high_velocity{};
    std::int16_t fade_low_key{};
    std::int16_t fade_high_key{};
    std::int16_t root_key{};
    float volume{};
    float pan{};
    float tune{};
    std::array<std::optional<bool>, 2> version_0x9a_flags;
    std::optional<std::int32_t> version_0x9a_s32;
    std::optional<std::int32_t> sample_file_table_index;
    std::optional<SampleSettingsPayload> sample_settings;
    std::size_t end_offset{};
};

struct ZoneLevelEnvSegment {
    std::int32_t s32{};
    std::array<float, 2> f32{};
};

struct ZoneLevelEnvPayload {
    SerializableHeader serializable;
    bool has_data{};
    std::optional<std::int16_t> s16;
    std::array<std::optional<std::int32_t>, 2> s32;
    std::array<std::optional<bool>, 2> flags;
    std::optional<std::string> target_xml_name;
    std::optional<std::int8_t> s8;
    std::vector<ZoneLevelEnvSegment> segments;
    std::size_t end_offset{};
};

struct IndexedZoneLevelEnv {
    std::uint8_t index{};
    ZoneLevelEnvPayload value;
};

struct ZonePrivatePayload {
    std::int32_t leading_s32{};
    std::int32_t enum_0_to_2{};
    std::array<std::uint8_t, 4> u8{};
    std::array<float, 2> f32{};
    bool first_flag{};
    bool second_flag{};
    std::int32_t s32_after_flags{};
    float f32_after_s32{};
    std::array<std::int16_t, 2> s16{};
    std::array<std::int32_t, 3> s32{};
    std::uint8_t trailing_u8{};
    bool trailing_flag{};
    std::uint64_t u64{};
    std::array<std::uint8_t, 2> level_env_presence_mask{};
    std::vector<IndexedZoneLevelEnv> level_envs;
    std::array<std::optional<float>, 2> version_0x93_f32;
    std::optional<bool> version_0x95_flag;
    std::optional<std::int32_t> version_0x95_s32;
    std::array<std::optional<float>, 2> version_0x95_f32;
    std::optional<std::int32_t> version_0x99_s32;
    std::int32_t final_s32{};
    std::size_t end_offset{};
};

struct LoopPayload {
    SerializableHeader serializable;
    enum class Mode : std::int32_t {
        none = 0,
        until_end = 1,
        until_release = 2,
        oneshot = 3,
    };
    Mode mode{ Mode::none };
    std::int32_t start{};
    std::int32_t length{};
    std::int32_t count{};
    bool alternating{};
    float tuning{};
    std::int32_t crossfade_length{};
    std::size_t end_offset{};
};

struct IndexedLoop {
    std::uint8_t index{};
    LoopPayload value;
};

struct SamplePayload {
    SerializableHeader serializable;
    bool flag{};
    std::int32_t original_file_table_index{};
    std::size_t end_offset{};
};

struct SampleSlicePayload {
    std::int32_t position{};
    std::optional<float> position_f32;
    std::uint32_t value{};
};

struct SampleSlicesPayload {
    std::uint32_t count{};
    std::optional<std::uint32_t> header_value;
    std::vector<SampleSlicePayload> slices;
    std::size_t end_offset{};
};

struct ZoneChildrenPayload {
    ChunkHeader loop_chunk;
    std::uint8_t loop_presence_mask{};
    std::vector<IndexedLoop> loops;
    std::optional<QuickBrowseDataPayload> quick_browse;
    std::optional<ChunkHeader> sample_chunk;
    std::optional<SamplePayload> sample;
    std::optional<SampleSlicesPayload> slices;
    std::size_t end_offset{};
};

struct ZonePayload {
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    ZonePrivatePayload private_payload;
    ZonePublicPayload public_payload;
    ZoneChildrenPayload children;
    std::size_t end_offset{};
};

struct ZoneArrayPayload {
    SerializableHeader serializable;
    std::uint32_t zone_count{};
    std::vector<ZonePayload> zones;
    std::size_t end_offset{};
};

struct GroupCompletePayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    GroupPayload group;
    ZoneArrayPayload zone_array;
    std::size_t end_offset{};
};

struct ProgramZoneEntry {
    std::int32_t factory_selector{};
    ZonePayload zone;
};

struct ProgramZoneChunkPayload {
    ChunkHeader chunk;
    std::int32_t zone_count{};
    std::vector<ProgramZoneEntry> zones;
    std::size_t end_offset{};
};

struct ProgramChildrenPayload {
    std::vector<ChunkHeader> effect_array_chunks;
    std::vector<ParameterArrayPayload> effect_arrays;
    std::vector<ChunkHeader> insert_bus_chunks;
    std::vector<InsertBusPayload> insert_buses;
    std::vector<ParScriptPayload> scripts;
    std::optional<QuickBrowseDataPayload> quick_browse;
    VoiceGroupChunkPayload voice_groups;
    ProgramGroupChunkPayload groups;
    ProgramZoneChunkPayload zones;
    std::size_t end_offset{};
};

struct NISoundDataPayload {
    SerializableHeader serializable;
    bool present{};
    std::array<std::uint32_t, 2> sound_info_u32_prefix{};
    std::array<std::string, 5> sound_info_strings;
    std::array<std::uint32_t, 6> sound_info_u32{};
    std::int32_t sound_info_s32{};
    std::vector<std::vector<std::string>> bank_chain_strings;
    std::vector<std::string> tags;
    std::vector<std::pair<std::string, std::string>> user_attributes;
    std::vector<std::pair<std::string, std::string>> string_map;
    struct ControllerAssignment {
        std::string name;
        std::array<float, 2> f32{};
        std::array<std::uint32_t, 2> u32{};
    };
    struct ControllerGroup {
        std::string name;
        std::vector<ControllerAssignment> assignments;
    };
    std::vector<ControllerGroup> controller_groups;
    std::optional<std::array<std::byte, 16>> item_uuid;
    std::size_t end_offset{};
};

struct ProgramPublicPayload {
    std::string name;
    double f64{};
    std::int8_t s8{};
    std::array<float, 3> f32{};
    std::array<std::uint8_t, 4> u8{};
    std::int16_t s16{};
    std::int32_t s32{};
    std::array<std::uint32_t, 3> u32{};
    bool flag{};
    std::int32_t s32_after_flag{};
    std::array<std::string, 3> strings;
    std::array<std::int16_t, 3> s16_tail{};
    std::optional<std::int32_t> content_file_table_index;
    std::vector<std::string> version_strings;
    std::optional<std::int32_t> version_0xa6_filename_index;
    std::optional<std::uint32_t> version_0xaf_u32;
    std::vector<NISoundDataPayload> nisound_data;
    std::optional<bool> version_0xb1_flag;
    std::optional<std::int32_t> version_0xb2_s32;
    std::optional<std::string> version_0xb3_string;
    std::optional<std::int32_t> version_0xb4_s32;
    std::vector<std::int32_t> trailing_special_filename_indices;
    std::size_t end_offset{};
};

struct DyxMorphGroupPayload {
    SerializableHeader serializable;
    std::int32_t s32{};
    std::string name;
    std::array<float, 3> f32{};
    bool flag{};
    std::int16_t s16{};
    std::size_t end_offset{};
};

struct DyxMorphMapPayload {
    SerializableHeader serializable;
    std::int32_t enum_1_to_2{};
    std::int32_t s32{};
    std::string name;
    std::uint32_t declared_value_count{};
    std::vector<std::int32_t> values;
    std::size_t end_offset{};
};

struct ProgramPrivatePayload {
    std::int32_t enum_0_to_2{};
    std::array<bool, 2> leading_flags{};
    std::int32_t first_s32{};
    bool flag_before_s32_pair{};
    std::array<std::int32_t, 2> s32_pair{};
    bool flag_before_second_s32{};
    std::int32_t second_s32{};
    std::array<bool, 3> flags_before_third_s32{};
    std::int32_t third_s32{};
    std::array<bool, 13> middle_flags{};
    std::array<std::int32_t, 3> s32_triplet{};
    std::array<bool, 2> flags_before_s16{};
    std::int16_t s16{};
    bool flag_after_s16{};
    std::optional<std::int32_t> legacy_filename_table_index;
    std::vector<ParScriptPayload> legacy_scripts;
    std::vector<DyxMorphGroupPayload> morph_groups;
    std::vector<DyxMorphMapPayload> morph_maps;
    std::uint32_t automation_capacity{};
    std::optional<std::uint32_t> automation_count;
    std::vector<AutomationObjectPayload> automation_objects;
    std::optional<bool> tail_flag;
    std::optional<std::array<std::int32_t, 2>> tail_s32_pair;
    std::optional<std::array<bool, 3>> tail_flags;
    std::optional<std::array<std::uint32_t, 2>> active_voice_counts;
    std::optional<std::int32_t> tail_s32;
    std::optional<std::array<bool, 2>> tail_flags_2;
    std::optional<std::array<std::int32_t, 2>> version_s32_pair;
    std::optional<std::uint32_t> tail_u32;
    std::optional<std::int32_t> filename_table_index;
    std::optional<std::array<bool, 2>> final_flags;
    std::optional<std::int32_t> final_s32;
    std::optional<std::string> final_string;
    std::optional<std::int32_t> legacy_special_filename_table_index;
    std::size_t end_offset{};
};

struct ProgramPayload {
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    ProgramPrivatePayload private_payload;
    ProgramPublicPayload public_payload;
    ProgramChildrenPayload children;
    std::size_t end_offset{};
};

struct SaveSettingsPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::int32_t translated_filename_table_index{};
    std::int32_t original_filename_table_index{};
    std::int32_t s32{};
    std::array<bool, 3> flags{};
    std::size_t end_offset{};
};

struct ProgramContainerPrivatePayload {
    std::int32_t s32{};
    std::array<bool, 4> flags{};
    std::int16_t s16{};
    std::optional<std::int32_t> version_0x50_original_filename_table_index;
    std::optional<std::int32_t> version_0x50_s32;
    std::optional<std::array<bool, 2>> version_0x50_flags;
    std::uint32_t automation_capacity{};
    std::optional<std::uint32_t> automation_count;
    std::vector<AutomationObjectPayload> automation_objects;
    std::optional<bool> version_0x50_trailing_flag;
    std::uint32_t output_mask{};
    std::size_t end_offset{};
};

struct ProgramContainerPublicPayload {
    std::string name;
    std::array<float, 2> f32{};
    std::size_t end_offset{};
};

struct ProgramContainerEntry {
    std::int16_t relative_slot{};
    ProgramPayload program;
};

struct ProgramContainerChildrenPayload {
    ChunkHeader voice_limit_chunk;
    VoiceLimitPayload voice_limit;
    std::optional<SaveSettingsPayload> save_settings;
    ChunkHeader programs_chunk;
    std::uint16_t program_count{};
    std::vector<ProgramContainerEntry> programs;
    std::size_t end_offset{};
};

struct ProgramContainerPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_markers{};
    ProgramContainerPrivatePayload private_payload;
    ProgramContainerPublicPayload public_payload;
    ProgramContainerChildrenPayload children;
    std::size_t end_offset{};
};

struct BankPrivatePayload {
    std::array<bool, 3> flags{};
    std::vector<std::int16_t> legacy_slot_numbers;
    std::array<bool, 64> legacy_slot_flags_0{};
    std::array<bool, 64> legacy_slot_flags_1{};
    std::array<std::vector<float>, 64> legacy_slot_f32;
    std::array<std::vector<std::int32_t>, 4> legacy_s32_arrays;
    std::optional<std::int32_t> legacy_original_filename_table_index;
    std::optional<std::int32_t> legacy_s32;
    std::optional<std::array<bool, 2>> legacy_flags;
    std::vector<ParScriptPayload> legacy_scripts;
    std::optional<std::array<std::int32_t, 2>> version_0x74_s32;
    std::optional<std::string> version_0x76_uuid;
    std::size_t end_offset{};
};

struct BankPublicPayload {
    std::array<float, 2> f32{};
    std::int32_t s32{};
    std::string name;
    std::size_t end_offset{};
};

struct BankSlotEntry {
    std::uint8_t serialized_slot{};
    ProgramContainerPayload program_container;
};

struct BankSlotListPayload {
    ChunkHeader chunk;
    std::array<std::uint8_t, 8> presence_mask{};
    std::uint16_t serialized_count{};
    std::vector<BankSlotEntry> entries;
    std::size_t end_offset{};
};

struct OutputPartitionPayload {
    SerializableHeader serializable;
    std::string name;
    std::array<std::int16_t, 2> s16{};
    float level{};
    std::vector<ParFxPayload> effects;
    std::size_t end_offset{};
};

struct IndexedOutputPartition {
    std::uint8_t index{};
    OutputPartitionPayload value;
};

struct OutputConfigurationPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::vector<std::int32_t> s32_array;
    std::array<std::uint8_t, 16> presence_mask{};
    std::vector<IndexedOutputPartition> partitions;
    std::size_t end_offset{};
};

struct BankMidiRoutingRecord {
    std::int16_t s16{};
    std::optional<std::int32_t> version_0x75_s32;
    std::array<bool, 2> flags{};
    std::vector<float> f32_values;
};

struct BankMidiRoutingPayload {
    ChunkHeader chunk;
    std::array<BankMidiRoutingRecord, 64> records;
    std::size_t end_offset{};
};

struct BankAudioRoutingPayload {
    ChunkHeader chunk;
    std::vector<std::vector<std::int32_t>> s32_lists;
    std::size_t end_offset{};
};

struct BankPayload {
    ChunkHeader chunk;
    SerializableHeader serializable;
    std::array<std::int32_t, 3> phase_sizes{};
    BankPrivatePayload private_payload;
    BankPublicPayload public_payload;
    std::vector<ChunkHeader> child_chunks;
    std::optional<OutputConfigurationPayload> output_configuration;
    bool output_configuration_in_private_phase{};
    std::optional<BankSlotListPayload> slot_list;
    std::optional<BankMidiRoutingPayload> midi_routing;
    std::optional<BankAudioRoutingPayload> audio_routing;
    std::size_t end_offset{};
};

// one error per child, so one we can't parse doesn't lose the others like the
// filename table
struct ModernPatchPayload {
    std::optional<std::size_t> preset_chunk_index;
    std::optional<std::uint16_t> artifact_kind;
    std::vector<ChunkHeader> chunks;
    std::optional<ProgramPayload> program;
    std::optional<ProgramContainerPayload> program_container;
    std::optional<BankPayload> bank;
    std::optional<GroupCompletePayload> group_complete;
    std::optional<ZoneArrayPayload> zone_array;
    std::optional<OutputConfigurationPayload> output_configuration;
    std::optional<PresetPayload> preset;
    std::optional<SnapshotMetadataPayload> snapshot_metadata;
    std::optional<SnapshotPayload> standalone_snapshot;
    std::optional<FileTable> file_table;
    std::vector<std::string> errors;
};

struct K42PatchHeader {
    static constexpr std::size_t serialized_size = 0xde;
    std::array<std::byte, serialized_size> normalized_bytes{};
    bool byte_swapped{};
    std::uint32_t magic{};
    std::uint32_t compressed_size{};
    std::uint16_t revision{};
    // NKM=0, NKI=1, NKB=2, NKP=3, NKG=4, NKZ=5, output config=6, NKSN=7
    std::uint16_t artifact_kind{};
    std::uint32_t signature{};
    std::uint32_t required_app_version{};
    std::uint16_t legacy_otp_word{};
    std::uint16_t library_word{};
    std::uint32_t library_id{};
    std::string product_snpid;
    std::uint32_t flags{};
    std::array<std::byte, 16> md5{};
    std::uint32_t payload_crc32{};
    std::uint32_t uncompressed_size{};

    [[nodiscard]] bool legacy_otp_encrypted() const noexcept {
        return (flags & 4U) != 0;
    }
};

struct K42PatchData {
    K42PatchHeader header;
    std::vector<std::byte> decompressed;
    std::vector<ChunkHeader> chunks;
};

struct K2PatchHeader {
    static constexpr std::size_t serialized_size = 0xaa;
    std::array<std::byte, serialized_size> normalized_bytes{};
    bool byte_swapped{};
    std::uint32_t magic{};
    std::uint32_t embedded_stream_size{};
    std::uint32_t compressed_size{};
    std::uint16_t generation_revision{};
    std::uint16_t preset_kind{};
    std::uint32_t signature{};
    std::uint32_t creator_version{};
    std::uint32_t required_app_version{};
    std::uint16_t legacy_otp_word{};
    std::uint16_t library_word{};
    std::uint32_t library_id{};
    std::string product_snpid;
    std::uint32_t flags{};
    std::uint32_t checksum{};

    [[nodiscard]] bool legacy_otp_encrypted() const noexcept {
        return (flags & 4U) != 0;
    }
};

struct K1TagAttribute {
    std::string name;
    std::string value;
};

struct K1TagElement {
    std::string name;
    std::vector<K1TagAttribute> attributes;
    std::vector<K1TagElement> children;
    bool self_closing{};
};

struct K1ZoneParameters {
    std::uint16_t struct_version{};
    std::optional<std::int16_t> low_key;
    std::optional<std::int16_t> high_key;
    std::optional<std::int16_t> low_velocity;
    std::optional<std::int16_t> high_velocity;
    std::optional<std::int16_t> fade_low_key;
    std::optional<std::int16_t> fade_high_key;
    std::optional<std::int16_t> fade_low_velocity;
    std::optional<std::int16_t> fade_high_velocity;
    std::optional<std::int16_t> root_key;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    std::optional<std::int32_t> sample_start;
    std::optional<std::int32_t> sample_end;
    std::optional<float> slicer_sensitivity;
    std::optional<bool> reference_zone;
};

enum class K1SamplePathEncoding {
    old_style,
    new_style_file_ex,
    new_style_file_ex2,
};

struct K1SampleSlice {
    std::int32_t index{};
    std::int32_t start{};
    std::int32_t end{};
};

struct K1SampleSemantic {
    std::optional<std::string> path;
    std::optional<K1SamplePathEncoding> path_encoding;
    std::vector<K1SampleSlice> slices;
};

enum class K1LoopMode : std::uint32_t {
    oneshot = 1,
    until_end = 3,
    until_release = 4,
};

struct K1LoopSemantic {
    std::uint16_t struct_version{};
    std::optional<std::int32_t> index;
    std::int32_t start{};
    std::int32_t length{};
    std::int32_t serialized_start{};
    std::int32_t serialized_length{};
    bool negative_start_clamped{};
    bool length_requires_loaded_sample_frame_count{};
    std::int32_t count{};
    bool alternating{};
    K1LoopMode mode{ K1LoopMode::until_end };
    float tuning{};
    std::int32_t crossfade_length{};
};

struct K1GroupParameters {
    std::uint16_t struct_version{};
    std::optional<bool> muted;
    std::optional<bool> solo;
    std::optional<std::int32_t> ui_row;
    std::optional<std::int32_t> ui_column;
    std::optional<std::int16_t> midi_channel;
    std::optional<std::int16_t> effective_midi_channel;
    bool midi_channel_overridden_by_program{};
    std::optional<std::int32_t> battery_low_key;
    std::optional<std::int32_t> battery_high_key;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    std::optional<bool> key_tracking;
    std::optional<bool> reverse;
    std::optional<bool> release_trigger;
    std::optional<bool> release_trigger_note_monophonic;
    std::optional<std::int32_t> release_trigger_counter;
    std::optional<std::int32_t> output;
    std::optional<std::int32_t> voice_group;
    std::optional<bool> selected_for_edit;
    std::optional<bool> effective_selected_for_edit;
};

struct K1GroupOutputResolution {
    std::int32_t serialized_output{};
    std::uint16_t requested_output_type{};
    std::uint16_t requested_ordinal{};
    bool requires_live_bank_output_configuration{ true };
    bool applied_only_when_program_output_is_unassigned{ true };
};

[[nodiscard]] std::uint32_t resolve_k1_group_output(
        const K1GroupOutputResolution &request,
        std::span<const std::int16_t> live_output_types);

struct K1ProgramParameters {
    std::uint16_t struct_version{};
    std::optional<std::int32_t> ui_rows;
    std::optional<std::int32_t> ui_columns;
    std::optional<std::int16_t> midi_channel;
    std::optional<float> master_volume;
    std::optional<float> master_pan;
    std::optional<float> master_tune;
    std::optional<std::uint32_t> output;
    std::optional<std::int8_t> transpose;
    std::optional<std::int8_t> low_velocity;
    std::optional<std::int8_t> high_velocity;
    std::optional<std::int8_t> low_key;
    std::optional<std::int8_t> high_key;
    std::optional<std::int32_t> fingerprint;
    std::optional<std::int32_t> active_group_index;
    std::optional<std::int32_t> effective_active_group_index;
    bool active_group_index_repaired{};
};

struct K1ModulationTarget {
    std::uint8_t index{};
    std::optional<std::string> xml_target;
    std::optional<std::uint32_t> target_id;
    std::optional<float> intensity;
    bool negative_intensity{};
    std::optional<std::int8_t> target_mod_index;
    std::optional<std::int16_t> slot_index;
    bool slot_index_inferred_from_effect_type{};
    bool wrong_arpeggiator_direction_corrected{};
    bool legacy_fx_intensity_corrected{};
    bool legacy_fx_intensity_requires_engine_sample_rate_conversion{};
    std::optional<std::uint8_t> moved_from_xsync_modulator_index;
};

struct K1InternalModulatorParameters {
    std::optional<float> frequency;
    std::optional<float> pulse_width;
    std::optional<float> note_value_frequency;
    std::optional<bool> retrigger;
    std::optional<bool> bypass;
    std::optional<std::int32_t> x_sync_mod_index;
};

enum class K1LfoWaveform : std::uint32_t {
    sine = 0,
    rectangle = 1,
    triangle = 2,
    sawtooth = 3,
    random = 4,
    multi = 5,
};

struct K1LfoParameters {
    std::optional<K1LfoWaveform> waveform;
    std::optional<float> delay;
    std::optional<float> note_value_delay;
    std::optional<float> level_sine;
    std::optional<float> level_rectangle;
    std::optional<float> level_triangle;
    std::optional<float> level_sawtooth;
    std::optional<float> level_random;
};

enum class K1ExternalModSource : std::uint32_t {
    pitch_bend = 1,
    poly_aftertouch = 2,
    mono_aftertouch = 3,
    midi_cc = 4,
    key_position = 7,
    velocity = 8,
    release_velocity = 9,
    release_trigger_counter = 10,
    legacy_cc_source_11 = 11,
    legacy_cc_source_12 = 12,
    legacy_cc_source_13 = 13,
};

struct K1ExternalModulatorParameters {
    std::optional<K1ExternalModSource> source;
    std::optional<std::int8_t> cc_number;
    std::optional<float> delay;
    std::optional<bool> bypass;
};

enum class K1EnvelopeType : std::uint32_t {
    ahdsr = 0,
    fm7 = 1,
    dbd = 2,
};

struct K1EnvelopeParameters {
    std::optional<K1EnvelopeType> type;
    std::optional<float> attack;
    std::optional<float> hold;
    std::optional<float> decay;
    std::optional<float> sustain;
    std::optional<float> release;
    std::optional<float> attack_curving;
    std::optional<bool> note_off_less_mode;
    std::optional<float> note_value_attack;
    std::optional<float> note_value_hold;
    std::optional<float> note_value_decay;
    std::optional<float> note_value_release;
    std::optional<float> break_level;
    std::optional<float> decay1;
    std::optional<float> decay2;
    std::optional<float> note_value_decay1;
    std::optional<float> note_value_decay2;
    std::optional<std::int32_t> loop_start;
    std::optional<std::int32_t> loop_end;
    std::optional<std::int32_t> release_end;
    std::optional<bool> loop_enabled;
    std::optional<bool> oneshot_mode;
    std::array<std::optional<float>, 32> times{};
    std::array<std::optional<float>, 32> levels{};
    std::array<std::optional<float>, 32> slopes{};
    std::optional<float> note_value_grid;
};

struct K1EnvelopeFollowerParameters {
    std::optional<float> attack;
    std::optional<float> decay;
    std::optional<float> gain;
    std::optional<float> adaptation_speed;
};

struct K1ArpeggiatorParameters {
    bool is_32_step{};
    bool pre_0x60_volume_steps_negated{};
    std::optional<std::int32_t> number_of_steps;
    std::optional<bool> single_trigger;
    std::array<std::optional<float>, 32> steps{};
};

enum class K1GlideMode {
    speed,
    time,
};

struct K1GlideParameters {
    std::optional<K1GlideMode> mode;
    std::optional<float> coefficient;
    std::optional<float> note_value_coefficient;
};

struct K1ModulationTable {
    std::array<float, 128> values{};
    std::array<bool, 128> explicit_points{};
    bool external_source_range_conversion{};
};

enum class K1EffectKind {
    filter,
    compressor,
    inverter,
    lo_fi,
    shaper,
    stereo_spread,
    distortion,
    delay,
    chorus,
    flanger,
    phaser,
    reverb,
};

struct K1EffectSemantic {
    K1EffectKind kind{};
    std::uint16_t struct_version{};
    std::vector<K1TagAttribute> attributes;
    std::optional<bool> bypass;
    std::optional<float> output_level;
    std::optional<float> return_level;
    std::optional<std::int32_t> execution_order;
    std::optional<std::uint8_t> runtime_slot;
    std::optional<std::string> type;
    std::optional<std::string> model;
    std::optional<float> cutoff;
    std::optional<float> resonance;
    std::optional<float> gain;
    std::array<std::optional<float>, 3> band_width{};
    std::array<std::optional<float>, 3> frequency{};
    std::array<std::optional<float>, 3> band_gain{};
    std::array<std::optional<float>, 3> shift{};
    std::array<std::optional<float>, 3> band_type{};
    std::array<std::optional<float>, 3> band_bypass{};
    std::array<std::optional<float>, 3> band_resonance{};
    std::optional<float> threshold;
    std::optional<float> ratio;
    std::optional<float> attack;
    std::optional<float> release;
    std::optional<bool> stereo_link;
    std::optional<bool> phase;
    std::optional<bool> panorama;
    std::optional<float> bits;
    std::optional<float> down_sample_file_value;
    std::optional<float> down_sample;
    bool down_sample_requires_engine_sample_rate_conversion{};
    std::optional<float> noise_level;
    std::optional<float> noise_color;
    std::optional<float> shape;
    std::optional<float> spread;
    std::optional<float> drive;
    std::optional<float> damping;
    std::optional<float> depth;
    std::optional<float> speed;
    std::optional<float> feedback;
    std::optional<float> phase_amount;
    std::optional<float> color;
    std::optional<float> time;
    std::optional<float> panning;
    std::optional<float> pre_delay;
    std::optional<float> room_size;
    std::optional<float> stereo;
    std::optional<float> filter_amount;
    std::optional<float> note_value_speed;
    std::optional<float> note_value_time;
};

struct K1SourceModeSemantic {
    std::uint16_t struct_version{};
    std::optional<std::string> type;
    std::optional<std::uint32_t> runtime_type;
    bool requires_loaded_sample_streamability_check{};
    std::optional<std::uint32_t> non_streamable_fallback_runtime_type;
    bool missing_slices_require_runtime_grid_initialization{};
    std::optional<std::uint32_t> missing_slices_runtime_grid_mode;
    std::optional<float> speed;
    std::optional<float> smooth;
    std::optional<float> note_value_speed;
    std::optional<float> formant_shift;
    std::optional<float> grain_length_file_value;
    std::optional<float> grain_length;
    bool grain_length_requires_sample_rate_conversion{};
    std::optional<bool> high_quality;
    std::optional<bool> dc_filter;
    std::optional<bool> retrigger;
    std::optional<float> slice_attack;
    std::optional<float> slice_release;
    std::optional<bool> slice_auto_play;
    std::optional<bool> transient_copy;
    std::optional<std::int32_t> transient_size;
    std::optional<std::int32_t> analysis_grain_size;
};

struct K1StartCriteriaSemantic {
    std::uint16_t struct_version{};
    std::optional<std::string> mode;
    std::optional<std::int16_t> key_min;
    std::optional<std::int16_t> key_max;
    std::optional<std::int16_t> controller;
    std::optional<std::int16_t> controller_min;
    std::optional<std::int16_t> controller_max;
    std::optional<std::int32_t> slice_zone_index;
    std::optional<std::int32_t> slice_index;
    std::optional<bool> sequencer_only;
    std::optional<std::int32_t> cycle_class;
    std::optional<std::string> next_criteria;
};

struct K1SendLevelsSemantic {
    float delay{ 1.0F };
    float chorus{ 1.0F };
    float flanger{ 1.0F };
    float phaser{ 1.0F };
    float reverb{ 1.0F };
    std::optional<std::uint8_t> runtime_effect_slot;
    bool materialized_by_pre_v2_close{};
};

struct K1VoiceLimitSemantic {
    std::uint16_t struct_version{};
    std::optional<std::string> name;
    std::optional<std::int32_t> maximum_voices;
    std::optional<std::string> mode;
    std::optional<bool> prefer_released;
    std::optional<std::int32_t> fade_time_ms;
    std::optional<std::int32_t> exclusion_group;
};

enum class K1AutomationType : std::uint32_t {
    midi_controller = 1,
    host_automation = 2,
};

struct K1AutomationSemantic {
    std::uint16_t struct_version{};
    std::vector<K1TagAttribute> attributes;
    std::optional<K1AutomationType> type;
    std::optional<std::string> target_tag;
    std::optional<std::uint32_t> parameter_tag;
    std::optional<std::int16_t> midi_cc;
    std::optional<std::int32_t> modulator_index;
    std::optional<std::uint8_t> effect_slot;
    std::optional<std::int32_t> program_object_selector;
    bool effect_slot_inferred_from_target_tag{};
    std::optional<bool> soft_take_over;
};

enum class K1ModulatorClass {
    internal,
    external,
    static_modulator,
};

struct K1ModulatorSemantic {
    K1ModulatorClass modulator_class{};
    std::optional<std::uint8_t> index;
    std::vector<K1TagAttribute> attributes;
    std::uint16_t struct_version{};
    std::optional<std::uint16_t> subtype_version;
    std::uint8_t target_count{ 1 };
    std::vector<K1ModulationTarget> targets;
    std::optional<std::string> internal_type;
    std::optional<K1InternalModulatorParameters> internal_parameters;
    std::optional<K1LfoParameters> lfo;
    std::optional<K1ExternalModulatorParameters> external_parameters;
    std::optional<K1EnvelopeParameters> envelope;
    std::optional<K1EnvelopeFollowerParameters> envelope_follower;
    std::optional<K1ArpeggiatorParameters> arpeggiator;
    std::optional<K1GlideParameters> glide;
    std::optional<K1ModulationTable> modulation_table;
    std::vector<K1ModulationTarget> removed_unused_targets;
};

struct K1GroupSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K1GroupParameters> parameters;
    std::vector<K1ModulatorSemantic> modulators;
    std::vector<K1EffectSemantic> effects;
    std::optional<K1SourceModeSemantic> source_mode;
    std::vector<K1StartCriteriaSemantic> start_criteria;
    std::optional<K1SendLevelsSemantic> send_levels;
    std::optional<K1SendLevelsSemantic> effective_send_levels;
    std::optional<K1GroupOutputResolution> output_resolution;
    std::vector<K1AutomationSemantic> automation;
    std::vector<K1AutomationSemantic> purged_automation;
    std::vector<K1ModulatorSemantic> removed_unused_modulators;
    bool generated_by_empty_program_recovery{};
};

struct K1ProgramSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<K1ProgramParameters> parameters;
    std::vector<K1VoiceLimitSemantic> voice_limits;
    std::vector<K1AutomationSemantic> automation;
    std::vector<K1EffectSemantic> effects;
    std::optional<K1SendLevelsSemantic> effective_send_levels;
    std::vector<K1AutomationSemantic> purged_automation;
    bool empty_program_default_group_generated{};
};

struct K1ZoneSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K1ZoneParameters> parameters;
    std::optional<K1SampleSemantic> sample;
    std::vector<K1LoopSemantic> loops;
};

struct K1PresetSemantic {
    std::vector<K1TagAttribute> attributes;
    std::vector<K1EffectSemantic> effects;
};

struct K1BankSemantic {
    std::vector<K1TagAttribute> attributes;
};

struct K1BatteryModulationSemantic {
    std::optional<std::int32_t> source;
    std::optional<std::int32_t> destination;
    std::optional<float> amount;
};

struct K1BatteryLayerSemantic {
    std::optional<std::string> path;
    std::optional<std::int16_t> low_velocity;
    std::optional<std::int16_t> high_velocity;
    std::optional<float> volume;
};

struct K1BatterySlotSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::string> label;
    std::optional<std::int32_t> root_key;
    std::optional<std::int32_t> low_key;
    std::optional<std::int32_t> high_key;
    std::optional<std::int32_t> mute_group;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> pitch;
    std::optional<std::int32_t> sample_start;
    std::optional<std::int32_t> effect_start;
    std::optional<std::int32_t> effect_length;
    std::optional<std::int32_t> effect_count;
    std::optional<std::int32_t> serialized_velocity_attack;
    std::optional<std::int32_t> serialized_velocity_hold;
    std::optional<std::int32_t> serialized_velocity_decay;
    std::optional<std::int32_t> serialized_velocity_sustain;
    std::optional<std::int32_t> serialized_velocity_release;
    std::optional<std::int32_t> serialized_pitch_decay_1;
    std::optional<std::int32_t> serialized_pitch_decay_2;
    std::optional<float> pitch_break;
    std::optional<float> pitch_amount;
    std::optional<float> waveshaper;
    std::optional<float> bit_reduction;
    std::optional<std::uint32_t> status;
    std::optional<std::int32_t> midi_channel;
    std::array<K1BatteryModulationSemantic, 6> modulation;
    std::vector<K1BatteryLayerSemantic> layers;
};

struct K1BatteryProgramSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::uint16_t> version;
    std::optional<std::string> name;
    std::optional<float> master_volume;
    std::vector<K1BatterySlotSemantic> slots;
};

enum class K2GridMode : std::uint32_t { none = 0, fixed = 1, automatic = 2 };
enum class K2InterpolationQuality : std::uint32_t {
    normal = 0,
    high = 1,
    ultra = 2
};

struct K2ZoneParameters {
    std::optional<std::int32_t> sample_start;
    std::optional<std::int32_t> sample_end;
    std::optional<std::int32_t> sample_start_modulation_range;
    std::optional<std::int16_t> low_key;
    std::optional<std::int16_t> high_key;
    std::optional<std::int16_t> low_velocity;
    std::optional<std::int16_t> high_velocity;
    std::optional<std::int16_t> fade_low_key;
    std::optional<std::int16_t> fade_high_key;
    std::optional<std::int16_t> fade_low_velocity;
    std::optional<std::int16_t> fade_high_velocity;
    std::optional<std::int16_t> root_key;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    std::optional<std::int32_t> morph_group_index;
    std::optional<K2GridMode> grid_mode;
    std::optional<std::uint8_t> fixed_unit_numerator;
    std::optional<std::uint8_t> fixed_unit_denominator;
    std::optional<std::uint8_t> measure_numerator;
    std::optional<std::uint8_t> measure_denominator;
    std::optional<float> tempo_scaling;
    bool propagate_to_slice_list_present{};
    std::optional<float> slicer_sensitivity;
    std::optional<bool> reference_zone;
    std::optional<bool> selected;
    std::optional<std::int32_t> zoom_scale_x;
    std::optional<float> zoom_scale_y;
    std::optional<std::int16_t> selected_loop_index;
    std::optional<std::int16_t> displayed_zle_index;
    std::optional<std::int32_t> groove_box_id;
    std::optional<std::int32_t> battery_map_position;
    std::optional<std::int32_t> battery_map_grab_start;
    std::optional<std::uint8_t> current_editor_tab;
    std::optional<std::uint16_t> parsed_version;
};

struct K2SampleSemantic {
    std::optional<std::string> path;
    std::optional<std::string> preferred_base_name;
    std::optional<std::int64_t> last_file_modified;
    std::optional<bool> volatile_sample;
    std::optional<bool> purged;
    std::optional<std::int32_t> unique_id;
    std::optional<std::int64_t> last_played;
    std::optional<std::uint32_t> sample_data_type;
    std::optional<std::int32_t> sample_rate;
    std::optional<std::int32_t> channel_count;
    std::optional<std::int32_t> frame_count;
    std::optional<std::int32_t> audio_offset;
    std::optional<std::int32_t> container_offset;
    std::optional<std::int32_t> root_note;
    std::optional<float> tuning;
    std::optional<bool> little_endian;
    std::optional<std::int32_t> expected_data_size;
};

struct K2LoopSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> start;
    std::optional<std::int32_t> length;
    std::optional<std::int32_t> count;
    std::optional<std::string> mode;
    std::optional<bool> alternating;
    std::optional<float> tuning;
    std::optional<std::int32_t> crossfade_length;
    std::optional<std::uint16_t> parsed_version;
};

struct K2ZoneSemantic {
    std::int32_t zone_ordinal{ -1 };
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K2ZoneParameters> parameters;
    std::optional<K2SampleSemantic> sample;
    std::vector<K2LoopSemantic> loops;
    bool missing_runtime_sample_removes_zone_on_close{ true };
    bool removed_by_close_due_to_absent_serialized_sample{};
};

struct K2GroupParameters {
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    std::optional<bool> key_tracking;
    std::optional<bool> reverse;
    std::optional<bool> release_trigger;
    std::optional<bool> release_trigger_note_monophonic;
    std::optional<std::int32_t> release_trigger_counter;
    std::optional<std::int32_t> raw_output_mask;
    std::optional<std::int16_t> midi_channel;
    std::optional<std::int32_t> voice_group;
    std::optional<bool> purged;
    std::array<std::optional<std::string>, 16> output_routing;
    std::optional<std::int32_t> amp_fx_split_point;
    std::optional<bool> selected_for_edit;
    std::optional<bool> selected_in_group_editor;
    std::optional<bool> zones_visible_in_map_list_view;
    std::optional<std::int32_t> battery_cell_color;
    std::optional<std::int32_t> battery_low_key;
    std::optional<std::int32_t> battery_high_key;
    std::optional<bool> fx_being_edited;
    std::optional<std::int32_t> edited_fx_index;
    std::optional<std::int32_t> groove_box_id;
    std::optional<K2InterpolationQuality> interpolation_quality;
    std::optional<bool> muted;
    std::optional<bool> soloed;
    std::optional<std::uint16_t> parsed_version;
};

struct K2GroupSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K2GroupParameters> parameters;
    bool effective_selected_for_edit{ true };
    bool selected_for_edit_repaired{};
};

enum class K2Cc64Mode : std::uint32_t {
    sustain_plus_controller = 0,
    sustain_without_controller = 1,
    controller_only = 3,
};

struct K2ProgramParameters {
    std::optional<double> total_sample_bytes;
    std::optional<std::uint8_t> transpose;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<float> tune;
    std::optional<std::uint8_t> low_velocity;
    std::optional<std::uint8_t> high_velocity;
    std::optional<std::uint8_t> low_key;
    std::optional<std::uint8_t> high_key;
    std::optional<std::int16_t> default_key_switch;
    std::optional<std::int32_t> dfd_channel_preload_size;
    std::optional<std::uint32_t> serialized_library_id;
    std::optional<std::uint32_t> loading_flags;
    std::optional<bool> group_solo;
    std::optional<K2Cc64Mode> cc64_mode;
    std::optional<bool> use_standard_cc_7_10;
    std::optional<bool> use_standard_cc_120_123;
    std::optional<std::int32_t> cc7_max_volume;
    std::optional<bool> auto_load_mode;
    std::optional<std::int32_t> active_group_index;
    std::optional<std::int32_t> edited_script_index;
    std::optional<bool> instrument_fx_being_edited;
    std::optional<std::int32_t> edited_instrument_fx_index;
    std::optional<bool> send_fx_being_edited;
    std::optional<std::int32_t> edited_send_fx_index;
    std::optional<bool> map_editor_list_mode;
    std::optional<bool> map_editor_locked;
    std::optional<bool> source_routers_open;
    std::optional<bool> amp_routers_open;
    std::optional<bool> up_down_mix_open_group;
    std::optional<bool> map_editor_open;
    std::optional<bool> sample_editor_open;
    std::optional<bool> group_editor_open;
    std::optional<bool> script_editor_open;
    std::optional<bool> properties_editor_open;
    std::optional<bool> map_editor_selected_groups_only;
    std::optional<bool> instrument_fx_visible;
    std::optional<bool> send_fx_visible;
    std::optional<bool> modulation_visible;
    std::optional<std::int32_t> master_zone_index;
    std::optional<std::int32_t> battery_visible_rows;
    std::optional<std::int32_t> battery_visible_columns;
    std::optional<bool> battery_irc_visible;
    std::optional<std::int16_t> performance_view_script_index;
    std::optional<std::int32_t> category_icon_index;
    std::optional<std::string> instrument_credits;
    std::optional<std::string> instrument_author;
    std::optional<std::string> instrument_url;
    std::optional<std::int16_t> instrument_category_1;
    std::optional<std::int16_t> instrument_category_2;
    std::optional<std::int16_t> instrument_category_3;
    std::optional<std::string> serialized_wallpaper_path;
    std::optional<std::uint16_t> parsed_version;
};

struct K2ProgramSemantic {
    std::int32_t program_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K2ProgramParameters> parameters;
    std::optional<std::int32_t> effective_active_group_index;
    bool active_group_index_repaired{};
};

enum class K2VoiceStealMode : std::uint16_t {
    any = 0,
    oldest = 1,
    newest = 2,
    highest = 3,
    lowest = 4,
};

struct K2VoiceLimitSemantic {
    std::int32_t program_ordinal{ -1 };
    bool global{};
    std::vector<K1TagAttribute> attributes;
    std::optional<std::string> name;
    std::optional<K2VoiceStealMode> mode;
    std::optional<bool> prefer_released;
    std::optional<std::int32_t> maximum_voices;
    std::optional<std::int32_t> fade_time_ms;
    std::optional<std::int32_t> exclusion_group;
    std::optional<std::uint16_t> parsed_version;
};

enum class K2StartMode : std::uint32_t {
    on_key = 1,
    on_controller = 2,
    cycle_round_robin = 3,
    cycle_random = 4,
    slice_trigger = 5,
};
enum class K2NextCriteria : std::uint32_t {
    and_also = 0,
    and_not = 1,
    or_else = 2
};

struct K2StartCriteriaSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K2StartMode> mode;
    std::optional<std::int16_t> minimum_key;
    std::optional<std::int16_t> maximum_key;
    std::optional<std::int16_t> controller;
    std::optional<std::int16_t> minimum_cc;
    std::optional<std::int16_t> maximum_cc;
    std::optional<std::int32_t> cycle_class;
    std::optional<std::int32_t> slice_zone_index;
    std::optional<std::int32_t> slice_index;
    std::optional<bool> sequencer_only;
    std::optional<K2NextCriteria> next_criteria;
    std::optional<std::uint16_t> parsed_version;
};

enum class K2SourceMode : std::uint32_t {
    tone_machine = 1,
    time_machine = 3,
    streaming = 4,
    slice_machine = 5,
    time_machine_2 = 6,
    sp1200_machine = 7,
    mpc60_machine = 8,
};

struct K2SourceModeSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<K2SourceMode> mode;
    bool requires_loaded_sample_streamability_check{};
    std::optional<std::uint32_t> non_streamable_fallback_runtime_type;
    bool missing_slices_require_runtime_grid_initialization{};
    std::optional<std::uint32_t> missing_slices_runtime_grid_mode;
    std::optional<float> speed;
    std::optional<float> smooth;
    std::optional<bool> serialized_retrigger;
    std::optional<bool> legato;
    std::optional<std::int32_t> sp1200_filter;
    std::optional<bool> zone_locked_speed;
    std::optional<float> note_value_speed;
    std::optional<bool> note_value_speed_enabled;
    std::optional<float> formant_shift;
    std::optional<float> grain_length;
    std::optional<bool> dc_filter;
    std::optional<bool> high_quality;
    std::optional<float> slice_attack;
    std::optional<float> slice_release;
    std::optional<bool> slice_auto_play;
    std::optional<bool> transient_copy;
    std::optional<std::int32_t> transient_size;
    std::optional<std::int32_t> analysis_grain_size;
    std::optional<std::uint16_t> parsed_version;
};

struct K2SliceSemantic {
    std::int32_t zone_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> index;
    std::optional<std::int32_t> position;
    std::optional<std::int32_t> flags;
};

struct K2ZleSegmentSemantic {
    std::int32_t index{};
    std::optional<std::int32_t> x;
    std::optional<float> y;
    std::optional<float> curve;
};

struct K2ZleSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> index;
    std::optional<std::int16_t> external_modulator_index;
    std::optional<std::int32_t> loop_start;
    std::optional<std::int32_t> loop_length;
    std::optional<bool> loop_active;
    std::optional<bool> speed_lock;
    std::optional<std::string> serialized_target;
    std::optional<std::uint32_t> target_id;
    std::optional<bool> target_lower_polarity;
    std::optional<std::uint8_t> target_index;
    std::vector<K2ZleSegmentSemantic> segments;
};

struct K2ModCurvePoint {
    float x{};
    float y{};
    float curve{};
};

struct K2ModTargetSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> index;
    std::optional<std::string> serialized_target;
    std::optional<std::uint32_t> target_id;
    std::optional<bool> target_lower_polarity;
    std::optional<float> intensity;
    std::optional<std::int16_t> slot_index;
    std::optional<std::uint8_t> flags;
    std::optional<std::int16_t> smoothing_coefficient;
    std::optional<std::uint8_t> target_object_index;
    std::optional<std::string> name;
    std::optional<std::uint16_t> parsed_version;
    std::optional<bool> table_open;
    bool has_table{};
    bool table_active{ true };
    std::array<float, 128> table{};
    bool has_curve{};
    bool curve_active{ true };
    std::vector<K2ModCurvePoint> curve;
};

enum class K2LfoWaveform : std::uint32_t {
    sine = 0,
    rectangle = 1,
    triangle = 2,
    sawtooth = 3,
    random = 4,
    multi = 5,
};

struct K2LfoSemantic {
    std::optional<K2LfoWaveform> waveform;
    std::optional<float> delay;
    std::optional<float> frequency;
    std::optional<float> pulse_width;
    std::optional<float> start_phase;
    std::optional<bool> normalize_multi_lfo;
    std::optional<float> note_value_frequency;
    std::optional<bool> note_value_frequency_enabled;
    std::optional<float> note_value_delay;
    std::optional<bool> note_value_delay_enabled;
    std::optional<float> sine_level;
    std::optional<float> rectangle_level;
    std::optional<float> triangle_level;
    std::optional<float> sawtooth_level;
    std::optional<float> random_level;
    std::optional<std::uint16_t> parsed_version;
};

enum class K2EnvelopeType : std::uint32_t { ahdsr = 0, fm7 = 1, dbd = 2 };

struct K2EnvelopeSemantic {
    std::optional<K2EnvelopeType> type;
    std::optional<float> attack_curving;
    std::optional<float> attack;
    std::optional<float> decay;
    std::optional<float> hold;
    std::optional<float> release;
    std::optional<float> sustain;
    std::optional<bool> note_off_less_mode;
    std::optional<float> note_value_attack;
    std::optional<float> note_value_decay;
    std::optional<float> note_value_hold;
    std::optional<float> note_value_release;
    std::optional<float> decay_1;
    std::optional<float> break_level;
    std::optional<float> decay_2;
    std::optional<float> note_value_decay_1;
    std::optional<float> note_value_decay_2;
    std::optional<std::int32_t> release_end;
    std::optional<std::int32_t> loop_start;
    std::optional<std::int32_t> loop_end;
    std::optional<bool> loop_enabled;
    std::optional<bool> one_shot_mode;
    std::array<std::optional<float>, 32> times;
    std::array<std::optional<float>, 32> levels;
    std::array<std::optional<float>, 32> slopes;
    std::optional<float> note_value_grid;
    std::optional<std::uint16_t> parsed_version;
};

struct K2EnvelopeFollowerSemantic {
    std::optional<float> attack;
    std::optional<float> decay;
    std::optional<float> gain;
    std::optional<float> adaptation_speed;
    std::optional<std::uint16_t> parsed_version;
};

enum class K2GlideType : std::uint32_t { speed = 0, time = 1 };
struct K2GlideSemantic {
    std::optional<K2GlideType> type;
    std::optional<float> coefficient;
    std::optional<float> note_value_coefficient;
    std::optional<bool> note_value_coefficient_enabled;
    std::optional<std::uint16_t> parsed_version;
};

struct K2ArpeggiatorSemantic {
    bool recognized_32_step_type{};
    std::optional<bool> snap_to_12;
    std::optional<std::int32_t> step_count;
    std::optional<bool> single_trigger;
    std::array<std::optional<float>, 32> steps;
    std::optional<float> frequency;
    std::optional<float> note_value_frequency;
    std::optional<bool> note_value_frequency_enabled;
    std::optional<std::uint16_t> parsed_version;
};

struct K2InternalModSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> serialized_index;
    std::vector<K2ModTargetSemantic> targets;
    enum class Kind : std::uint32_t {
        lfo = 1,
        envelope = 2,
        arpeggiator = 3,
        envelope_follower = 4,
        glide = 5
    };
    std::optional<Kind> kind;
    std::optional<bool> routers_open;
    std::optional<float> serialized_note_value_frequency;
    std::optional<bool> bypass;
    std::optional<bool> retrigger;
    std::optional<std::int32_t> class_id;
    std::optional<std::string> name;
    std::optional<float> serialized_frequency;
    std::optional<float> serialized_pulse_width;
    std::optional<bool> simulate_k2_dfd_volume_modulation;
    std::optional<std::uint16_t> parsed_version;
    std::optional<K2LfoSemantic> lfo;
    std::optional<K2EnvelopeSemantic> envelope;
    std::optional<K2EnvelopeFollowerSemantic> envelope_follower;
    std::optional<K2GlideSemantic> glide;
    std::optional<K2ArpeggiatorSemantic> arpeggiator;
};

enum class K2ExternalModType : std::uint32_t {
    external = 1,
    zone_envelope = 2
};
enum class K2ExternalModSource : std::uint32_t {
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

struct K2ExternalModSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> serialized_index;
    std::vector<K2ModTargetSemantic> targets;
    std::optional<K2ExternalModType> type;
    std::optional<K2ExternalModSource> source;
    std::optional<std::uint8_t> cc_number;
    std::optional<bool> bypass;
    std::optional<bool> simulate_k2_envelope_time_modulation;
    std::optional<std::int32_t> class_id;
    std::optional<std::string> name;
    std::optional<float> serialized_delay;
    std::optional<std::int16_t> initial_value;
    std::optional<std::uint16_t> parsed_version;
};

struct K2ScriptPersistentVariable {
    std::string serialized_name_suffix;
    std::string serialized_value;
    std::string combined_value;
};

struct K2ScriptSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::uint16_t> parsed_version;
    std::optional<std::string> source_text;
    std::optional<bool> source_editor_open;
    std::optional<bool> touched_but_not_applied;
    std::optional<bool> bypass;
    std::optional<std::string> serialized_password;
    std::optional<std::string> description;
    std::optional<std::string> text_file_name;
    std::vector<K2ScriptPersistentVariable> persistent_variables;
};

struct K2MorphGroupSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::uint16_t> parsed_version;
    std::optional<std::int32_t> id;
    std::optional<std::string> name;
    std::optional<float> smoothing;
    std::optional<float> left;
    std::optional<float> right;
    std::optional<bool> tonal;
    std::optional<std::int16_t> root_key_shift;
};

enum class K2MorphMapType : std::uint32_t { velocity = 1, articulation = 2 };

struct K2MorphMapSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::uint16_t> parsed_version;
    std::optional<K2MorphMapType> type;
    std::optional<std::int32_t> id;
    std::optional<std::string> name;
    std::array<std::optional<std::int32_t>, 64> morph_group_ids{};
};

enum class K2AutomationAddressMode : std::uint32_t {
    unknown = 0,
    midi_controller = 1,
    host_parameter = 2,
};

struct K2AutomationSemantic {
    std::vector<K1TagAttribute> attributes;
    std::int32_t program_index{ -1 };
    std::int32_t group_index{ -1 };
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    std::optional<std::uint16_t> parsed_version;
    std::optional<K2AutomationAddressMode> address_mode;
    std::optional<bool> soft_takeover;
    std::optional<bool> program_send_fx_is_in_insert_chain;
    std::optional<std::int16_t> address;
    std::optional<std::string> serialized_parameter_tag;
    std::optional<std::uint32_t> parameter_tag_id;
    std::optional<std::int32_t> object_index;
    std::optional<float> range_from;
    std::optional<float> range_to;
    // set at runtime when automation objects get set up
    std::optional<std::int32_t> effective_program_object_selector;
    // old name, don't break callers
    std::optional<std::int32_t> effective_program_send_fx_is_in_insert_chain;
};

enum class K2EffectKind : std::uint32_t {
    filter,
    compressor,
    limiter,
    gainer,
    inverter,
    dyx,
    surround_panner,
    lo_fi,
    distortion,
    skreamer,
    rotator,
    twang,
    cabinet,
    shaper,
    stereo_spread,
    chorus,
    flanger,
    phaser,
    reverb,
    delay,
    send_levels,
    irc,
};
enum class K2CompressorModel : std::uint32_t {
    classic = 0,
    enhanced = 1,
    pro = 2
};
enum class K2DistortionType : std::uint32_t { tube = 0, transistor = 1 };
enum class K2FilterType : std::uint32_t {
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
    eq_1_band = 0x5f,
    eq_2_band = 0x60,
    eq_3_band = 0x61,
};
enum class K2SurroundVolumeAlgorithm : std::uint32_t {
    constant_power = 0,
    sinusoid = 1,
    logarithmic = 2,
};
struct K2SurroundChannel {
    std::optional<float> x;
    std::optional<float> y;
    std::optional<std::uint8_t> flags;
    std::optional<std::uint8_t> role;
    std::optional<std::uint8_t> effective_flags_or_role;
};

struct K2EffectSemantic {
    std::int32_t program_ordinal{ -1 };
    std::int32_t group_ordinal{ -1 };
    // ProgramInsertFX is bank 1, ProgramSendFX is 0, anything else is empty
    std::optional<std::int32_t> program_object_selector;
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> serialized_index;
    std::optional<K2EffectKind> kind;
    std::optional<std::uint32_t> internal_type;
    std::optional<std::uint16_t> parsed_version;
    std::optional<std::uint16_t> subtype_version;
    std::optional<bool> routers_open;
    std::optional<std::int32_t> class_id;
    std::optional<bool> bypass;
    std::optional<float> output_level;
    std::optional<float> dry_output_level;
    std::optional<std::int32_t> send_fx_output_partition;
    std::optional<bool> inverter_phase;
    std::optional<bool> inverter_panorama;
    std::optional<float> gain;
    std::optional<float> shaper_shape;
    std::optional<std::int32_t> shaper_type;
    std::optional<float> stereo_spread;
    std::optional<float> stereo_pan;
    std::optional<bool> stereo_pseudo;
    std::optional<float> dyx_morph;
    std::optional<float> dyx_dry;
    std::optional<std::int32_t> dyx_morph_map_index;
    std::optional<bool> dyx_linear_phase;
    std::optional<K2CompressorModel> compressor_model;
    std::optional<float> compressor_threshold;
    std::optional<float> compressor_ratio;
    std::optional<float> compressor_attack;
    std::optional<float> compressor_release;
    std::optional<bool> compressor_stereo_link;
    std::optional<float> limiter_input_gain;
    std::optional<float> limiter_release_time;
    std::optional<float> lo_fi_bits;
    std::optional<float> lo_fi_down_sample;
    std::optional<bool> lo_fi_sample_hold_integer;
    std::optional<float> lo_fi_noise_level;
    std::optional<float> lo_fi_noise_color;
    std::optional<K2DistortionType> distortion_type;
    std::optional<float> distortion_drive;
    std::optional<float> distortion_damping;
    std::optional<float> skreamer_tone;
    std::optional<float> skreamer_drive;
    std::optional<float> skreamer_bass;
    std::optional<float> skreamer_bright;
    std::optional<float> skreamer_mix;
    std::optional<float> rotator_speed;
    std::optional<float> rotator_balance;
    std::optional<float> rotator_acceleration_high;
    std::optional<float> rotator_acceleration_low;
    std::optional<float> rotator_distance;
    std::optional<float> rotator_mix;
    std::optional<float> twang_volume;
    std::optional<float> twang_treble;
    std::optional<float> twang_mid;
    std::optional<float> twang_bass;
    std::optional<bool> twang_bright;
    std::optional<bool> twang_serialized_polyphonic;
    std::optional<bool> twang_effective_monophonic;
    std::optional<float> cabinet_size;
    std::optional<float> cabinet_air;
    std::optional<float> cabinet_treble;
    std::optional<float> cabinet_bass;
    std::optional<std::int32_t> cabinet_type;
    std::optional<float> chorus_depth;
    std::optional<float> chorus_speed;
    std::optional<float> chorus_phase;
    std::optional<float> chorus_note_value_speed;
    std::optional<bool> chorus_note_value_speed_enabled;
    std::optional<float> flanger_depth;
    std::optional<float> flanger_feedback;
    std::optional<float> flanger_speed;
    std::optional<float> flanger_phase;
    std::optional<float> flanger_color;
    std::optional<float> flanger_note_value_speed;
    std::optional<bool> flanger_note_value_speed_enabled;
    std::optional<float> phaser_depth;
    std::optional<float> phaser_feedback;
    std::optional<float> phaser_speed;
    std::optional<float> phaser_phase;
    std::optional<float> phaser_note_value_speed;
    std::optional<bool> phaser_note_value_speed_enabled;
    std::optional<K2FilterType> filter_type;
    std::optional<float> filter_cutoff;
    std::optional<float> filter_resonance;
    std::array<std::optional<float>, 3> filter_eq_frequency;
    std::array<std::optional<float>, 3> filter_eq_bandwidth;
    std::array<std::optional<float>, 3> filter_eq_gain;
    std::optional<float> filter_shift_b;
    std::optional<float> filter_shift_c;
    std::optional<float> filter_resonance_b;
    std::optional<float> filter_resonance_c;
    std::array<std::optional<float>, 3> filter_vowel_type;
    std::array<std::optional<float>, 3> filter_vowel_bypass;
    std::optional<float> filter_gain;
    std::optional<float> reverb_pre_delay;
    std::optional<float> reverb_room_size;
    std::optional<float> reverb_stereo;
    std::optional<float> reverb_color;
    std::optional<float> reverb_filter;
    std::optional<float> delay_time;
    std::optional<float> delay_feedback;
    std::optional<float> delay_panning;
    std::optional<float> delay_damping;
    std::optional<float> delay_note_value_time;
    std::optional<bool> delay_note_value_time_enabled;
    std::array<std::optional<float>, 8> send_levels;
    std::array<K2SurroundChannel, 16> surround_speakers;
    std::array<K2SurroundChannel, 16> surround_effective_speakers;
    std::array<K2SurroundChannel, 16> surround_sources;
    std::optional<std::int32_t> surround_serialized_speaker_count;
    std::optional<std::int32_t> surround_effective_speaker_count;
    std::optional<std::int32_t> surround_source_count;
    std::optional<float> surround_lfe_crossover_frequency;
    std::optional<float> surround_lfe_volume;
    std::optional<float> surround_size;
    std::optional<float> surround_divergence;
    std::optional<float> surround_air_amount;
    std::optional<float> surround_delay_amount;
    std::optional<float> surround_doppler_amount;
    std::optional<K2SurroundVolumeAlgorithm> surround_volume_algorithm;
    std::optional<bool> surround_use_speaker_delays;
    std::optional<bool> surround_use_air_absorption;
    std::optional<bool> surround_use_doppler_effect;
    std::optional<float> surround_offset_distance;
    std::optional<float> surround_offset_azimuth;
    std::optional<float> surround_offset_x;
    std::optional<float> surround_offset_y;
    std::optional<std::int32_t> surround_preset_speaker_setup;
    std::optional<std::string> irc_serialized_ir_file;
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
    std::optional<bool> irc_serialized_bypass_latency_compensation;
    std::optional<bool> irc_effective_bypass_latency_compensation;
    std::optional<bool> irc_envelope_active;
    std::array<std::optional<float>, 8> irc_envelope_times;
    std::array<std::optional<float>, 8> irc_envelope_levels;
};

struct K2BankSlotSemantic {
    std::optional<std::int16_t> midi_channel;
    std::optional<bool> solo;
    std::optional<bool> mute;
    std::array<std::optional<float>, 4> auxiliary_send_levels;
    std::optional<std::int32_t> reorder_index;
};

struct K2BankSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<bool> load_purged;
    std::optional<bool> show_multi_script;
    std::optional<float> serialized_master_volume;
    std::optional<float> serialized_master_tune;
    std::array<K2BankSlotSemantic, 64> slots;
    std::optional<std::string> original_subdirectory;
    std::optional<std::int32_t> original_save_mode;
    std::optional<bool> original_absolute_paths;
    std::optional<bool> original_compressed_samples;
};

struct K2ProgramContainerSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::int32_t> serialized_output;
    std::optional<bool> load_purged;
    std::optional<bool> table_open;
    std::optional<bool> small_rack_unit;
    std::optional<bool> auxiliary_sends_visible;
    std::optional<std::int16_t> current_program_change_number;
    std::optional<std::uint32_t> serialized_output_mask;
    std::optional<float> volume;
    std::optional<float> pan;
    std::optional<std::string> original_subdirectory;
    std::optional<std::int32_t> original_save_mode;
    std::optional<bool> original_absolute_paths;
    std::optional<bool> original_compressed_samples;
    std::optional<bool> has_been_saved;
};

struct K2OutputConfigurationSemantic {
    std::vector<K1TagAttribute> attributes;
    std::array<std::optional<std::int32_t>, 128> physical_output_mapping;
};

struct K2OutputPartitionSemantic {
    std::vector<K1TagAttribute> attributes;
    std::optional<std::string> name;
    std::optional<std::int16_t> channel_count;
    std::optional<std::int16_t> auxiliary_index;
    std::optional<float> volume;
    std::optional<std::uint16_t> parsed_version;
};

// standalone monoliths start at zero, pre-NIS K4.2 sample monoliths have a
// 0xde byte envelope in front
struct MonolithEntry {
    std::uint16_t serialized_size{};
    std::uint32_t stored_offset{};
    std::uint32_t resolved_offset{};
    // a physical-EOF offset stays intact even though it has no payload bytes
    bool points_to_eof{};
    std::uint16_t type{};
    std::u16string name;
    struct PayloadHeader {
        enum class Kind { sample, patch, generic };
        Kind kind{};
        std::uint32_t offset{};
        std::uint32_t magic{};
        std::uint16_t version{};
        std::uint32_t writer_argument{};
        std::uint32_t transform_mode{};
        std::optional<std::uint32_t> item_attributes;
        std::optional<std::uint8_t> reserved_marker;
        std::optional<std::uint32_t> reserved_trailer;
        std::uint64_t source_size{};
        std::optional<std::uint32_t> legacy_source_size_metadata;
        std::optional<std::uint32_t> sample_trailer;
        std::size_t header_size{};
        std::size_t end_offset{};
    };
    std::optional<PayloadHeader> payload;
};

struct MonolithTable {
    static constexpr std::uint32_t table_magic = 0x5e70ac54U;
    static constexpr std::size_t table_header_size = 0x16;
    std::uint32_t offset{};
    bool byte_swapped{};
    std::uint16_t version{};
    std::uint32_t writer_argument{};
    std::uint32_t transform_mode{};
    std::uint32_t entry_count{};
    std::uint32_t table_identifier{};
    std::vector<MonolithEntry> entries;
    std::size_t end_offset{};
};

// NKR/NKX folder tree, the item payloads get parsed separately
struct MonolithContainer {
    std::size_t root_offset{};
    std::vector<MonolithTable> tables;
};

struct NkcNode {
    std::uint32_t parent_table_identifier{};
    std::uint32_t entry_attributes{};
    std::uint16_t entry_type{};
    std::uint32_t child_table_attributes{};
    std::u16string name;
    std::vector<NkcNode> children;
};

struct NkcCache {
    static constexpr std::uint32_t magic = 0x3fe1107aU;
    static constexpr std::uint16_t version_0110 = 0x0110U;
    bool byte_swapped{};
    std::uint16_t version{};
    NkcNode root;
    std::size_t end_offset{};
};

struct NcwInfo {
    static constexpr std::uint32_t magic = 0xd69ea801U;
    static constexpr std::size_t header_size = 0x78;
    bool byte_swapped{};
    std::uint32_t header_version{};
    std::uint16_t channel_count{};
    std::uint16_t bits_per_sample{};
    std::uint32_t sample_rate{};
    std::uint32_t sample_count{};
    std::uint32_t block_index_offset{};
    // from the start of the file, the other blocks are relative to
    // block_offsets[0]
    std::uint32_t first_block_data_offset{};
    std::int32_t terminal_block_offset{};
    bool variant_8_flag{};
    std::uint32_t codec_variant{};
    std::size_t file_offset{};
    std::size_t block_data_base{};
    std::vector<std::uint32_t> block_offsets;
    struct BlockSpan {
        std::size_t offset{};
        std::size_t end_offset{};
    };
    std::vector<BlockSpan> blocks;
};

// each ADPCM block produces 512 signed samples before scaling and optional
// stereo reconstruction
struct NcwBlockHeader {
    static constexpr std::uint32_t magic = 0x3e9a0c16U;
    static constexpr std::size_t serialized_size = 0x10;
    std::size_t offset{};
    bool byte_swapped{};
    std::int32_t initial_value{};
    std::int16_t residual_bit_width{};
    std::uint16_t flags{};
    std::size_t payload_offset{};
    std::size_t payload_size{};
    std::size_t end_offset{};
};

enum class NicntValueKind : std::uint8_t {
    string,
    number,
};

struct NicntProductSpecificValue {
    std::string name;
    NicntValueKind kind{ NicntValueKind::string };
    std::string string_value;
    std::int32_t number_value{};
};

struct NicntProductFamily {
    std::string name;
    std::optional<std::uint32_t> version;
};

enum class NicntImageRefKind : std::uint8_t {
    text,
    base64_data,
    product_family,
};

struct NicntImageRef {
    NicntImageRefKind kind{ NicntImageRefKind::text };
    std::string text;
    std::optional<NicntProductFamily> product_family;
};

// inverted ranges get cleared on validation. keep the text, NI versions can
// have prerelease/build parts
struct NicntVersionSpecifier {
    std::optional<std::string> min_version;
    std::optional<std::string> max_version;
};

struct NicntAppRelevance {
    NicntVersionSpecifier versions;
    std::string application;
    std::optional<std::uint32_t> auth_app_id;
    bool native_content{};
};

struct NicntProductRelevance {
    NicntVersionSpecifier versions;
    std::vector<NicntAppRelevance> applications;
};

struct NicntAppDependency {
    NicntVersionSpecifier versions;
    std::string application;
    std::optional<std::uint32_t> auth_app_id;
};

struct NicntProductDependencies {
    NicntVersionSpecifier versions;
    std::vector<NicntAppDependency> applications;
};

struct NicntTargetInfo {
    std::optional<std::string> target;
    // application mask and platform enum are separate selectors
    std::uint32_t target_mask{ 0xfff };
    NicntVersionSpecifier versions;
    std::optional<std::string> platform;
    std::uint32_t platform_value{};
    std::optional<std::string> min_os_version_win;
    std::optional<std::string> max_os_version_win;
    std::optional<std::string> min_os_version_mac;
    std::optional<std::string> max_os_version_mac;
    std::optional<std::string> min_os_version_native_os;
    std::optional<std::string> max_os_version_native_os;
    std::optional<std::string> min_os_version_linux;
    std::optional<std::string> max_os_version_linux;
    std::optional<std::string> legacy_os_min;
    std::optional<std::string> legacy_os_max;
};

struct NicntTargetedStringValue {
    NicntTargetInfo target_info;
    std::string value;
};

struct NicntTargetedU32Value {
    NicntTargetInfo target_info;
    std::uint32_t value{};
};

enum class NicntAuthSystem : std::int32_t {
    unknown = -1,
    none = 0,
    ras0 = 1,
    ras1 = 2,
    ras1_5 = 3,
    ras2 = 4,
    ras3 = 5,
};

struct NicntTargetedAuthSystemValue {
    NicntTargetInfo target_info;
    NicntAuthSystem value{ NicntAuthSystem::none };
    std::string source_text;
};

struct NicntNksEnabled {
    NicntVersionSpecifier versions;
    bool enabled{};
};

enum class NicntFactoryLibraryDirectoryMode : std::uint32_t {
    // every spelling except "registry" maps to zero; its further meaning is
    // unknown
    default_mode = 0,
    registry = 1,
};

struct NicntFactoryLibrary {
    NicntVersionSpecifier versions;
    bool structured{};
    std::optional<std::string> upid;
    bool binary_generates_random_upid{};
    std::string name;
    std::string directory;
    NicntFactoryLibraryDirectoryMode directory_mode{
        NicntFactoryLibraryDirectoryMode::default_mode
    };
    std::vector<NicntProductRelevance> relevance;
    std::vector<NicntProductDependencies> dependencies;
};

struct NicntSupersessionRule {
    NicntVersionSpecifier product_versions;
    std::string upid;
    NicntVersionSpecifier superseded_versions;
};

struct NicntProductFlavour {
    std::string name;
    std::int32_t flavour_value{ -1 };
    bool used_upgrade_compatibility{};
    std::string snpid;
    std::vector<std::uint32_t> snpid_values;
    std::string serial_source_text;
    std::string serial;
    NicntAuthSystem serial_auth_system{ NicntAuthSystem::unknown };
    std::optional<std::uint32_t> serial_snpid;
    std::vector<NicntTargetedAuthSystemValue> auth_systems;
    std::vector<NicntFactoryLibrary> factory_libraries;
    std::vector<NicntSupersessionRule> supersessions;
};

enum class NicntProductType : std::uint32_t {
    unknown = 0,
    app = 1,
    utility = 2,
    content = 4,
    plugin = 8,
    driver = 16,
    bundle = 32,
};

struct NicntProductFilter {
    std::uint32_t product_type_mask{};
    std::vector<std::string> snpids;
};

struct NicntPluginId {
    bool fx{};
    std::uint32_t value{};
};

struct NicntVst3Id {
    bool fx{};
    std::array<std::byte, 16> value{};
};

struct NicntBundleMemberDeclaration {
    std::string serial;
    std::optional<std::string> added_at;
    // "%Y-%m-%dT%H:%M:%S" in local time, stored as system clock ms
    std::optional<std::int64_t> added_at_milliseconds;
};

struct NicntProductInfo {
    std::uint32_t version{};
    std::string hash;
    // checked against the running SC engine version before deserializing
    std::optional<std::string> min_sc_version;
    std::optional<std::string> max_sc_version;
    std::string upid;
    std::string name;
    std::string type;
    NicntProductType product_type{ NicntProductType::unknown };
    std::string internal_name;
    std::string ps;
    std::optional<NicntProductFamily> product_family;
    std::string company;
    std::string vendor;
    std::string website;
    std::string shop_link;
    std::optional<std::int32_t> value;
    std::optional<std::int32_t> bundle_value;
    std::string scan_mode;
    std::vector<NicntTargetedStringValue> bin_names;
    std::string host_mode;
    std::optional<std::uint32_t> auth_app_id;
    // one ID per fx=false/true at most, the first one that parses wins
    std::vector<NicntPluginId> plugin_ids;
    std::vector<NicntVst3Id> vst3_ids;
    // direct product children, separate from Flavour libraries
    std::vector<NicntFactoryLibrary> factory_libraries;
    std::string file_extension;
    std::optional<NicntImageRef> icon;
    std::optional<NicntImageRef> header;
    std::optional<NicntImageRef> logo;
    std::string snpid;
    // SNPIDs use three-character chunks; when none exist, validation may add
    // the PID embedded in the serial
    std::vector<std::uint32_t> snpid_values;
    std::string serial_source_text;
    std::string serial;
    NicntAuthSystem serial_auth_system{ NicntAuthSystem::unknown };
    std::optional<std::uint32_t> serial_snpid;
    std::vector<NicntTargetedAuthSystemValue> auth_systems;
    std::vector<NicntTargetedStringValue> reg_keys;
    std::vector<NicntTargetedU32Value> visibility;
    // root Members/Member entries drive the bundle Type fallback; the second
    // vector also includes nested Members/Bundle declarations
    std::vector<NicntBundleMemberDeclaration> bundle_members;
    std::vector<NicntBundleMemberDeclaration> all_bundle_member_declarations;
    std::optional<NicntNksEnabled> nks_enabled;
    std::string powered_by;
    std::string engine;
    std::string engine_version;
    std::vector<NicntProductFlavour> flavours;
    std::vector<NicntProductRelevance> relevance;
    std::vector<NicntProductDependencies> dependencies;
    std::vector<NicntProductSpecificValue> product_specific_values;
};

struct NicntContentEntry {
    std::uint64_t relative_offset{};
    std::uint64_t size{};
    std::uint32_t id{};
    std::uint32_t revision{};
    std::u16string name;
    std::size_t data_offset{};
    std::size_t end_offset{};
};

struct NicntContentIndexEntry {
    std::uint32_t record_index{};
    std::uint32_t id{};
};

enum class NicntContentSelectorKind : std::uint8_t { name, id };

struct NicntContentSelector {
    NicntContentSelectorKind kind{ NicntContentSelectorKind::name };
    std::string name;
    std::uint32_t id{};
};

struct NicntContentPartSpan {
    std::size_t part_index{};
    std::size_t part_offset{};
    std::span<const std::byte> bytes;
};

struct NicntFileContentRange {
    std::uint32_t part_index{};
    std::uint64_t primary_extent_size{};
    std::uint64_t part_relative_offset{};
    bool has_mapped_part{};
    std::uint32_t mapped_part_index{};
    std::uint64_t mapped_part_relative_offset{};
    std::uint64_t logical_content_offset{};
    std::uint64_t content_size{};
};

struct NicntContentToc {
    std::size_t offset{};
    std::uint32_t version{};
    std::size_t record_size{};
    std::uint32_t entry_count{};
    std::uint32_t flags{};
    std::uint64_t total_content_size{};
    std::size_t index_offset{};
    std::vector<NicntContentIndexEntry> id_index;
    std::size_t records_offset{};
    std::size_t sentinel_offset{};
    std::size_t content_offset{};
    std::size_t end_offset{};
    std::vector<NicntContentEntry> entries;
};

inline constexpr std::uint32_t nicnt_any_content_revision = 0xffffffffU;

struct NicntRejectedProduct {
    std::size_t source_index{};
    std::string error;
};

// we read these hints from an NI container's reserved data or from the product
// info db XML when looking up legacy libraries
struct NicntProductHints {
    std::string version;
    std::string spec;
    std::vector<NicntProductInfo> products;
    std::vector<NicntRejectedProduct> rejected_products;
};

// product-info monolith fields with known layouts or XML consumers;
// shared file-container TOCs are parsed separately
struct NicntContainer {
    static constexpr std::size_t metadata_header_size = 0x100;
    static constexpr std::size_t reserved_data_offset = 0x100;
    std::uint32_t metadata_header_kind{};
    std::string product_version;
    std::uint32_t reserved_data_size{};
    std::uint32_t metadata_payload_skip{};
    std::size_t product_hints_xml_size{};
    std::string product_hints_version;
    std::string product_hints_spec;
    std::vector<NicntProductInfo> products;
    // failed products are skipped individually; keep their errors here
    std::vector<NicntRejectedProduct> rejected_products;
    // every TOC in order
    std::vector<NicntContentToc> content_tocs;
    std::optional<NicntContentToc> content_toc;
};

// old K2 names, it's the same monolith format
using K2MonolithEntry = MonolithEntry;
using K2MonolithTable = MonolithTable;

struct K2MonolithInfo {
    static constexpr std::uint32_t patch_link_magic = 0x4916e63cU;
    static constexpr std::size_t patch_link_size = 0x1b;
    std::vector<K2MonolithTable> tables;
    std::size_t selected_table_index{};
    std::size_t selected_entry_index{};
    std::uint16_t patch_link_version{};
    std::array<std::byte, patch_link_size> patch_link_bytes{};
    std::uint32_t embedded_patch_offset{};
};

struct K2PatchData {
    using Attribute = K1TagAttribute;
    using Element = K1TagElement;
    K2PatchHeader header;
    std::optional<K2MonolithInfo> monolith;
    std::vector<std::byte> decompressed;
    std::vector<Attribute> xml_declaration;
    std::vector<Element> elements;
    std::vector<K2ProgramSemantic> programs;
    std::vector<K2GroupSemantic> groups;
    std::vector<K2ZoneSemantic> zones;
    std::vector<K2VoiceLimitSemantic> voice_limits;
    std::vector<K2StartCriteriaSemantic> start_criteria;
    std::vector<K2SourceModeSemantic> source_modes;
    std::vector<K2SliceSemantic> slices;
    std::vector<K2ZleSemantic> zles;
    std::vector<K2InternalModSemantic> internal_modulators;
    std::vector<K2ExternalModSemantic> external_modulators;
    std::vector<K2ScriptSemantic> scripts;
    std::vector<K2MorphGroupSemantic> morph_groups;
    std::vector<K2MorphMapSemantic> morph_maps;
    std::vector<K2AutomationSemantic> automation;
    std::vector<K2AutomationSemantic> effective_automation;
    std::vector<K2AutomationSemantic> purged_automation;
    std::vector<K2EffectSemantic> effects;
    std::vector<K2BankSemantic> banks;
    std::vector<K2ProgramContainerSemantic> containers;
    std::vector<K2OutputConfigurationSemantic> output_configurations;
    std::vector<K2OutputPartitionSemantic> output_partitions;
};

struct K1PatchHeader {
    static constexpr std::size_t serialized_size = 0x24;
    std::array<std::byte, serialized_size> normalized_bytes{};
    bool byte_swapped{};
    std::uint32_t magic{};
    std::uint16_t field_04{};
    std::uint16_t field_06{};
    std::uint32_t format_version{};
    // words at 0x0c, 0x14, 0x18 and 0x1c; their meanings are still unknown
    std::array<std::uint32_t, 4> confirmed_u32_fields{};
    std::array<std::byte, 4> unswapped_tail{};
};

struct K1PatchData {
    K1PatchHeader header;
    std::vector<std::byte> payload;
    std::vector<K1TagAttribute> xml_declaration;
    std::vector<K1TagElement> elements;
    std::vector<K1ProgramSemantic> programs;
    std::vector<K1GroupSemantic> groups;
    std::vector<K1ZoneSemantic> zones;
    std::vector<K1PresetSemantic> presets;
    std::vector<K1BankSemantic> banks;
    std::vector<K1BatteryProgramSemantic> battery_programs;
};

struct Document {
    Format format{ Format::unknown };
    PatchGeneration generation{ PatchGeneration::unknown };
    std::uint64_t declared_size{};
    std::uint64_t actual_size{};
    std::string identity_hex;
    Metadata metadata;
    std::optional<RepositoryRoot> repository_root;
    std::vector<PresetInfo> presets;
    std::vector<SoundInfoItem> sound_info_items;
    std::vector<AudioSampleItem> audio_sample_items;
    std::vector<ExternalFileReferenceItem> external_file_references;
    std::vector<InternalResourceReferenceItem> internal_resource_references;
    std::vector<PictureItem> picture_items;
    std::vector<BinaryChunkItem> binary_chunk_items;
    std::vector<ResourcesItem> resources_items;
    std::vector<GenericItem> generic_items;
    std::vector<ModuleItem> module_items;
    std::vector<ModuleBankItem> module_bank_items;
    std::vector<BankItem> bank_items;
    std::vector<AuthorizationItem> authorization_items;
    std::vector<BaseItem> base_items;
    std::vector<BankContainerItem> bank_container_items;
    std::vector<PresetContainerItem> preset_container_items;
    std::vector<AutomationParameters> automation_parameters;
    std::vector<ControllerAssignments> controller_assignments;
    std::vector<BNISoundHeader> bnisound_headers;
    std::vector<PresetChunkItem> preset_chunks;
    std::vector<ModernPatchPayload> modern_patches;
    std::optional<K42PatchData> k42_patch_data;
    std::optional<K2PatchData> k2_patch_data;
    std::optional<K1PatchData> k1_patch_data;
    std::optional<MonolithContainer> resource_monolith;
    std::vector<Frame> frames;
    std::vector<ProtectedItem> protected_items;
    std::vector<Error> errors;

    [[nodiscard]] bool structurally_valid() const noexcept {
        return format != Format::unknown && errors.empty();
    }
};

[[nodiscard]] Document parse(std::span<const std::byte> bytes,
        std::span<const std::byte> encryption_key = {});
[[nodiscard]] Document parse_file(const std::filesystem::path &path);
[[nodiscard]] PatchGeneration detect_patch_generation(
        std::span<const std::byte> bytes) noexcept;
[[nodiscard]] const char *format_name(Format format) noexcept;
[[nodiscard]] const char *generation_name(PatchGeneration generation) noexcept;
[[nodiscard]] const char *protected_item_kind_name(
        ProtectedItemKind kind) noexcept;
[[nodiscard]] std::array<std::byte, 16> calculate_k42_header_md5(
        std::span<const std::byte> normalized_header);
[[nodiscard]] std::uint32_t kontakt_crc32(
        std::span<const std::byte> bytes) noexcept;
[[nodiscard]] K42PatchData parse_k42_patch_data(
        std::span<const std::byte> bytes,
        std::optional<std::uint32_t> current_app_version = std::nullopt,
        std::span<const std::byte> encryption_key = {});
[[nodiscard]] std::string snpid_from_product_id(std::uint32_t product_id);
[[nodiscard]] std::uint32_t k42_product_id(std::span<const std::byte> bytes);
[[nodiscard]] bool k42_legacy_otp_encrypted(std::span<const std::byte> bytes);
[[nodiscard]] K2PatchData parse_k2_patch_data(std::span<const std::byte> bytes,
        std::optional<std::uint32_t> current_app_version = std::nullopt,
        std::span<const std::byte> encryption_key = {});
[[nodiscard]] std::uint32_t k2_product_id(std::span<const std::byte> bytes);
[[nodiscard]] bool k2_legacy_otp_encrypted(std::span<const std::byte> bytes);
[[nodiscard]] std::uint32_t calculate_k2_header_checksum(
        std::span<const std::byte> normalized_header);
void parse_k2_tag_stream(K2PatchData &data);
[[nodiscard]] K1PatchData parse_k1_patch_data(std::span<const std::byte> bytes);

// runs before FastLZ, the key is 64 KiB and indexed by the low 16 bits. it's a
// xor so it goes both ways
void apply_encryption_item_xor(
        std::span<std::byte> data, std::span<const std::byte> encryption_key);

// loads the 64 KiB key blob from disk, fails if the size or checksum is off.
// we NEVER build these bytes into libnki
[[nodiscard]] std::vector<std::byte> load_encryption_private_key(
        const std::filesystem::path &path);

// empty unless LIBNKI_BUNDLED_KEY_PATH is set, local use only, don't ship that
[[nodiscard]] std::span<const std::byte>
bundled_encryption_private_key() noexcept;
[[nodiscard]] std::string sha256_hex(std::span<const std::byte> data);
[[nodiscard]] const char *expected_encryption_private_key_sha256() noexcept;

// derives the 64 KiB XOR key from the product's HU/JDX values;
// callers must supply the product hints explicitly
[[nodiscard]] std::vector<std::byte> derive_product_encryption_key(
        std::span<const std::byte> private_key, std::string_view snpid,
        const std::filesystem::path &product_hints_path);
[[nodiscard]] std::vector<std::byte> derive_product_encryption_key(
        std::span<const std::byte> private_key, std::uint32_t product_id,
        const std::filesystem::path &product_hints_path);
[[nodiscard]] std::vector<std::byte> derive_product_encryption_key(
        std::span<const std::byte> private_key, const NicntContainer &nicnt,
        std::string_view snpid);

struct LocalLibraryInfo {
    std::filesystem::path root;
    NicntContainer metadata;
};
// walks up at most five folders looking for NICNT metadata
[[nodiscard]] std::vector<LocalLibraryInfo> discover_local_libraries(
        const std::filesystem::path &instrument_path);
[[nodiscard]] std::vector<std::byte> derive_local_product_encryption_key(
        std::span<const std::byte> private_key,
        std::span<const LocalLibraryInfo> libraries, std::string_view snpid);
[[nodiscard]] std::vector<std::byte> derive_local_product_encryption_key(
        std::span<const std::byte> private_key,
        std::span<const LocalLibraryInfo> libraries, std::uint32_t product_id);

// optional XOR precedes FastLZ; decoded size must match the subtree header
[[nodiscard]] std::vector<std::byte> decode_protected_item(
        std::span<const std::byte> file_bytes, const ProtectedItem &item,
        std::span<const std::byte> encryption_key = {});

[[nodiscard]] Document decode_and_parse_protected_item(
        std::span<const std::byte> file_bytes, const ProtectedItem &item,
        std::span<const std::byte> encryption_key = {});

// siblings have a U16 type and U32 payload size; skips are relative to the
// byte immediately after that header
[[nodiscard]] std::vector<ChunkHeader> scan_chunk_sequence(
        std::span<const std::byte> bytes, std::size_t offset = 0);

// v3 0x4b file table
[[nodiscard]] FileTable parse_file_table_v3(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] FileTable parse_file_table_v2(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] FileTable parse_file_table_pre_k51(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] SerializableHeader parse_serializable_header(
        std::span<const std::byte> bytes, std::size_t offset,
        bool expected_structured, std::uint16_t maximum_version);
[[nodiscard]] PresetImplPrefix parse_preset_impl_prefix(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] GroupArrayHeader parse_snapshot_group_array_header(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] GroupSnapshotPrefix parse_group_snapshot_prefix(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] ParameterArrayPrefix parse_parameter_array_prefix(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled = false);
[[nodiscard]] SourceModePrefix parse_source_mode_prefix(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] SourceModePayload parse_source_mode(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] ParFxPayload parse_par_fx(std::span<const std::byte> bytes,
        const ChunkHeader &chunk,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] ParameterArrayPayload parse_parameter_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] GroupSnapshotPayload parse_group_snapshot(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] InsertBusPayload parse_insert_bus(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] SnapshotPayload parse_snapshot(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] SnapshotMetadataPayload parse_snapshot_metadata(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] SnapshotPresetPayload parse_snapshot_preset_impl(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] PresetPayload parse_preset(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {},
        std::optional<std::uint32_t> creator_version_packed = std::nullopt);
[[nodiscard]] InternalModulatorPayload parse_internal_modulator_array_entry(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {},
        std::optional<std::uint32_t> creator_version_packed = std::nullopt);
[[nodiscard]] ExternalModulatorPayload parse_external_modulator_array_entry(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::optional<std::uint32_t> creator_version_packed = std::nullopt);
[[nodiscard]] VoiceLimitPayload parse_voice_limit(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] VoiceGroupChunkPayload parse_voice_group_chunk(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] ParScriptPayload parse_par_script(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] ParScriptPayload parse_par_script_payload(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] QuickBrowseDataPayload parse_quick_browse_data(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] GroupPublicPayload parse_group_public_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t group_version);
[[nodiscard]] StartCriteriaPayload parse_start_criteria(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] GroupDynamicsPayload parse_group_dynamics(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] GroupChildrenPayload parse_group_children(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t group_version, bool has_group_dynamics,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] AutomationObjectPayload parse_automation_object(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] GroupPrivatePayload parse_group_private_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t group_version, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] GroupPayload parse_group(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] ProgramGroupChunkPayload parse_program_group_chunk(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] SampleSettingsPayload parse_sample_settings(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t zone_version);
[[nodiscard]] ZonePublicPayload parse_zone_public_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t zone_version);
[[nodiscard]] ZoneLevelEnvPayload parse_zone_level_env(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] ZonePrivatePayload parse_zone_private_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t zone_version);
[[nodiscard]] LoopPayload parse_loop(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] SamplePayload parse_sample(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] SampleSlicesPayload parse_sample_slices(
        std::span<const std::byte> bytes, std::size_t offset,
        bool stores_float_positions);
[[nodiscard]] ZoneChildrenPayload parse_zone_children(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t zone_version, bool has_sample_payload);
[[nodiscard]] ZonePayload parse_zone(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] ZoneArrayPayload parse_zone_array(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] GroupCompletePayload parse_group_complete(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] ProgramZoneChunkPayload parse_program_zone_chunk(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] ProgramChildrenPayload parse_program_children(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t program_version, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] NISoundDataPayload parse_nisound_data(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] ProgramPublicPayload parse_program_public_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t program_version);
[[nodiscard]] DyxMorphGroupPayload parse_dyx_morph_group(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] DyxMorphMapPayload parse_dyx_morph_map(
        std::span<const std::byte> bytes, std::size_t offset);
[[nodiscard]] ProgramPrivatePayload parse_program_private_payload(
        std::span<const std::byte> bytes, std::size_t offset,
        std::uint16_t program_version);
[[nodiscard]] ProgramPayload parse_program(std::span<const std::byte> bytes,
        std::size_t offset, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] SaveSettingsPayload parse_save_settings(
        std::span<const std::byte> bytes, const ChunkHeader &chunk);
[[nodiscard]] ProgramContainerPayload parse_program_container(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] BankPayload parse_bank(std::span<const std::byte> bytes,
        const ChunkHeader &chunk, bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] BankSlotListPayload parse_bank_slot_list(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        bool context_ids_enabled = false,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] OutputConfigurationPayload parse_output_configuration(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::span<const ParFxTypeMapping> runtime_type_mappings = {});
[[nodiscard]] BankMidiRoutingPayload parse_bank_midi_routing(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::uint16_t bank_version);
[[nodiscard]] BankAudioRoutingPayload parse_bank_audio_routing(
        std::span<const std::byte> bytes, const ChunkHeader &chunk,
        std::uint16_t bank_version);
[[nodiscard]] MonolithContainer parse_monolith_container(
        std::span<const std::byte> bytes, std::size_t root_offset = 0);
// everything but the last component has to be a folder, ASCII ignores case
// but UTF-8 multibyte has to match exactly
[[nodiscard]] const MonolithEntry *find_monolith_entry(
        const MonolithContainer &container,
        std::span<const std::string_view> utf8_components);
[[nodiscard]] NkcCache parse_nkc_cache(std::span<const std::byte> bytes);
[[nodiscard]] NcwInfo parse_ncw_info(std::span<const std::byte> bytes,
        std::size_t file_offset = 0, std::size_t logical_size = 0);
[[nodiscard]] NcwBlockHeader parse_ncw_block_header(
        std::span<const std::byte> bytes, std::size_t block_offset,
        bool byte_swapped = false);
[[nodiscard]] std::array<std::int32_t, 512> decode_ncw_block(
        std::span<const std::byte> bytes, const NcwBlockHeader &header);
[[nodiscard]] std::array<float, 512> decode_ncw_block_f32(
        std::span<const std::byte> bytes, const NcwBlockHeader &header,
        float integer_scale);
// interleaves the complete block after mid/side reconstruction; all 512 frames
// remain available, including padding beyond physical sample EOF
[[nodiscard]] std::vector<float> decode_ncw_cache_block_f32(
        std::span<const std::byte> bytes, const NcwInfo &info,
        std::size_t block_index);
[[nodiscard]] std::vector<std::int32_t> decode_ncw_samples_i32(
        std::span<const std::byte> bytes, const NcwInfo &info);
[[nodiscard]] std::vector<float> decode_ncw_samples_f32(
        std::span<const std::byte> bytes, const NcwInfo &info,
        std::size_t maximum_frames = std::numeric_limits<std::size_t>::max());
[[nodiscard]] NicntContainer parse_nicnt(std::span<const std::byte> bytes);
[[nodiscard]] NicntProductHints parse_nicnt_product_hints(std::string_view xml);
// skip any 0x100 byte MTD headers, the FC TOC is right after them or at 0
[[nodiscard]] std::optional<NicntContentToc> parse_file_container_toc(
        std::span<const std::byte> bytes);
[[nodiscard]] std::vector<NicntContentToc> parse_file_container_tocs(
        std::span<const std::byte> bytes);
[[nodiscard]] std::vector<NicntContentToc> parse_file_container_tocs(
        std::span<const std::span<const std::byte>> parts);
// any revision selects the highest; an exact revision selects the first match
[[nodiscard]] const NicntContentEntry *find_nicnt_content_by_id(
        const NicntContentToc &toc, std::uint32_t id,
        std::uint32_t revision = nicnt_any_content_revision);
[[nodiscard]] const NicntContentEntry *find_nicnt_content_by_id(
        std::span<const NicntContentToc> tocs, std::uint32_t id,
        std::uint32_t revision = nicnt_any_content_revision);
[[nodiscard]] const NicntContentEntry *find_nicnt_content_by_name(
        const NicntContentToc &toc, std::string_view utf8_name,
        std::uint32_t revision = nicnt_any_content_revision);
[[nodiscard]] const NicntContentEntry *find_nicnt_content_by_name(
        std::span<const NicntContentToc> tocs, std::string_view utf8_name,
        std::uint32_t revision = nicnt_any_content_revision);
// still encoded, this doesn't decode anything
[[nodiscard]] std::span<const std::byte> nicnt_content_bytes(
        std::span<const std::byte> container, const NicntContentEntry &entry);
[[nodiscard]] std::vector<NicntContentPartSpan> nicnt_content_parts(
        std::span<const std::span<const std::byte>> parts,
        const NicntContentEntry &entry);
// parses child TOCs within the selected content range
[[nodiscard]] std::vector<NicntContentToc> parse_nicnt_content_subcontainer(
        std::span<const std::byte> container, const NicntContentEntry &entry);
[[nodiscard]] std::vector<NicntContentToc> parse_nicnt_content_subcontainer(
        std::span<const std::span<const std::byte>> parts,
        const NicntContentEntry &entry);
// each component resolves within the current container before opening its child
[[nodiscard]] std::optional<std::vector<NicntContentToc>>
open_nicnt_content_subpath(std::span<const std::byte> container,
        std::span<const NicntContentSelector> selectors,
        std::uint32_t revision = nicnt_any_content_revision);
[[nodiscard]] std::optional<std::vector<NicntContentToc>>
open_nicnt_content_subpath(std::span<const std::span<const std::byte>> parts,
        std::span<const NicntContentSelector> selectors,
        std::uint32_t revision = nicnt_any_content_revision);
// zero-size entries can be found by lookup but produce no file content range
[[nodiscard]] std::optional<NicntFileContentRange> nicnt_content_range(
        std::span<const std::span<const std::byte>> parts,
        const NicntContentEntry &entry);
// product checksum input and SHA-1 hex
[[nodiscard]] std::string nicnt_product_checksum_input(
        const NicntProductInfo &product);
[[nodiscard]] std::string nicnt_product_checksum(
        const NicntProductInfo &product);
// no Product@hash is fine, otherwise it has to match the lowercase SHA-1
// exactly
[[nodiscard]] bool verify_nicnt_product_checksum(
        const NicntProductInfo &product);
// compares versions the way kontakt does
[[nodiscard]] bool nicnt_product_is_feasible(
        const NicntProductInfo &product, std::string_view engine_version);
[[nodiscard]] bool nicnt_product_matches_filter(
        const NicntProductInfo &product, const NicntProductFilter &filter);
// kontakt 8's default filter
[[nodiscard]] NicntProductFilter kontakt8_default_product_filter();
// first product kontakt would accept, all of them are still in products
[[nodiscard]] const NicntProductInfo *select_nicnt_monolith_product(
        const NicntContainer &container, std::string_view engine_version,
        const NicntProductFilter *filter = nullptr);
// pre-0x111 stores decimal digits, later the real ID. no payload means no ID,
// EOF leaves included
[[nodiscard]] std::optional<std::uint32_t> monolith_entry_library_id(
        const MonolithEntry &entry) noexcept;
[[nodiscard]] std::vector<std::byte> decode_monolith_payload(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        std::span<const std::byte> product_key = {},
        std::span<const std::byte> legacy_xor_keys = {});
[[nodiscard]] std::vector<std::byte> decode_monolith_payload_prefix(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        std::size_t maximum_bytes, std::span<const std::byte> product_key = {},
        std::span<const std::byte> legacy_xor_keys = {});
// decodes just this window, not everything before it. product pad indices are
// relative to the payload, legacy rows use the stored position
[[nodiscard]] std::vector<std::byte> decode_monolith_payload_range(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        std::size_t first_byte, std::size_t maximum_bytes,
        std::span<const std::byte> product_key = {},
        std::span<const std::byte> legacy_xor_keys = {});
struct MonolithNcwPrefix {
    NcwInfo info;
    std::vector<float> interleaved_samples;
    // frames past EOF in the last 512 frame block, empty if we didn't decode
    // that far or the sample ends on a block
    std::vector<float> interleaved_terminal_cache_padding;
};
[[nodiscard]] MonolithNcwPrefix decode_monolith_ncw_prefix(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        std::size_t maximum_frames, std::span<const std::byte> product_key = {},
        std::span<const std::byte> legacy_xor_keys = {});
[[nodiscard]] MonolithNcwPrefix decode_monolith_ncw_frames(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        std::size_t first_frame, std::size_t frame_count,
        std::span<const std::byte> product_key = {},
        std::span<const std::byte> legacy_xor_keys = {});

// native destination ID and polarity; unknown XML names aren't eligible targets
[[nodiscard]] std::optional<std::pair<std::uint32_t, bool>>
resolve_modulation_target_name(std::string_view name);

} // namespace libnki
