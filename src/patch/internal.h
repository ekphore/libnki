// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "libnki/nki.h"

namespace libnki::detail {

K2EffectSemantic parse_k2_effect(const K1TagElement &element);
K2BankSemantic parse_k2_bank(const K1TagElement &element);
K2ProgramContainerSemantic parse_k2_program_container(
        const K1TagElement &element);
K2OutputConfigurationSemantic parse_k2_output_configuration(
        const K1TagElement &element);
K2OutputPartitionSemantic parse_k2_output_partition(
        const K1TagElement &element);
void apply_k2_close_semantics(K2PatchData &data);

namespace k1 {
void materialize(K1PatchData &data);
} // namespace k1

} // namespace libnki::detail

#include "../protection/internal.h"
#include "binary.h"

namespace libnki {

// used by group and snapshot parsing, not public
ParameterArrayPayload parse_internal_modulator_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled,
        std::span<const ParFxTypeMapping> runtime_type_mappings);
ParameterArrayPayload parse_external_modulator_array(
        std::span<const std::byte> bytes, std::size_t offset,
        bool context_ids_enabled);

} // namespace libnki

namespace libnki::detail::patch {
using protection::parse_authorization_payload;
using protection::parse_protected_item;

ParScriptPayload parse_par_script_bounded(std::span<const std::byte> bytes,
        std::size_t offset, std::size_t limit);

std::size_t fastlz_decompress(
        std::span<const std::byte> input, std::span<std::byte> output);

bool legacy_patch_magic(std::uint32_t value);

bool inherited_record(std::span<const std::byte> bytes, std::size_t off,
        std::uint32_t expected_item_id, std::size_t limit, Document &doc);

std::optional<RepositoryRoot> parse_repository_root(
        std::span<const std::byte> bytes, const Frame &frame, Document &doc);

std::optional<AuthorizationItem> parse_authorization_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<BaseItem> parse_base_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<PresetInfo> parse_kontakt_preset(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<PresetInfo> parse_preset_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<SoundInfoItem> parse_sound_info(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<AutomationParameters> parse_automation_parameters(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<ControllerAssignments> parse_controller_assignments(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<BNISoundHeader> parse_bnisound_header(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<AudioSampleItem> parse_audio_sample_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<ExternalFileReferenceItem> parse_external_file_reference_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<InternalResourceReferenceItem>
parse_internal_resource_reference_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<PictureItem> parse_picture_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<BinaryChunkItem> parse_binary_chunk_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<ResourcesItem> parse_resources_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<GenericItem> parse_generic_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<ModuleItem> parse_module_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<ModuleBankItem> parse_module_bank_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<BankItem> parse_bank_item(std::span<const std::byte> bytes,
        const Frame &frame, std::size_t frame_index, Document &doc);

std::optional<BankContainerItem> parse_bank_container_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<PresetContainerItem> parse_preset_container_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

std::optional<PresetChunkItem> parse_preset_chunk_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, Document &doc);

} // namespace libnki::detail::patch
