// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "libnki/nki.h"

#include <algorithm>
#include <bit>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <utility>

#include "../binary/read.h"

namespace libnki {
using namespace detail::binary;

std::vector<std::byte> decode_monolith_payload(std::span<const std::byte> bytes,
        const MonolithEntry &entry, std::span<const std::byte> product_key,
        std::span<const std::byte> legacy_xor_keys) {
    return decode_monolith_payload_prefix(bytes, entry,
            std::numeric_limits<std::size_t>::max(), product_key,
            legacy_xor_keys);
}

std::vector<std::byte> decode_monolith_payload_prefix(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        const std::size_t maximum_bytes, std::span<const std::byte> product_key,
        std::span<const std::byte> legacy_xor_keys) {
    return decode_monolith_payload_range(
            bytes, entry, 0, maximum_bytes, product_key, legacy_xor_keys);
}

std::vector<std::byte> decode_monolith_payload_range(
        std::span<const std::byte> bytes, const MonolithEntry &entry,
        const std::size_t first_byte, const std::size_t maximum_bytes,
        std::span<const std::byte> product_key,
        std::span<const std::byte> legacy_xor_keys) {
    if (!entry.payload) {
        throw std::runtime_error(
                "monolith entry has no supported payload header");
    }
    const auto &header = *entry.payload;
    if (header.offset > bytes.size() ||
            header.header_size >
                    bytes.size() - static_cast<std::size_t>(header.offset))
        throw std::runtime_error("monolith payload header is out of bounds");
    const auto data_offset =
            static_cast<std::size_t>(header.offset) + header.header_size;
    if (data_offset > bytes.size() ||
            header.source_size > bytes.size() - data_offset) {
        throw std::runtime_error("monolith payload span is out of bounds");
    }
    if (first_byte > header.source_size)
        throw std::runtime_error("monolith payload window is out of bounds");
    const auto output_size = std::min<std::size_t>(
            header.source_size - first_byte, maximum_bytes);
    // clang-format off
    std::vector<std::byte> out(bytes.begin() +
            static_cast<std::ptrdiff_t>(data_offset + first_byte),
            bytes.begin() + static_cast<std::ptrdiff_t>(data_offset +
            first_byte + output_size));
    // clang-format on
    if (header.transform_mode == 0xffU)
        return out;
    if (header.transform_mode == 0x100U) {
        if (product_key.size() != 0x10000U) {
            throw std::runtime_error(
                    "monolith transform 0x100 requires a 65536-byte product key");
        }
        for (std::size_t index = 0; index < out.size(); ++index) {
            out[index] ^= product_key[(first_byte + index) & 0xffffU];
        }
        return out;
    }
    const auto row_offset =
            static_cast<std::size_t>(header.transform_mode) * 0x10U;
    if (header.transform_mode > 0xffU || row_offset > legacy_xor_keys.size() ||
            0x10U > legacy_xor_keys.size() - row_offset) {
        throw std::runtime_error("monolith legacy transform requires the "
                                 "selected 16-byte XOR-key row");
    }
    for (std::size_t index = 0; index < out.size(); ++index) {
        const auto key_index =
                row_offset + ((data_offset + first_byte + index) & 0x0fU);
        out[index] ^= legacy_xor_keys[key_index];
    }
    return out;
}

MonolithNcwPrefix decode_monolith_ncw_prefix(std::span<const std::byte> bytes,
        const MonolithEntry &entry, const std::size_t maximum_frames,
        std::span<const std::byte> product_key,
        std::span<const std::byte> legacy_xor_keys) {
    if (!entry.payload)
        throw std::runtime_error(
                "monolith entry has no supported payload header");
    const auto &header = *entry.payload;
    const auto data_offset =
            static_cast<std::size_t>(header.offset) + header.header_size;
    const auto source_size = static_cast<std::size_t>(header.source_size);
    if (data_offset > bytes.size() || source_size > bytes.size() - data_offset)
        throw std::runtime_error("monolith payload span is out of bounds");
    const auto decode_bytes = [&](const std::size_t count) {
        std::vector<std::byte> out(
                bytes.begin() + static_cast<std::ptrdiff_t>(data_offset),
                bytes.begin() +
                        static_cast<std::ptrdiff_t>(data_offset + count));
        if (header.transform_mode == 0xffU)
            return out;
        if (header.transform_mode == 0x100U) {
            if (product_key.size() != 0x10000U)
                throw std::runtime_error("monolith transform 0x100 requires a "
                                         "65536-byte product key");
            for (std::size_t index = 0; index < out.size(); ++index)
                out[index] ^= product_key[index & 0xffffU];
            return out;
        }
        const auto row_offset =
                static_cast<std::size_t>(header.transform_mode) * 0x10U;
        if (header.transform_mode > 0xffU ||
                row_offset > legacy_xor_keys.size() ||
                0x10U > legacy_xor_keys.size() - row_offset)
            throw std::runtime_error("monolith legacy transform requires the "
                                     "selected 16-byte XOR-key row");
        for (std::size_t index = 0; index < out.size(); ++index)
            out[index] ^= legacy_xor_keys[row_offset +
                                          ((data_offset + index) & 0x0fU)];
        return out;
    };
    if (source_size < NcwInfo::header_size)
        throw std::runtime_error("truncated monolith NCW payload");
    auto prefix = decode_bytes(NcwInfo::header_size);
    const auto stored_magic = u32le(prefix, 0);
    if (stored_magic != NcwInfo::magic &&
            swap32(stored_magic) != NcwInfo::magic)
        throw std::runtime_error("invalid NCW magic");
    const bool swapped = stored_magic != NcwInfo::magic;
    const auto header_u32 = [&](const std::size_t offset) {
        const auto value = u32le(prefix, offset);
        return swapped ? swap32(value) : value;
    };
    const auto sample_count = header_u32(0x10);
    const auto index_offset = static_cast<std::size_t>(header_u32(0x14));
    const auto block_count =
            (static_cast<std::uint64_t>(sample_count) + 0x1ffU) / 0x200U + 1U;
    if (block_count > (1U << 24) || block_count * 4U > source_size ||
            index_offset > source_size - block_count * 4U)
        throw std::runtime_error("NCW block-offset table is out of bounds");
    prefix = decode_bytes(std::max<std::size_t>(NcwInfo::header_size,
            index_offset + static_cast<std::size_t>(block_count * 4U)));
    auto info = parse_ncw_info(prefix, 0, source_size);
    const auto wanted_frames =
            std::min<std::size_t>(maximum_frames, info.sample_count);
    const auto wanted_blocks = std::min<std::size_t>(
            info.blocks.size(), (wanted_frames + 0x1ffU) / 0x200U);
    const auto required_size =
            wanted_blocks == 0 ? prefix.size()
                               : info.blocks[wanted_blocks - 1].end_offset;
    if (required_size > source_size)
        throw std::runtime_error("NCW preload span exceeds monolith payload");
    if (required_size > prefix.size())
        prefix = decode_bytes(required_size);
    auto samples = decode_ncw_samples_f32(prefix, info, maximum_frames);
    std::vector<float> padding;
    if (wanted_frames == info.sample_count && info.sample_count % 512 != 0) {
        const auto block = decode_ncw_cache_block_f32(
                prefix, info, info.sample_count / 512);
        padding.assign(block.begin() + static_cast<std::ptrdiff_t>(
                                               (info.sample_count % 512) *
                                               info.channel_count),
                block.end());
    }
    return { std::move(info), std::move(samples), std::move(padding) };
}

MonolithNcwPrefix decode_monolith_ncw_frames(
        const std::span<const std::byte> bytes, const MonolithEntry &entry,
        const std::size_t first_frame, const std::size_t requested_frames,
        const std::span<const std::byte> product_key,
        const std::span<const std::byte> legacy_xor_keys) {
    auto metadata = decode_monolith_ncw_prefix(
            bytes, entry, 0, product_key, legacy_xor_keys);
    auto &info = metadata.info;
    if (first_frame >= info.sample_count || requested_frames == 0) {
        metadata.interleaved_samples.clear();
        return metadata;
    }
    const auto frame_count = std::min<std::size_t>(requested_frames,
            static_cast<std::size_t>(info.sample_count) - first_frame);
    if (!entry.payload)
        throw std::runtime_error(
                "monolith entry has no supported payload header");
    const auto &payload = *entry.payload;
    const auto data_offset =
            static_cast<std::size_t>(payload.offset) + payload.header_size;
    const auto decode_range = [&](const std::size_t offset,
                                      const std::size_t count) {
        // clang-format off
        if (offset > payload.source_size || count > payload.source_size -
                offset || data_offset > bytes.size() || offset > bytes.size() -
                data_offset || count > bytes.size() - data_offset - offset)
            // clang-format on
            throw std::runtime_error(
                    "monolith NCW block range is out of bounds");
        // clang-format off
        std::vector<std::byte> out(bytes.begin() +
                static_cast<std::ptrdiff_t>(data_offset + offset),
                bytes.begin() + static_cast<std::ptrdiff_t>(data_offset +
                offset + count));
        // clang-format on
        if (payload.transform_mode == 0xffU)
            return out;
        if (payload.transform_mode == 0x100U) {
            if (product_key.size() != 0x10000U)
                throw std::runtime_error("monolith transform 0x100 requires a "
                                         "65536-byte product key");
            for (std::size_t index = 0; index < out.size(); ++index)
                out[index] ^= product_key[(offset + index) & 0xffffU];
            return out;
        }
        const auto row_offset =
                static_cast<std::size_t>(payload.transform_mode) * 0x10U;
        if (payload.transform_mode > 0xffU ||
                row_offset > legacy_xor_keys.size() ||
                0x10U > legacy_xor_keys.size() - row_offset)
            throw std::runtime_error("monolith legacy transform requires the "
                                     "selected 16-byte XOR-key row");
        for (std::size_t index = 0; index < out.size(); ++index)
            out[index] ^=
                    legacy_xor_keys[row_offset +
                                    ((data_offset + offset + index) & 0x0fU)];
        return out;
    };
    float scale{};
    switch (info.bits_per_sample) {
        case 16:
            scale = 1.0F / 32768.0F;
            break;
        case 24:
            scale = 1.0F / 8388608.0F;
            break;
        case 32:
            scale = 1.0F / 2147483648.0F;
            break;
        default:
            throw std::invalid_argument("unsupported NCW integer scale");
    }
    std::vector<float> output(frame_count * info.channel_count);
    const auto first_block = first_frame / 512;
    const auto last_frame = first_frame + frame_count;
    const auto last_block = (last_frame + 511) / 512;
    for (std::size_t block_index = first_block;
            block_index < std::min(last_block, info.blocks.size());
            ++block_index) {
        const auto &span = info.blocks[block_index];
        auto block_bytes =
                decode_range(span.offset, span.end_offset - span.offset);
        std::size_t cursor{};
        std::vector<std::array<float, 512>> channels;
        channels.reserve(info.channel_count);
        std::uint16_t first_flags{};
        for (std::uint16_t channel = 0; channel < info.channel_count;
                ++channel) {
            const auto header = parse_ncw_block_header(
                    block_bytes, cursor, info.byte_swapped);
            if (channel == 0)
                first_flags = header.flags;
            channels.push_back(
                    decode_ncw_block_f32(block_bytes, header, scale));
            cursor = header.end_offset;
        }
        if (cursor != block_bytes.size())
            throw std::runtime_error(
                    "NCW indexed block span has trailing bytes");
        if (info.channel_count == 2 && (first_flags & 1U) != 0)
            for (std::size_t frame = 0; frame < 512; ++frame) {
                const auto mid = channels[0][frame];
                const auto side = channels[1][frame];
                channels[0][frame] = mid + side;
                channels[1][frame] = mid - side;
            }
        const auto block_frame = block_index * 512;
        const auto copy_first = std::max(first_frame, block_frame);
        const auto copy_last = std::min(last_frame, block_frame + 512);
        for (auto frame = copy_first; frame < copy_last; ++frame)
            for (std::size_t channel = 0; channel < info.channel_count;
                    ++channel)
                output[(frame - first_frame) * info.channel_count + channel] =
                        channels[channel][frame - block_frame];
        if (last_frame == info.sample_count && info.sample_count % 512 != 0 &&
                block_index == info.sample_count / 512) {
            const auto valid = info.sample_count % 512;
            metadata.interleaved_terminal_cache_padding.resize(
                    (512 - valid) * info.channel_count);
            for (std::size_t frame = valid; frame < 512; ++frame)
                for (std::size_t channel = 0; channel < info.channel_count;
                        ++channel)
                    metadata.interleaved_terminal_cache_padding
                            [(frame - valid) * info.channel_count + channel] =
                            channels[channel][frame];
        }
    }
    metadata.interleaved_samples = std::move(output);
    return metadata;
}

} // namespace libnki
