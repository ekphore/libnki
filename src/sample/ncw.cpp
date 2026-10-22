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

NcwInfo parse_ncw_info(std::span<const std::byte> bytes,
        std::size_t file_offset, std::size_t logical_size) {
    if (logical_size == 0)
        logical_size = bytes.size();
    if (logical_size < bytes.size())
        throw std::invalid_argument(
                "NCW logical size is smaller than supplied bytes");
    if (file_offset > bytes.size() ||
            NcwInfo::header_size > bytes.size() - file_offset) {
        throw std::runtime_error("truncated NCW header");
    }
    const auto stored_magic = u32le(bytes, file_offset);
    if (stored_magic != NcwInfo::magic &&
            swap32(stored_magic) != NcwInfo::magic) {
        throw std::runtime_error("invalid NCW magic");
    }
    NcwInfo out;
    out.file_offset = file_offset;
    out.byte_swapped = stored_magic != NcwInfo::magic;
    auto ncw_u16 = [&](std::size_t relative_offset) {
        const auto value = u16le(bytes, file_offset + relative_offset);
        return out.byte_swapped ? swap16(value) : value;
    };
    auto ncw_u32 = [&](std::size_t relative_offset) {
        const auto value = u32le(bytes, file_offset + relative_offset);
        return out.byte_swapped ? swap32(value) : value;
    };
    out.header_version = ncw_u32(4);
    if (out.header_version < 0x130U) {
        throw std::runtime_error("unsupported NCW header version");
    }
    out.channel_count = ncw_u16(8);
    out.bits_per_sample = ncw_u16(0x0a);
    out.sample_rate = ncw_u32(0x0c);
    out.sample_count = ncw_u32(0x10);
    out.block_index_offset = ncw_u32(0x14);
    out.first_block_data_offset = ncw_u32(0x18);
    out.terminal_block_offset = static_cast<std::int32_t>(ncw_u32(0x1c));
    out.variant_8_flag = u8(bytes, file_offset + 0x77) != 0;
    switch (out.bits_per_sample) {
        case 16:
            out.codec_variant = 5;
            break;
        case 24:
            out.codec_variant = 6;
            break;
        case 32:
            out.codec_variant =
                    out.header_version != 0x130U && out.variant_8_flag ? 8 : 7;
            break;
        default:
            throw std::runtime_error("unsupported NCW sample bit depth");
    }
    if (out.channel_count == 0) {
        throw std::runtime_error("invalid NCW channel count");
    }
    const auto block_count =
            (static_cast<std::uint64_t>(out.sample_count) + 0x1ffU) / 0x200U +
            1U;
    if (block_count > (1U << 24) ||
            out.block_index_offset > bytes.size() - file_offset ||
            block_count * 4U >
                    bytes.size() - file_offset - out.block_index_offset) {
        throw std::runtime_error("NCW block-offset table is out of bounds");
    }
    out.block_offsets.reserve(static_cast<std::size_t>(block_count));
    for (std::uint64_t index = 0; index < block_count; ++index) {
        out.block_offsets.push_back(ncw_u32(
                out.block_index_offset + static_cast<std::size_t>(index * 4U)));
    }
    if (out.terminal_block_offset >= 0) {
        out.block_offsets.back() =
                static_cast<std::uint32_t>(out.terminal_block_offset);
    }
    if (out.block_offsets.size() < 2 ||
            out.first_block_data_offset < out.block_offsets.front()) {
        throw std::runtime_error("invalid NCW block-offset origin");
    }
    const auto relative_base = static_cast<std::size_t>(
            out.first_block_data_offset - out.block_offsets.front());
    if (file_offset > logical_size ||
            relative_base > logical_size - file_offset) {
        throw std::runtime_error("NCW block-data base is out of bounds");
    }
    out.block_data_base = file_offset + relative_base;
    out.blocks.reserve(out.block_offsets.size() - 1U);
    for (std::size_t index = 0; index + 1 < out.block_offsets.size(); ++index) {
        const auto relative_start =
                static_cast<std::size_t>(out.block_offsets[index]);
        const auto relative_end =
                static_cast<std::size_t>(out.block_offsets[index + 1]);
        if (out.block_data_base > logical_size ||
                relative_end < relative_start ||
                relative_start > logical_size - out.block_data_base ||
                relative_end > logical_size - out.block_data_base) {
            throw std::runtime_error(
                    "NCW block span is out of bounds or nonmonotonic");
        }
        out.blocks.push_back({ out.block_data_base + relative_start,
                out.block_data_base + relative_end });
    }
    return out;
}

NcwBlockHeader parse_ncw_block_header(std::span<const std::byte> bytes,
        std::size_t block_offset, bool byte_swapped) {
    if (block_offset > bytes.size() ||
            NcwBlockHeader::serialized_size > bytes.size() - block_offset) {
        throw std::runtime_error("truncated NCW BADPCM block header");
    }
    const auto block_u16 = [&](std::size_t relative_offset) {
        const auto value = u16le(bytes, block_offset + relative_offset);
        return byte_swapped ? swap16(value) : value;
    };
    const auto block_u32 = [&](std::size_t relative_offset) {
        const auto value = u32le(bytes, block_offset + relative_offset);
        return byte_swapped ? swap32(value) : value;
    };
    if (block_u32(0) != NcwBlockHeader::magic) {
        throw std::runtime_error("invalid NCW BADPCM block magic");
    }
    NcwBlockHeader out;
    out.offset = block_offset;
    out.byte_swapped = byte_swapped;
    out.initial_value = static_cast<std::int32_t>(block_u32(4));
    out.residual_bit_width = static_cast<std::int16_t>(block_u16(8));
    out.flags = block_u16(0x0a);
    const auto width = static_cast<int>(out.residual_bit_width);
    if (!((width >= 2 && width <= 31) || width == -16 || width == -24 ||
                width == -32)) {
        throw std::runtime_error("unsupported NCW BADPCM residual width");
    }
    out.payload_offset = block_offset + NcwBlockHeader::serialized_size;
    out.payload_size =
            static_cast<std::size_t>(width < 0 ? -width : width) * 0x40U;
    if (out.payload_size > bytes.size() - out.payload_offset) {
        throw std::runtime_error("truncated NCW BADPCM block payload");
    }
    out.end_offset = out.payload_offset + out.payload_size;
    return out;
}

std::array<std::int32_t, 512> decode_ncw_block(
        std::span<const std::byte> bytes, const NcwBlockHeader &header) {
    if (header.payload_offset > bytes.size() ||
            header.payload_size > bytes.size() - header.payload_offset ||
            header.end_offset != header.payload_offset + header.payload_size) {
        throw std::invalid_argument("NCW BADPCM block span is out of bounds");
    }
    if ((header.flags & 2U) != 0) {
        throw std::invalid_argument(
                "floating NCW BADPCM block requested as integer");
    }
    std::array<std::int32_t, 512> out{};
    const auto width = static_cast<int>(header.residual_bit_width);
    if (width < 0) {
        const auto sample_width = static_cast<unsigned>(-width);
        for (std::size_t index = 0; index < out.size(); ++index) {
            const auto offset =
                    header.payload_offset + index * (sample_width / 8U);
            if (sample_width == 16) {
                auto value = u16le(bytes, offset);
                if (header.byte_swapped)
                    value = swap16(value);
                out[index] = static_cast<std::int16_t>(value);
            } else if (sample_width == 24) {
                std::uint32_t value;
                if (header.byte_swapped) {
                    value = static_cast<std::uint32_t>(u8(bytes, offset + 2)) |
                            (static_cast<std::uint32_t>(u8(bytes, offset + 1))
                                    << 8U) |
                            (static_cast<std::uint32_t>(u8(bytes, offset))
                                    << 16U);
                } else {
                    value = static_cast<std::uint32_t>(u8(bytes, offset)) |
                            (static_cast<std::uint32_t>(u8(bytes, offset + 1))
                                    << 8U) |
                            (static_cast<std::uint32_t>(u8(bytes, offset + 2))
                                    << 16U);
                }
                if ((value & 0x00800000U) != 0)
                    value |= 0xff000000U;
                out[index] = static_cast<std::int32_t>(value);
            } else {
                auto value = u32le(bytes, offset);
                if (header.byte_swapped)
                    value = swap32(value);
                out[index] = static_cast<std::int32_t>(value);
            }
        }
        return out;
    }

    out[0] = header.initial_value;
    const auto read_word = [&](std::size_t word_index) {
        auto value = u32le(bytes, header.payload_offset + word_index * 4U);
        return header.byte_swapped ? swap32(value) : value;
    };
    const auto mask = (std::uint32_t{ 1 } << static_cast<unsigned>(width)) - 1U;
    std::uint32_t accumulator =
            static_cast<std::uint32_t>(header.initial_value);
    for (std::size_t sample = 1; sample < out.size(); ++sample) {
        const auto bit_offset = (sample - 1U) * static_cast<std::size_t>(width);
        const auto word_index = bit_offset / 32U;
        const auto shift = static_cast<unsigned>(bit_offset & 31U);
        std::uint32_t encoded = read_word(word_index) >> shift;
        if (shift + static_cast<unsigned>(width) > 32U) {
            encoded |= read_word(word_index + 1U) << (32U - shift);
        }
        encoded &= mask;
        if ((encoded & (std::uint32_t{ 1 }
                               << static_cast<unsigned>(width - 1))) != 0) {
            encoded |= ~mask;
        }
        accumulator += encoded;
        out[sample] = static_cast<std::int32_t>(accumulator);
    }
    return out;
}

std::array<float, 512> decode_ncw_block_f32(std::span<const std::byte> bytes,
        const NcwBlockHeader &header, float integer_scale) {
    if ((header.flags & 2U) == 0) {
        const auto integers = decode_ncw_block(bytes, header);
        std::array<float, 512> out{};
        for (std::size_t index = 0; index < out.size(); ++index) {
            out[index] = static_cast<float>(integers[index]) * integer_scale;
        }
        return out;
    }
    if (header.payload_offset > bytes.size() ||
            header.payload_size > bytes.size() - header.payload_offset) {
        throw std::invalid_argument(
                "NCW floating BADPCM block span is out of bounds");
    }
    std::array<float, 512> out{};
    const auto width = static_cast<int>(header.residual_bit_width);
    if (width == -32) {
        for (std::size_t index = 0; index < out.size(); ++index) {
            auto bits = u32le(bytes, header.payload_offset + index * 4U);
            if (header.byte_swapped)
                bits = swap32(bits);
            out[index] = std::bit_cast<float>(bits);
        }
        return out;
    }
    if (width < 2 || width > 31) {
        throw std::runtime_error(
                "unsupported floating NCW BADPCM residual width");
    }
    std::uint32_t accumulator =
            static_cast<std::uint32_t>(header.initial_value);
    out[0] = std::bit_cast<float>(accumulator);
    const auto read_word = [&](std::size_t word_index) {
        auto value = u32le(bytes, header.payload_offset + word_index * 4U);
        return header.byte_swapped ? swap32(value) : value;
    };
    const auto mask = (std::uint32_t{ 1 } << static_cast<unsigned>(width)) - 1U;
    for (std::size_t sample = 1; sample < out.size(); ++sample) {
        const auto bit_offset = (sample - 1U) * static_cast<std::size_t>(width);
        const auto word_index = bit_offset / 32U;
        const auto shift = static_cast<unsigned>(bit_offset & 31U);
        std::uint32_t encoded = read_word(word_index) >> shift;
        if (shift + static_cast<unsigned>(width) > 32U) {
            encoded |= read_word(word_index + 1U) << (32U - shift);
        }
        encoded &= mask;
        if ((encoded & (std::uint32_t{ 1 }
                               << static_cast<unsigned>(width - 1))) != 0) {
            encoded |= ~mask;
        }
        // floating residuals add IEEE bit patterns as integers, not float
        // values
        accumulator += encoded;
        out[sample] = std::bit_cast<float>(accumulator);
    }
    return out;
}

std::vector<std::int32_t> decode_ncw_samples_i32(
        std::span<const std::byte> bytes, const NcwInfo &info) {
    if (info.channel_count == 0) {
        throw std::invalid_argument("NCW channel count is zero");
    }
    const auto frame_count = static_cast<std::size_t>(info.sample_count);
    if (frame_count >
            std::numeric_limits<std::size_t>::max() / info.channel_count) {
        throw std::runtime_error(
                "NCW decoded sample count overflows address space");
    }
    std::vector<std::int32_t> out(frame_count * info.channel_count);
    std::size_t produced_frames = 0;
    for (const auto &span : info.blocks) {
        if (produced_frames == frame_count)
            break;
        std::size_t cursor = span.offset;
        std::vector<std::array<std::int32_t, 512>> channels;
        channels.reserve(info.channel_count);
        std::uint16_t first_flags = 0;
        for (std::uint16_t channel = 0; channel < info.channel_count;
                ++channel) {
            const auto header =
                    parse_ncw_block_header(bytes, cursor, info.byte_swapped);
            if (header.end_offset > span.end_offset) {
                throw std::runtime_error(
                        "NCW channel block exceeds indexed block span");
            }
            if (channel == 0)
                first_flags = header.flags;
            if ((header.flags & 2U) != 0) {
                throw std::runtime_error(
                        "floating NCW cannot be decoded to integer samples");
            }
            channels.push_back(decode_ncw_block(bytes, header));
            cursor = header.end_offset;
        }
        if (cursor != span.end_offset) {
            throw std::runtime_error(
                    "NCW indexed block span has trailing bytes");
        }
        if (info.channel_count == 2 && (first_flags & 1U) != 0) {
            for (std::size_t frame = 0; frame < 512; ++frame) {
                const auto mid = static_cast<std::uint32_t>(channels[0][frame]);
                const auto side =
                        static_cast<std::uint32_t>(channels[1][frame]);
                channels[0][frame] = static_cast<std::int32_t>(mid + side);
                channels[1][frame] = static_cast<std::int32_t>(mid - side);
            }
        }
        const auto frames_here =
                std::min<std::size_t>(512, frame_count - produced_frames);
        for (std::size_t frame = 0; frame < frames_here; ++frame) {
            for (std::uint16_t channel = 0; channel < info.channel_count;
                    ++channel) {
                out[(produced_frames + frame) * info.channel_count + channel] =
                        channels[channel][frame];
            }
        }
        produced_frames += frames_here;
    }
    if (produced_frames != frame_count) {
        throw std::runtime_error(
                "NCW block index does not cover declared sample count");
    }
    return out;
}

std::vector<float> decode_ncw_cache_block_f32(std::span<const std::byte> bytes,
        const NcwInfo &info, const std::size_t block_index) {
    if (info.channel_count == 0)
        throw std::invalid_argument("NCW channel count is zero");
    const auto &span = info.blocks.at(block_index);
    float scale;
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
    std::size_t cursor = span.offset;
    std::vector<std::array<float, 512>> channels;
    channels.reserve(info.channel_count);
    std::uint16_t first_flags = 0;
    for (std::uint16_t channel = 0; channel < info.channel_count; ++channel) {
        const auto header =
                parse_ncw_block_header(bytes, cursor, info.byte_swapped);
        if (header.end_offset > span.end_offset)
            throw std::runtime_error(
                    "NCW channel block exceeds indexed block span");
        if (channel == 0)
            first_flags = header.flags;
        channels.push_back(decode_ncw_block_f32(bytes, header, scale));
        cursor = header.end_offset;
    }
    if (cursor != span.end_offset)
        throw std::runtime_error("NCW indexed block span has trailing bytes");
    if (info.channel_count == 2 && (first_flags & 1U) != 0)
        for (std::size_t frame = 0; frame < 512; ++frame) {
            const auto mid = channels[0][frame];
            const auto side = channels[1][frame];
            channels[0][frame] = mid + side;
            channels[1][frame] = mid - side;
        }
    std::vector<float> out(512 * static_cast<std::size_t>(info.channel_count));
    for (std::size_t frame = 0; frame < 512; ++frame)
        for (std::size_t channel = 0; channel < info.channel_count; ++channel)
            out[frame * info.channel_count + channel] =
                    channels[channel][frame];
    return out;
}

std::vector<float> decode_ncw_samples_f32(std::span<const std::byte> bytes,
        const NcwInfo &info, const std::size_t maximum_frames) {
    if (info.channel_count == 0)
        throw std::invalid_argument("NCW channel count is zero");
    const auto frame_count = std::min(
            static_cast<std::size_t>(info.sample_count), maximum_frames);
    if (frame_count >
            std::numeric_limits<std::size_t>::max() / info.channel_count) {
        throw std::runtime_error(
                "NCW decoded sample count overflows address space");
    }
    float scale;
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
    std::vector<float> out(frame_count * info.channel_count);
    std::size_t produced_frames = 0;
    for (const auto &span : info.blocks) {
        if (produced_frames == frame_count)
            break;
        std::size_t cursor = span.offset;
        std::vector<std::array<float, 512>> channels;
        channels.reserve(info.channel_count);
        std::uint16_t first_flags = 0;
        for (std::uint16_t channel = 0; channel < info.channel_count;
                ++channel) {
            const auto header =
                    parse_ncw_block_header(bytes, cursor, info.byte_swapped);
            if (header.end_offset > span.end_offset) {
                throw std::runtime_error(
                        "NCW channel block exceeds indexed block span");
            }
            if (channel == 0)
                first_flags = header.flags;
            channels.push_back(decode_ncw_block_f32(bytes, header, scale));
            cursor = header.end_offset;
        }
        if (cursor != span.end_offset) {
            throw std::runtime_error(
                    "NCW indexed block span has trailing bytes");
        }
        if (info.channel_count == 2 && (first_flags & 1U) != 0) {
            for (std::size_t frame = 0; frame < 512; ++frame) {
                const auto mid = channels[0][frame];
                const auto side = channels[1][frame];
                channels[0][frame] = mid + side;
                channels[1][frame] = mid - side;
            }
        }
        const auto frames_here =
                std::min<std::size_t>(512, frame_count - produced_frames);
        for (std::size_t frame = 0; frame < frames_here; ++frame) {
            for (std::uint16_t channel = 0; channel < info.channel_count;
                    ++channel) {
                out[(produced_frames + frame) * info.channel_count + channel] =
                        channels[channel][frame];
            }
        }
        produced_frames += frames_here;
    }
    if (produced_frames != frame_count) {
        throw std::runtime_error(
                "NCW block index does not cover declared sample count");
    }
    return out;
}

} // namespace libnki
