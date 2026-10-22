// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../patch/internal.h"
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
using namespace detail::protection;

namespace {
std::vector<std::byte> derive_encryption_key_from_traits(
        std::span<const std::byte> private_key, std::string_view ctr_iv_hex,
        std::string_view aes_key_hex) {
    constexpr std::size_t kEncryptionKeySize = 1U << 16;
    if (private_key.size() != kEncryptionKeySize) {
        throw std::invalid_argument(
                "encryption private key must be exactly 65536 bytes");
    }
    auto decode_hex = [](std::string_view text, std::string_view label) {
        if ((text.size() & 1U) != 0) {
            throw std::invalid_argument(
                    std::string(label) +
                    " must contain complete hex-byte pairs");
        }
        auto nibble = [label](char c) -> unsigned {
            if (c >= '0' && c <= '9')
                return static_cast<unsigned>(c - '0');
            if (c >= 'a' && c <= 'f')
                return static_cast<unsigned>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F')
                return static_cast<unsigned>(c - 'A' + 10);
            throw std::invalid_argument(
                    std::string(label) + " contains a non-hex character");
        };
        std::vector<unsigned char> result(text.size() / 2);
        for (std::size_t i = 0; i < result.size(); ++i) {
            result[i] = static_cast<unsigned char>(
                    (nibble(text[i * 2]) << 4U) | nibble(text[i * 2 + 1]));
        }
        return result;
    };

    auto iv = decode_hex(ctr_iv_hex, "CTR IV");
    auto aes_key = decode_hex(aes_key_hex, "AES key");
    if (iv.size() != 16)
        throw std::invalid_argument("CTR IV must be exactly 16 bytes");
    const EVP_CIPHER *cipher = nullptr;
    if (aes_key.size() == 16)
        cipher = EVP_aes_128_ctr();
    else if (aes_key.size() == 24)
        cipher = EVP_aes_192_ctr();
    else if (aes_key.size() == 32)
        cipher = EVP_aes_256_ctr();
    else
        throw std::invalid_argument("AES key must be 16, 24, or 32 bytes");

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (context == nullptr)
        throw std::runtime_error("cannot allocate AES-CTR context");
    std::vector<std::byte> derived(kEncryptionKeySize);
    int produced = 0;
    int final_produced = 0;
    const auto ok =
            EVP_EncryptInit_ex(
                    context, cipher, nullptr, aes_key.data(), iv.data()) == 1 &&
            EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
            EVP_EncryptUpdate(context,
                    reinterpret_cast<unsigned char *>(derived.data()),
                    &produced,
                    reinterpret_cast<const unsigned char *>(private_key.data()),
                    static_cast<int>(private_key.size())) == 1 &&
            EVP_EncryptFinal_ex(context,
                    reinterpret_cast<unsigned char *>(derived.data()) +
                            produced,
                    &final_produced) == 1;
    EVP_CIPHER_CTX_free(context);
    std::fill(aes_key.begin(), aes_key.end(), 0);
    if (!ok || produced + final_produced != static_cast<int>(derived.size())) {
        std::fill(derived.begin(), derived.end(), std::byte{ 0 });
        throw std::runtime_error("AES-CTR key derivation failed");
    }
    return derived;
}

std::string xml_text(std::string_view product, std::string_view tag) {
    const std::string open = "<" + std::string(tag) + ">";
    const std::string close = "</" + std::string(tag) + ">";
    const auto begin = product.find(open);
    if (begin == std::string_view::npos)
        return {};
    const auto value_begin = begin + open.size();
    const auto end = product.find(close, value_begin);
    if (end == std::string_view::npos)
        return {};
    return std::string(product.substr(value_begin, end - value_begin));
}
} // namespace

const char *expected_encryption_private_key_sha256() noexcept {
    return "257fe1f26b8c674f5b634ecce2ae11e1723050f1a02de6bdf6d0edab52cfbc4f";
}

std::string sha256_hex(std::span<const std::byte> data) {
    static constexpr std::array<std::uint32_t, 64> k{ 0x428a2f98U, 0x71374491U,
        0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
        0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U,
        0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU,
        0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U,
        0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U,
        0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
        0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U,
        0x106aa070U, 0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU,
        0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU,
        0xbef9a3f7U, 0xc67178f2U };
    std::array<std::uint32_t, 8> h{ 0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U,
        0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U };
    const auto bit_length = static_cast<std::uint64_t>(data.size()) * 8U;
    auto padded_size = data.size() + 1 + 8;
    padded_size = (padded_size + 63U) & ~std::size_t{ 63U };
    std::vector<std::byte> padded(padded_size);
    std::copy(data.begin(), data.end(), padded.begin());
    padded[data.size()] = std::byte{ 0x80 };
    for (std::size_t i = 0; i < 8; ++i) {
        padded[padded_size - 1 - i] =
                std::byte((bit_length >> (i * 8U)) & 0xffU);
    }
    const auto rotr = [](std::uint32_t v, unsigned n) {
        return (v >> n) | (v << (32U - n));
    };
    for (std::size_t block = 0; block < padded.size(); block += 64) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i) {
            const auto p = block + i * 4;
            w[i] = (static_cast<std::uint32_t>(u8(padded, p)) << 24U) |
                   (static_cast<std::uint32_t>(u8(padded, p + 1)) << 16U) |
                   (static_cast<std::uint32_t>(u8(padded, p + 2)) << 8U) |
                   static_cast<std::uint32_t>(u8(padded, p + 3));
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                            (w[i - 15] >> 3U);
            const auto s1 =
                    rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        auto [a, b, c, d, e, f, g, hh] = h;
        for (std::size_t i = 0; i < 64; ++i) {
            const auto s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const auto ch = (e & f) ^ (~e & g);
            const auto t1 = hh + s1 + ch + k[i] + w[i];
            const auto s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto t2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto word : h) {
        for (int shift = 28; shift >= 0; shift -= 4)
            result.push_back(digits[(word >> shift) & 0xfU]);
    }
    return result;
}

std::vector<std::byte> load_encryption_private_key(
        const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input)
        throw std::runtime_error("cannot open encryption private-key file");
    const auto end = input.tellg();
    constexpr std::size_t expected_size = 1U << 16;
    if (end != static_cast<std::streamoff>(expected_size)) {
        throw std::runtime_error(
                "encryption private-key file must be exactly 65536 bytes");
    }
    std::vector<std::byte> key(expected_size);
    input.seekg(0);
    if (!input.read(reinterpret_cast<char *>(key.data()),
                static_cast<std::streamsize>(key.size()))) {
        throw std::runtime_error("cannot read encryption private-key file");
    }
    if (sha256_hex(key) != expected_encryption_private_key_sha256()) {
        std::fill(key.begin(), key.end(), std::byte{ 0 });
        throw std::runtime_error(
                "encryption private-key SHA-256 does not match the expected key");
    }
    return key;
}

void apply_encryption_item_xor(
        std::span<std::byte> data, std::span<const std::byte> encryption_key) {
    constexpr std::size_t kEncryptionKeySize = 1U << 16;
    if (encryption_key.size() != kEncryptionKeySize) {
        throw std::invalid_argument(
                "EncryptionItem key must be exactly 65536 bytes");
    }
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] ^= encryption_key[i & 0xffffU];
    }
}

std::vector<std::byte> derive_product_encryption_key(
        std::span<const std::byte> private_key, std::string_view snpid,
        const std::filesystem::path &product_hints_path) {
    if (snpid.empty())
        throw std::invalid_argument("cannot resolve an empty product SNPID");
    std::ifstream input(product_hints_path, std::ios::binary | std::ios::ate);
    if (!input)
        throw std::runtime_error(
                "cannot open Native Instruments ProductHints file");
    const auto end = input.tellg();
    if (end < 0)
        throw std::runtime_error(
                "cannot size Native Instruments ProductHints file");
    std::string xml(static_cast<std::size_t>(end), '\0');
    input.seekg(0);
    if (!xml.empty() &&
            !input.read(xml.data(), static_cast<std::streamsize>(xml.size()))) {
        throw std::runtime_error(
                "cannot read Native Instruments ProductHints file");
    }

    std::size_t pos = 0;
    while ((pos = xml.find("<Product", pos)) != std::string::npos) {
        const auto tag_end = xml.find('>', pos);
        const auto product_end = tag_end == std::string::npos
                                         ? std::string::npos
                                         : xml.find("</Product>", tag_end + 1);
        if (product_end == std::string::npos)
            break;
        const std::string_view product(
                xml.data() + tag_end + 1, product_end - tag_end - 1);
        // SNPID spelling isn't case-sensitive, for either hex or base36 IDs
        const auto catalog_snpid = xml_text(product, "SNPID");
        if (std::ranges::equal(
                    catalog_snpid, snpid, [](unsigned char a, unsigned char b) {
                        return std::tolower(a) == std::tolower(b);
                    })) {
            const auto specific_begin = product.find("<ProductSpecific>");
            const auto specific_end = product.find("</ProductSpecific>");
            if (specific_begin == std::string_view::npos ||
                    specific_end == std::string_view::npos ||
                    specific_end < specific_begin) {
                throw std::runtime_error(
                        "product record has no ProductSpecific section");
            }
            const auto specific = product.substr(
                    specific_begin, specific_end - specific_begin);
            const auto hu = xml_text(specific, "HU");
            const auto jdx = xml_text(specific, "JDX");
            if (hu.empty() || jdx.empty()) {
                throw std::runtime_error(
                        "product record has no HU/JDX encryption traits");
            }
            return derive_encryption_key_from_traits(private_key, hu, jdx);
        }
        pos = product_end + 10;
    }
    throw std::runtime_error(
            "no Native Instruments product record matches SNPID " +
            std::string(snpid));
}

std::vector<std::byte> derive_product_encryption_key(
        std::span<const std::byte> private_key, std::uint32_t product_id,
        const std::filesystem::path &product_hints_path) {
    return derive_product_encryption_key(
            private_key, snpid_from_product_id(product_id), product_hints_path);
}

std::vector<std::byte> derive_product_encryption_key(
        std::span<const std::byte> private_key, const NicntContainer &nicnt,
        std::string_view snpid) {
    for (const auto &product : nicnt.products) {
        if (!std::ranges::equal(
                    product.snpid, snpid, [](unsigned char a, unsigned char b) {
                        return std::tolower(a) == std::tolower(b);
                    }))
            continue;
        std::string hu;
        std::string jdx;
        for (const auto &value : product.product_specific_values) {
            if (value.kind != NicntValueKind::string)
                continue;
            if (value.name == "HU")
                hu = value.string_value;
            if (value.name == "JDX")
                jdx = value.string_value;
        }
        if (hu.empty() || jdx.empty()) {
            throw std::runtime_error(
                    "NICNT product has no HU/JDX encryption traits");
        }
        return derive_encryption_key_from_traits(private_key, hu, jdx);
    }
    throw std::runtime_error(
            "no NICNT product record matches SNPID " + std::string(snpid));
}

std::vector<LocalLibraryInfo> discover_local_libraries(
        const std::filesystem::path &instrument_path) {
    std::error_code absolute_error;
    const auto absolute_path =
            std::filesystem::absolute(instrument_path, absolute_error);
    auto directory =
            (absolute_error ? instrument_path : absolute_path).parent_path();
    for (unsigned depth = 0; depth < 5 && !directory.empty(); ++depth) {
        std::vector<LocalLibraryInfo> result;
        std::error_code error;
        std::filesystem::directory_iterator entries(directory, error);
        while (!error && entries != std::filesystem::directory_iterator{}) {
            const auto candidate = entries->path();
            auto extension = candidate.extension().string();
            std::transform(extension.begin(), extension.end(),
                    extension.begin(), [](unsigned char c) {
                        return static_cast<char>(std::tolower(c));
                    });
            if (extension == ".nicnt" && entries->is_regular_file(error)) {
                try {
                    std::ifstream input(
                            candidate, std::ios::binary | std::ios::ate);
                    const auto size = input.tellg();
                    if (size < 0)
                        throw std::runtime_error("cannot size local NICNT");
                    std::vector<std::byte> bytes(
                            static_cast<std::size_t>(size));
                    input.seekg(0);
                    if (!input.read(
                                reinterpret_cast<char *>(bytes.data()), size))
                        throw std::runtime_error("cannot read local NICNT");
                    auto metadata = parse_nicnt(bytes);
                    if (!metadata.products.empty())
                        result.push_back({ directory, std::move(metadata) });
                } catch (const std::exception &) { /* no usable local record */
                }
            }
            entries.increment(error);
        }
        if (!result.empty())
            return result;
        const auto parent = directory.parent_path();
        if (parent == directory)
            break;
        directory = parent;
    }
    return {};
}

std::vector<std::byte> derive_local_product_encryption_key(
        std::span<const std::byte> private_key,
        std::span<const LocalLibraryInfo> libraries, std::string_view snpid) {
    const NicntContainer *selected = nullptr;
    for (const auto &library : libraries)
        for (const auto &product : library.metadata.products)
            if (std::ranges::equal(product.snpid, snpid,
                        [](unsigned char a, unsigned char b) {
                            return std::tolower(a) == std::tolower(b);
                        })) {
                if (selected)
                    throw std::runtime_error("ambiguous local product SNPID");
                selected = &library.metadata;
            }
    if (!selected)
        throw std::runtime_error(
                "no local NICNT product matches SNPID " + std::string(snpid));
    return derive_product_encryption_key(private_key, *selected, snpid);
}

std::vector<std::byte> derive_local_product_encryption_key(
        std::span<const std::byte> private_key,
        std::span<const LocalLibraryInfo> libraries, std::uint32_t id) {
    return derive_local_product_encryption_key(
            private_key, libraries, snpid_from_product_id(id));
}

std::vector<std::byte> decode_protected_item(
        std::span<const std::byte> file_bytes, const ProtectedItem &item,
        std::span<const std::byte> encryption_key) {
    if (!item.uses_compression) {
        if (!item.nested_item_offset || !item.nested_item_size ||
                *item.nested_item_offset > file_bytes.size() ||
                *item.nested_item_size >
                        file_bytes.size() - *item.nested_item_offset) {
            throw std::invalid_argument(
                    "protected item has no direct nested payload");
        }
        // clang-format off
        return std::vector<std::byte>(file_bytes.begin() +
                static_cast<std::ptrdiff_t>(*item.nested_item_offset),
                file_bytes.begin() +
                static_cast<std::ptrdiff_t>(*item.nested_item_offset +
                *item.nested_item_size));
        // clang-format on
    }
    if (!item.compressed_data_offset || !item.compressed_size ||
            !item.uncompressed_size) {
        throw std::invalid_argument("protected item has no compressed payload");
    }
    const auto off = *item.compressed_data_offset;
    const auto size = static_cast<std::size_t>(*item.compressed_size);
    if (!has(file_bytes, off, size)) {
        throw std::invalid_argument("protected item payload is out of bounds");
    }
    std::vector<std::byte> compressed(
            file_bytes.begin() + static_cast<std::ptrdiff_t>(off),
            file_bytes.begin() + static_cast<std::ptrdiff_t>(off + size));
    if (item.kind == ProtectedItemKind::encryption_item &&
            item.xor_enabled.value_or(false)) {
        if (encryption_key.empty()) {
            throw std::invalid_argument(
                    "EncryptionItem requires a derived key");
        }
        apply_encryption_item_xor(compressed, encryption_key);
    }
    std::vector<std::byte> output(*item.uncompressed_size);
    const auto produced = fastlz_decompress(compressed, output);
    if (produced != output.size()) {
        throw std::runtime_error("FastLZ output size does not match "
                                 "SubtreeItem declaration (produced " +
                                 std::to_string(produced) + ", expected " +
                                 std::to_string(output.size()) + ")");
    }
    return output;
}

Document decode_and_parse_protected_item(std::span<const std::byte> file_bytes,
        const ProtectedItem &item, std::span<const std::byte> encryption_key) {
    const auto decoded =
            decode_protected_item(file_bytes, item, encryption_key);
    return parse(decoded);
}

} // namespace libnki
