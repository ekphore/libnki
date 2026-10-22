// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "libnki/nki.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <limits>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>

#include "../binary/read.h"
#include "internal.h"

namespace libnki {
using namespace detail::binary;
using namespace detail::product;

namespace detail::product {

std::uint32_t stoi_u32(const std::ssub_match &match) {
    if (!match.matched || match.length() == 0)
        return 0;
    return static_cast<std::uint32_t>(std::stoi(match.str(), nullptr, 10));
}

std::vector<std::string> split_dotted(std::string_view source) {
    std::vector<std::string> out;
    while (!source.empty()) {
        const auto dot = source.find('.');
        out.emplace_back(source.substr(0, dot));
        if (dot == std::string_view::npos)
            break;
        source.remove_prefix(dot + 1);
    }
    return out;
}

BinaryVersionNumber parse_binary_version_number(std::string_view source) {
    // try SemVer first; the legacy form also accepts separators and revision
    // suffixes
    static const std::regex semver(
            R"(^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$)");
    static const std::regex legacy(
            R"(^\s*(\d+)(?:[\.\-_/ ](\d+))?(?:[\.\-_/ ](\d+))?(?:[\.\-_/ ]*(?:\([CR]|\(RC)?(\d+)\)?)?\s*$)");
    const std::string text(source);
    std::smatch match;
    BinaryVersionNumber out;
    if (std::regex_match(text, match, semver)) {
        out.major = stoi_u32(match[1]);
        out.minor = stoi_u32(match[2]);
        out.patch = stoi_u32(match[3]);
        if (match[4].matched && match[4].length() != 0) {
            out.prerelease = split_dotted(match[4].str());
        }
        if (match[5].matched && match[5].length() != 0) {
            out.build = split_dotted(match[5].str());
        }
        out.valid = true;
    } else if (std::regex_match(text, match, legacy)) {
        out.major = stoi_u32(match[1]);
        out.minor = stoi_u32(match[2]);
        out.patch = stoi_u32(match[3]);
        out.revision = stoi_u32(match[4]);
        out.valid = true;
    }
    return out;
}

bool all_ascii_digits(std::string_view value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(),
                   [](unsigned char c) { return c >= '0' && c <= '9'; });
}

int compare_binary_version_numbers(
        const BinaryVersionNumber &lhs, const BinaryVersionNumber &rhs) {
    const std::uint32_t lhs_parts[] = { lhs.major, lhs.minor, lhs.patch };
    const std::uint32_t rhs_parts[] = { rhs.major, rhs.minor, rhs.patch };
    for (std::size_t index = 0; index < 3; ++index) {
        if (lhs_parts[index] != rhs_parts[index]) {
            return lhs_parts[index] < rhs_parts[index] ? -1 : 1;
        }
    }
    if (lhs.prerelease.empty() != rhs.prerelease.empty()) {
        return lhs.prerelease.empty() ? 1 : -1;
    }
    const auto common = std::min(lhs.prerelease.size(), rhs.prerelease.size());
    for (std::size_t index = 0; index < common; ++index) {
        const auto &left = lhs.prerelease[index];
        const auto &right = rhs.prerelease[index];
        if (left == right)
            continue;
        const bool left_numeric = all_ascii_digits(left);
        const bool right_numeric = all_ascii_digits(right);
        if (left_numeric != right_numeric)
            return left_numeric ? -1 : 1;
        if (left_numeric) {
            const auto left_value = std::stoi(left, nullptr, 10);
            const auto right_value = std::stoi(right, nullptr, 10);
            if (left_value != right_value)
                return left_value < right_value ? -1 : 1;
            continue;
        }
        return left < right ? -1 : 1;
    }
    if (lhs.prerelease.size() != rhs.prerelease.size()) {
        return lhs.prerelease.size() < rhs.prerelease.size() ? -1 : 1;
    }
    // mismatched validity states compare equal, before checking legacy
    // revisions
    if (lhs.valid != rhs.valid)
        return 0;
    if (lhs.revision != rhs.revision)
        return lhs.revision < rhs.revision ? -1 : 1;
    return 0;
}

bool sane_version_specifier(const NicntVersionSpecifier &versions) {
    if (!versions.min_version || !versions.max_version)
        return true;
    return compare_binary_version_numbers(
                   parse_binary_version_number(*versions.max_version),
                   parse_binary_version_number(*versions.min_version)) >= 0;
}

std::string canonical_upid(std::string_view source);

std::uint32_t decimal_component(const std::ssub_match &match) {
    if (!match.matched || match.length() == 0)
        return 0;
    std::uint32_t value{};
    const auto text = match.str();
    const auto result =
            std::from_chars(text.data(), text.data() + text.size(), value);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size()
                   ? value
                   : 0;
}

std::string checksum_version_string(const std::optional<std::string> &source) {
    // checksum versions use four components unless SemVer supplies a suffix
    if (!source)
        return "0.0.0.0";
    static const std::regex semver(
            R"(^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$)");
    static const std::regex legacy(
            R"(^\s*(\d+)(?:[\.\-_/ ](\d+))?(?:[\.\-_/ ](\d+))?(?:[\.\-_/ ]*(?:\([CR]|\(RC)?(\d+)\)?)?\s*$)");
    std::smatch match;
    if (std::regex_match(*source, match, semver)) {
        auto out = std::to_string(decimal_component(match[1])) + "." +
                   std::to_string(decimal_component(match[2])) + "." +
                   std::to_string(decimal_component(match[3]));
        if (match[4].matched && match[4].length() != 0) {
            out += "-" + match[4].str();
        } else if (!match[5].matched || match[5].length() == 0) {
            out += ".0";
        }
        return out;
    }
    if (std::regex_match(*source, match, legacy)) {
        return std::to_string(decimal_component(match[1])) + "." +
               std::to_string(decimal_component(match[2])) + "." +
               std::to_string(decimal_component(match[3])) + "." +
               std::to_string(decimal_component(match[4]));
    }
    return "0.0.0.0";
}

std::string canonical_upid(std::string_view source) {
    constexpr std::size_t hyphens[] = { 8, 13, 18, 23 };
    if (source.size() != 36)
        return "00000000-0000-0000-0000-000000000000";
    std::string out(source);
    for (std::size_t index = 0; index < out.size(); ++index) {
        const bool is_hyphen = std::find(std::begin(hyphens), std::end(hyphens),
                                       index) != std::end(hyphens);
        if (is_hyphen) {
            if (out[index] != '-')
                return "00000000-0000-0000-0000-000000000000";
        } else if (std::isxdigit(static_cast<unsigned char>(out[index])) != 0) {
            out[index] = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(out[index])));
        } else {
            return "00000000-0000-0000-0000-000000000000";
        }
    }
    return out;
}

std::uint32_t snpid_unsigned(std::string_view source) {
    if (source.size() > 3)
        source = source.substr(0, 3);
    if (source.empty())
        return 0;
    const bool hexadecimal = std::all_of(source.begin(), source.end(),
            [](unsigned char value) { return std::isxdigit(value) != 0; });
    std::uint32_t value = 0;
    if (hexadecimal) {
        const auto result = std::from_chars(
                source.data(), source.data() + source.size(), value, 16);
        return result.ec == std::errc{} ? value : 0;
    }
    for (unsigned char character : source) {
        character = static_cast<unsigned char>(std::toupper(character));
        std::uint32_t digit{};
        if (character >= '0' && character <= '9')
            digit = character - '0';
        else if (character >= 'A' && character <= 'Z')
            digit = character - 'A' + 10;
        else
            return 0;
        value = value * 36U + digit;
    }
    return value + 0xff0U;
}

std::string snpid_string(std::uint32_t value) {
    char buffer[16]{};
    if (value < 0x1000) {
        std::snprintf(buffer, sizeof(buffer), "%03x", value);
        return buffer;
    }
    value -= 0xff0;
    std::string out;
    do {
        const auto digit = value % 36U;
        out.push_back(
                static_cast<char>(digit < 10 ? '0' + digit : 'A' + digit - 10));
        value /= 36U;
    } while (value != 0);
    std::reverse(out.begin(), out.end());
    if (out.size() < 3)
        out.insert(out.begin(), 3 - out.size(), '0');
    return out;
}

std::set<std::uint32_t> snpid_set(std::string_view concatenated) {
    std::set<std::uint32_t> result;
    for (std::size_t offset = 0; offset + 3 <= concatenated.size();
            offset += 3) {
        result.insert(snpid_unsigned(concatenated.substr(offset, 3)));
    }
    return result;
}

struct ParsedSerialNumber {
    std::string normalized;
    NicntAuthSystem auth_system{ NicntAuthSystem::unknown };
    std::optional<std::uint32_t> snpid;
};

std::string filter_serial_ras2(std::string_view source) {
    std::string out;
    std::copy_if(source.begin(), source.end(), std::back_inserter(out),
            [](unsigned char value) {
                return std::isdigit(value) != 0 || value == '-' || value == ' ';
            });
    return out;
}

std::string filter_serial_ras3(std::string source) {
    std::transform(source.begin(), source.end(), source.begin(),
            [](unsigned char value) {
                return static_cast<char>(std::toupper(value));
            });
    std::string out;
    std::copy_if(source.begin(), source.end(), std::back_inserter(out),
            [](unsigned char value) {
                return std::isalnum(value) != 0 || value == '-';
            });
    return out;
}

ParsedSerialNumber parse_serial_number(std::string source) {
    while (!source.empty() && source.front() == ' ')
        source.erase(source.begin());
    while (!source.empty() && source.back() == ' ')
        source.pop_back();
    NicntAuthSystem auth = NicntAuthSystem::unknown;
    if (source.size() == 15 ||
            (source.size() == 28 && source.starts_with("507"))) {
        auth = NicntAuthSystem::ras0;
    } else if (source.size() == 29) {
        if (filter_serial_ras2(source).size() == 29)
            auth = NicntAuthSystem::ras2;
        else if (filter_serial_ras3(source).size() == 29)
            auth = NicntAuthSystem::ras3;
    }
    auto normalized = auth == NicntAuthSystem::ras3
                              ? filter_serial_ras3(source)
                              : filter_serial_ras2(source);
    ParsedSerialNumber out;
    out.auth_system = auth;
    out.normalized = std::move(normalized);
    if (!out.normalized.empty())
        out.snpid = snpid_unsigned(out.normalized);
    return out;
}

bool apply_pid_sanity(std::string_view snpid_source,
        std::string_view serial_source,
        const std::vector<NicntTargetedAuthSystemValue> &auth_systems,
        std::vector<std::uint32_t> &pid_values, std::string &normalized_serial,
        NicntAuthSystem &serial_auth,
        std::optional<std::uint32_t> &serial_snpid) {
    const auto parsed_serial = parse_serial_number(std::string(serial_source));
    normalized_serial = parsed_serial.normalized;
    serial_auth = parsed_serial.auth_system;
    serial_snpid = parsed_serial.snpid;
    const auto parsed_pids = snpid_set(snpid_source);
    pid_values.assign(parsed_pids.begin(), parsed_pids.end());
    if (normalized_serial.empty()) {
        return !pid_values.empty() ||
               std::none_of(auth_systems.begin(), auth_systems.end(),
                       [](const auto &item) {
                           return item.value != NicntAuthSystem::none;
                       });
    }
    if (pid_values.empty()) {
        pid_values.push_back(*serial_snpid);
        return true;
    }
    if (std::find(pid_values.begin(), pid_values.end(), *serial_snpid) ==
            pid_values.end()) {
        normalized_serial
                .clear(); // a rejected serial mustn't survive the failed check
        serial_snpid.reset();
        return false;
    }
    return true;
}

std::string pid_string(std::string_view concatenated) {
    std::string result;
    for (const auto value : snpid_set(concatenated))
        result += snpid_string(value);
    return result;
}

std::string uppercase_hex(std::uint32_t value) {
    char buffer[16]{};
    std::snprintf(buffer, sizeof(buffer), "%X", value);
    return buffer;
}

std::string normalized_serial(std::string source, NicntAuthSystem system) {
    while (!source.empty() && source.front() == ' ')
        source.erase(source.begin());
    while (!source.empty() && source.back() == ' ')
        source.pop_back();
    return system == NicntAuthSystem::ras3
                   ? filter_serial_ras3(std::move(source))
                   : filter_serial_ras2(source);
}

std::string sha1_hex(std::string_view input) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context)
        throw std::runtime_error("failed to allocate SHA-1 context");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    const bool ok =
            EVP_DigestInit_ex(context, EVP_sha1(), nullptr) == 1 &&
            EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
            EVP_DigestFinal_ex(context, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || digest_size != 20)
        throw std::runtime_error("failed to calculate SHA-1");
    constexpr char digits[] = "0123456789abcdef";
    std::string result(digest_size * 2, '0');
    for (std::size_t index = 0; index < digest_size; ++index) {
        result[index * 2] = digits[digest[index] >> 4U];
        result[index * 2 + 1] = digits[digest[index] & 0x0fU];
    }
    return result;
}

} // namespace detail::product

std::string nicnt_product_checksum_input(const NicntProductInfo &product) {
    std::string result = std::to_string(product.version);
    result += canonical_upid(product.upid);

    std::vector<std::string> components;
    components.reserve(product.auth_systems.size());
    for (const auto &auth : product.auth_systems) {
        components.push_back(
                std::to_string(static_cast<std::int32_t>(auth.value)) +
                checksum_version_string(auth.target_info.versions.min_version) +
                checksum_version_string(auth.target_info.versions.max_version));
    }
    std::sort(components.begin(), components.end());
    for (const auto &component : components)
        result += component;

    result += pid_string(product.snpid);
    // the registry-key default is empty, so only sorted serialized records add
    // bytes
    components.clear();
    components.reserve(product.reg_keys.size());
    for (const auto &reg_key : product.reg_keys) {
        components.push_back(
                reg_key.value +
                std::to_string(reg_key.target_info.platform_value));
    }
    std::sort(components.begin(), components.end());
    for (const auto &component : components)
        result += component;

    // only the first relevance/dependency collection contributes; its outer
    // version range isn't hashed
    components.clear();
    if (!product.relevance.empty()) {
        for (const auto &relevance : product.relevance.front().applications) {
            if (!relevance.auth_app_id)
                continue;
            components.push_back(
                    std::to_string(*relevance.auth_app_id) +
                    std::to_string(
                            static_cast<unsigned>(relevance.native_content)) +
                    checksum_version_string(relevance.versions.min_version) +
                    checksum_version_string(relevance.versions.max_version));
        }
    }
    std::sort(components.begin(), components.end());
    for (const auto &component : components)
        result += component;

    components.clear();
    if (!product.dependencies.empty()) {
        for (const auto &dependency :
                product.dependencies.front().applications) {
            if (!dependency.auth_app_id)
                continue;
            components.push_back(
                    std::to_string(*dependency.auth_app_id) +
                    checksum_version_string(dependency.versions.min_version) +
                    checksum_version_string(dependency.versions.max_version));
        }
    }
    std::sort(components.begin(), components.end());
    for (const auto &component : components)
        result += component;

    components.clear();
    components.reserve(product.flavours.size());
    for (const auto &flavour : product.flavours) {
        std::string component = std::to_string(flavour.flavour_value);
        for (const auto value : snpid_set(flavour.snpid))
            component += uppercase_hex(value);
        const auto auth = flavour.auth_systems.empty()
                                  ? NicntAuthSystem::none
                                  : flavour.auth_systems.front().value;
        component += std::to_string(static_cast<std::int32_t>(auth));
        component += normalized_serial(flavour.serial, auth);
        components.push_back(std::move(component));
    }
    std::sort(components.begin(), components.end());
    for (const auto &component : components)
        result += component;

    constexpr char checksum_salt[] = { '\x07', '\x01', '\x05', '\x7f', '\x05' };
    result.append(checksum_salt, sizeof(checksum_salt));
    return result;
}

std::string nicnt_product_checksum(const NicntProductInfo &product) {
    return sha1_hex(nicnt_product_checksum_input(product));
}

bool verify_nicnt_product_checksum(const NicntProductInfo &product) {
    // an absent hash bypasses checksum validation
    return product.hash.empty() ||
           nicnt_product_checksum(product) == product.hash;
}

bool nicnt_product_is_feasible(
        const NicntProductInfo &product, std::string_view engine_version) {
    const auto engine = parse_binary_version_number(engine_version);
    if (product.min_sc_version &&
            compare_binary_version_numbers(engine,
                    parse_binary_version_number(*product.min_sc_version)) < 0) {
        return false;
    }
    if (product.max_sc_version &&
            compare_binary_version_numbers(engine,
                    parse_binary_version_number(*product.max_sc_version)) > 0) {
        return false;
    }
    return true;
}

bool nicnt_product_matches_filter(
        const NicntProductInfo &product, const NicntProductFilter &filter) {
    if ((filter.product_type_mask &
                static_cast<std::uint32_t>(product.product_type)) != 0) {
        return true;
    }
    const auto product_snpids = snpid_set(product.snpid);
    for (const auto &source : filter.snpids) {
        if (product_snpids.contains(snpid_unsigned(source)))
            return true;
    }
    return false;
}

NicntProductFilter kontakt8_default_product_filter() {
    // keep the duplicate KT8 entry in the default filter
    return { 0x24U, { "KT8", "HCS", "KT8", "KP8", "K8B" } };
}

const NicntProductInfo *select_nicnt_monolith_product(
        const NicntContainer &container, std::string_view engine_version,
        const NicntProductFilter *filter) {
    for (const auto &product : container.products) {
        if (nicnt_product_is_feasible(product, engine_version) &&
                (filter == nullptr ||
                        nicnt_product_matches_filter(product, *filter)) &&
                verify_nicnt_product_checksum(product)) {
            // the first match decides even if it isn't Content, don't keep
            // looking for one
            if (product.product_type != NicntProductType::content)
                return nullptr;
            return &product;
        }
    }
    return nullptr;
}

} // namespace libnki
