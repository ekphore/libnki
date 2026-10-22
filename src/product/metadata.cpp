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
#include "../container/internal.h"
#include "internal.h"

namespace libnki {
using namespace detail::binary;
using namespace detail::product;
using detail::container::kMetadataMagic;

namespace detail::product {

bool magic_at(std::span<const std::byte> bytes, std::size_t offset,
        std::string_view magic) {
    if (offset > bytes.size() || magic.size() > bytes.size() - offset)
        return false;
    for (std::size_t i = 0; i < magic.size(); ++i) {
        if (u8(bytes, offset + i) != static_cast<std::uint8_t>(magic[i]))
            return false;
    }
    return true;
}

bool has_magic(std::span<const std::byte> bytes) {
    return magic_at(bytes, 0, kMetadataMagic);
}

std::string read_product_version(std::span<const std::byte> bytes) {
    // the version is UTF-16 at +0x42; don't read into the field at +0x80
    std::string out;
    for (std::size_t offset = 0x42; offset + 1 < 0x80; offset += 2) {
        const auto code_unit =
                static_cast<std::uint16_t>(u8(bytes, offset)) |
                static_cast<std::uint16_t>(u8(bytes, offset + 1) << 8U);
        if (code_unit == 0)
            break;
        if (code_unit > 0x7f) {
            throw std::runtime_error(
                    "non-ASCII NICNT container product version");
        }
        out.push_back(static_cast<char>(code_unit));
    }
    return out;
}

std::string_view child_text(std::string_view parent, std::string_view name) {
    const std::string open = "<" + std::string(name) + ">";
    const std::string close = "</" + std::string(name) + ">";
    const auto begin = parent.find(open);
    if (begin == std::string_view::npos)
        return {};
    const auto value_begin = begin + open.size();
    const auto end = parent.find(close, value_begin);
    if (end == std::string_view::npos)
        return {};
    return parent.substr(value_begin, end - value_begin);
}

std::optional<std::string_view> optional_child_text(
        std::string_view parent, std::string_view name) {
    const std::string open = "<" + std::string(name) + ">";
    const std::string close = "</" + std::string(name) + ">";
    const auto begin = parent.find(open);
    if (begin == std::string_view::npos)
        return std::nullopt;
    const auto value_begin = begin + open.size();
    const auto end = parent.find(close, value_begin);
    if (end == std::string_view::npos) {
        throw std::runtime_error(
                "unterminated NICNT " + std::string(name) + " element");
    }
    return parent.substr(value_begin, end - value_begin);
}

std::size_t matching_xml_close(std::string_view text, std::string_view name,
        std::size_t content_begin);

std::optional<std::string_view> optional_element_body(
        std::string_view parent, std::string_view name) {
    const std::string prefix = "<" + std::string(name);
    const auto begin = parent.find(prefix);
    if (begin == std::string_view::npos)
        return std::nullopt;
    const auto name_end = begin + prefix.size();
    if (name_end >= parent.size() ||
            (parent[name_end] != '>' && parent[name_end] != ' ' &&
                    parent[name_end] != '\t' && parent[name_end] != '\r' &&
                    parent[name_end] != '\n'))
        return std::nullopt;
    const auto open_end = parent.find('>', name_end);
    const auto end = open_end == std::string_view::npos
                             ? std::string_view::npos
                             : matching_xml_close(parent, name, open_end + 1);
    if (end == std::string_view::npos) {
        throw std::runtime_error(
                "unterminated NICNT " + std::string(name) + " element");
    }
    return parent.substr(open_end + 1, end - open_end - 1);
}

struct XmlElementView {
    std::string_view attributes;
    std::string_view body;
};

std::size_t xml_tag_end(std::string_view text, std::size_t begin) {
    char quote = 0;
    for (std::size_t pos = begin; pos < text.size(); ++pos) {
        const char character = text[pos];
        if (quote != 0) {
            if (character == quote)
                quote = 0;
        } else if (character == '\'' || character == '"') {
            quote = character;
        } else if (character == '>') {
            return pos;
        }
    }
    return std::string_view::npos;
}

std::size_t matching_xml_close(std::string_view text, std::string_view name,
        std::size_t content_begin) {
    const std::string open = "<" + std::string(name);
    const std::string close = "</" + std::string(name) + ">";
    std::size_t depth = 1;
    std::size_t pos = content_begin;
    while (true) {
        const auto close_pos = text.find(close, pos);
        if (close_pos == std::string_view::npos)
            return std::string_view::npos;
        auto open_pos = text.find(open, pos);
        while (open_pos != std::string_view::npos) {
            const auto after_name = open_pos + open.size();
            if (after_name < text.size() &&
                    std::string_view(" \t\r\n/>").find(text[after_name]) !=
                            std::string_view::npos) {
                break;
            }
            open_pos = text.find(open, after_name);
        }
        if (open_pos != std::string_view::npos && open_pos < close_pos) {
            const auto end = xml_tag_end(text, open_pos + open.size());
            if (end == std::string_view::npos)
                return std::string_view::npos;
            std::size_t before_end = end;
            while (before_end > open_pos &&
                    std::isspace(static_cast<unsigned char>(
                            text[before_end - 1])) != 0) {
                --before_end;
            }
            if (text[before_end - 1] != '/')
                ++depth;
            pos = end + 1;
        } else {
            if (--depth == 0)
                return close_pos;
            pos = close_pos + close.size();
        }
    }
}

std::vector<XmlElementView> direct_elements_named(
        std::string_view parent, std::string_view wanted_name) {
    std::vector<XmlElementView> out;
    std::size_t pos = 0;
    while ((pos = parent.find('<', pos)) != std::string_view::npos) {
        if (parent.substr(pos, 4) == "<!--") {
            const auto end = parent.find("-->", pos + 4);
            if (end == std::string_view::npos)
                throw std::runtime_error("unterminated NICNT XML comment");
            pos = end + 3;
            continue;
        }
        if (pos + 1 >= parent.size())
            break;
        if (parent[pos + 1] == '?' || parent[pos + 1] == '!') {
            const auto end = xml_tag_end(parent, pos + 2);
            if (end == std::string_view::npos)
                throw std::runtime_error("unterminated NICNT XML declaration");
            pos = end + 1;
            continue;
        }
        if (parent[pos + 1] == '/') {
            pos += 2;
            continue;
        }
        const auto name_begin = pos + 1;
        const auto name_end = parent.find_first_of(" \t\r\n/>", name_begin);
        if (name_end == std::string_view::npos || name_end == name_begin) {
            throw std::runtime_error("invalid NICNT XML child element");
        }
        const auto open_end = xml_tag_end(parent, name_end);
        if (open_end == std::string_view::npos) {
            throw std::runtime_error("unterminated NICNT XML child tag");
        }
        const auto name = parent.substr(name_begin, name_end - name_begin);
        std::size_t before_end = open_end;
        while (before_end > name_end && std::isspace(static_cast<unsigned char>(
                                                parent[before_end - 1])) != 0)
            --before_end;
        if (before_end > name_end && parent[before_end - 1] == '/') {
            if (name == wanted_name) {
                out.push_back(
                        { parent.substr(name_end, open_end - name_end), {} });
            }
            pos = open_end + 1;
            continue;
        }
        const std::string close = "</" + std::string(name) + ">";
        const auto close_begin = matching_xml_close(parent, name, open_end + 1);
        if (close_begin == std::string_view::npos) {
            throw std::runtime_error(
                    "unterminated NICNT " + std::string(name) + " element");
        }
        if (name == wanted_name) {
            out.push_back({ parent.substr(name_end, open_end - name_end),
                    parent.substr(open_end + 1, close_begin - open_end - 1) });
        }
        pos = close_begin + close.size();
    }
    return out;
}

std::optional<std::string_view> xml_attribute(
        std::string_view attributes, std::string_view name) {
    std::size_t pos = 0;
    while ((pos = attributes.find(name, pos)) != std::string_view::npos) {
        const bool left_boundary =
                pos == 0 || std::isspace(static_cast<unsigned char>(
                                    attributes[pos - 1])) != 0;
        auto cursor = pos + name.size();
        while (cursor < attributes.size() &&
                std::isspace(static_cast<unsigned char>(attributes[cursor])) !=
                        0)
            ++cursor;
        if (!left_boundary || cursor >= attributes.size() ||
                attributes[cursor] != '=') {
            pos += name.size();
            continue;
        }
        ++cursor;
        while (cursor < attributes.size() &&
                std::isspace(static_cast<unsigned char>(attributes[cursor])) !=
                        0)
            ++cursor;
        if (cursor >= attributes.size() ||
                (attributes[cursor] != '\'' && attributes[cursor] != '"')) {
            throw std::runtime_error(
                    "invalid NICNT " + std::string(name) + " attribute");
        }
        const char quote = attributes[cursor++];
        const auto end = attributes.find(quote, cursor);
        if (end == std::string_view::npos) {
            throw std::runtime_error(
                    "unterminated NICNT " + std::string(name) + " attribute");
        }
        return attributes.substr(cursor, end - cursor);
    }
    return std::nullopt;
}

NicntVersionSpecifier parse_version_specifier(std::string_view attributes) {
    NicntVersionSpecifier out;
    if (const auto value = xml_attribute(attributes, "minVersion")) {
        out.min_version = std::string(*value);
    }
    if (const auto value = xml_attribute(attributes, "maxVersion")) {
        out.max_version = std::string(*value);
    }
    return out;
}

std::optional<std::uint32_t> numeric_auth_app_id(std::string_view text) {
    std::uint32_t parsed{};
    const auto result =
            std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec == std::errc{} && result.ptr == text.data() + text.size() &&
            parsed != 0) {
        return parsed;
    }
    // checksums use these numeric IDs, but we keep the symbolic source text too
    constexpr std::pair<std::string_view, std::uint32_t> ids[] = {
        { "guitarrig", 1 },
        { "kontakt", 2 },
        { "kore", 3 },
        { "reaktor", 4 },
        { "maschine", 5 },
        { "absynth", 6 },
        { "massive", 7 },
        { "fm8", 8 },
        { "battery", 9 },
        { "kkontrol", 10 },
        { "sc", 11 },
        { "traktor", 1000 },
        { "reflektor", 12 },
        { "vc160", 13 },
        { "vc2a", 14 },
        { "vc76", 15 },
        { "transientmaster", 16 },
        { "solidbuscomp", 17 },
        { "soliddynamics", 18 },
        { "solideq", 19 },
        { "passiveeq", 20 },
        { "enhancedeq", 21 },
        { "varicomp", 22 },
        { "gainbooster", 23 },
        { "driver", 24 },
        { "rc24", 25 },
        { "rc48", 26 },
        { "supercharger", 27 },
        { "superchargergt", 28 },
        { "replika", 29 },
        { "replikaxb", 30 },
        { "massivex", 32 },
        { "catalyst", 33 },
        { "3rdparty", 500 },
    };
    for (const auto &[name, id] : ids) {
        if (text == name)
            return id;
    }
    return std::nullopt;
}

std::optional<std::uint32_t> product_family_auth_app_id(
        std::string_view family) {
    // only a space in the final three bytes strips the family suffix
    if (family.size() >= 3) {
        const auto suffix_begin = family.size() - 3;
        if (const auto separator = family.find(' ', suffix_begin);
                separator != std::string_view::npos) {
            family = family.substr(0, separator);
        }
    }
    std::string normalized(family);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
            [](unsigned char value) {
                return static_cast<char>(std::tolower(value));
            });
    return numeric_auth_app_id(normalized);
}

std::optional<NicntAuthSystem> auth_system_from_text(std::string_view text) {
    std::string lowered(text);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
            [](unsigned char value) {
                return static_cast<char>(std::tolower(value));
            });
    constexpr std::pair<std::string_view, NicntAuthSystem> systems[] = {
        { "none", NicntAuthSystem::none },
        { "ras0", NicntAuthSystem::ras0 },
        { "ras1", NicntAuthSystem::ras1 },
        { "ras1_5", NicntAuthSystem::ras1_5 },
        { "ras2", NicntAuthSystem::ras2 },
        { "ras3", NicntAuthSystem::ras3 },
    };
    for (const auto &[name, system] : systems) {
        if (lowered == name)
            return system;
    }
    return std::nullopt;
}

std::uint32_t target_mask_from_text(std::string_view text) {
    constexpr std::pair<std::string_view, std::uint32_t> targets[] = {
        { "All", 0xfff },
        { "Standalone", 1 },
        { "VST", 2 },
        { "VST64", 4 },
        { "RTAS", 8 },
        { "AU", 0x10 },
        { "AAX", 0x20 },
        { "AAX64", 0x40 },
        { "Dxi", 0x80 },
        { "VST3", 0x100 },
    };
    std::uint32_t result = 0;
    std::size_t position = 0;
    while (position < text.size()) {
        while (position < text.size() &&
                std::isspace(static_cast<unsigned char>(text[position])) != 0)
            ++position;
        const auto begin = position;
        while (position < text.size() &&
                std::isspace(static_cast<unsigned char>(text[position])) == 0)
            ++position;
        const auto token = text.substr(begin, position - begin);
        for (const auto &[name, value] : targets) {
            if (token == name) {
                result |= value;
                break;
            }
        }
    }
    return result;
}

std::uint32_t platform_value_from_text(std::string_view text) {
    std::string lowered(text);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
            [](unsigned char value) {
                return static_cast<char>(std::tolower(value));
            });
    if (lowered == "pc" || lowered == "win")
        return 1;
    if (lowered == "mac")
        return 2;
    if (lowered == "nativeos")
        return 3;
    if (lowered == "linux")
        return 4;
    return 0;
}

std::uint32_t xml_u32_attribute_or_zero(
        std::string_view attributes, std::string_view name) {
    const auto value = xml_attribute(attributes, name);
    if (!value)
        return 0;
    std::uint32_t parsed{};
    const auto result = std::from_chars(
            value->data(), value->data() + value->size(), parsed);
    return result.ec == std::errc{} ? parsed : 0;
}

std::vector<NicntProductRelevance> parse_relevance(std::string_view product) {
    std::vector<NicntProductRelevance> out;
    for (const auto &outer : direct_elements_named(product, "Relevance")) {
        NicntProductRelevance parsed;
        parsed.versions = parse_version_specifier(outer.attributes);
        if (!sane_version_specifier(parsed.versions))
            continue;
        for (const auto &child :
                direct_elements_named(outer.body, "Application")) {
            NicntAppRelevance application;
            application.versions = parse_version_specifier(child.attributes);
            if (!sane_version_specifier(application.versions))
                continue;
            application.application = std::string(child.body);
            application.auth_app_id = numeric_auth_app_id(child.body);
            if (const auto native =
                            xml_attribute(child.attributes, "nativeContent")) {
                std::string lowered(*native);
                for (auto &character : lowered) {
                    character = static_cast<char>(std::tolower(
                            static_cast<unsigned char>(character)));
                }
                application.native_content = lowered == "true";
            }
            parsed.applications.push_back(std::move(application));
        }
        out.push_back(std::move(parsed));
    }
    return out;
}

std::vector<NicntProductDependencies> parse_dependencies(
        std::string_view product) {
    std::vector<NicntProductDependencies> out;
    for (const auto &outer : direct_elements_named(product, "Dependencies")) {
        NicntProductDependencies parsed;
        parsed.versions = parse_version_specifier(outer.attributes);
        if (!sane_version_specifier(parsed.versions))
            continue;
        for (const auto &child :
                direct_elements_named(outer.body, "AppDependency")) {
            NicntAppDependency application;
            application.versions = parse_version_specifier(child.attributes);
            if (!sane_version_specifier(application.versions))
                continue;
            application.application = std::string(child.body);
            application.auth_app_id = numeric_auth_app_id(child.body);
            parsed.applications.push_back(std::move(application));
        }
        out.push_back(std::move(parsed));
    }
    return out;
}

std::optional<std::string> copied_attribute(
        std::string_view attributes, std::string_view name) {
    const auto value = xml_attribute(attributes, name);
    return value ? std::optional<std::string>(std::string(*value))
                 : std::nullopt;
}

NicntTargetInfo parse_target_info(std::string_view attributes) {
    NicntTargetInfo out;
    out.target = copied_attribute(attributes, "target");
    if (out.target)
        out.target_mask = target_mask_from_text(*out.target);
    out.versions = parse_version_specifier(attributes);
    out.platform = copied_attribute(attributes, "platform");
    if (out.platform)
        out.platform_value = platform_value_from_text(*out.platform);
    out.min_os_version_win = copied_attribute(attributes, "minOSVersionWin");
    out.max_os_version_win = copied_attribute(attributes, "maxOSVersionWin");
    out.min_os_version_mac = copied_attribute(attributes, "minOSVersionMac");
    out.max_os_version_mac = copied_attribute(attributes, "maxOSVersionMac");
    out.min_os_version_native_os =
            copied_attribute(attributes, "minOSVersionNativeOS");
    out.max_os_version_native_os =
            copied_attribute(attributes, "maxOSVersionNativeOS");
    out.min_os_version_linux =
            copied_attribute(attributes, "minOSVersionLinux");
    out.max_os_version_linux =
            copied_attribute(attributes, "maxOSVersionLinux");
    out.legacy_os_min = copied_attribute(attributes, "os_min");
    out.legacy_os_max = copied_attribute(attributes, "os_max");
    return out;
}

std::vector<NicntTargetedAuthSystemValue> parse_auth_system_property(
        std::string_view product) {
    std::vector<NicntTargetedAuthSystemValue> out;
    for (const auto &element : direct_elements_named(product, "AuthSystem")) {
        const auto translated = auth_system_from_text(element.body);
        if (!translated)
            continue;
        out.push_back({ parse_target_info(element.attributes), *translated,
                std::string(element.body) });
    }
    return out;
}

std::vector<NicntTargetedStringValue> parse_string_property(
        std::string_view product, std::string_view name) {
    std::vector<NicntTargetedStringValue> out;
    for (const auto &element : direct_elements_named(product, name)) {
        out.push_back({ parse_target_info(element.attributes),
                std::string(element.body) });
    }
    return out;
}

std::vector<NicntTargetedU32Value> parse_u32_property(
        std::string_view product, std::string_view name) {
    std::vector<NicntTargetedU32Value> out;
    for (const auto &element : direct_elements_named(product, name)) {
        std::uint32_t value{};
        const auto result = std::from_chars(element.body.data(),
                element.body.data() + element.body.size(), value);
        if (result.ec == std::errc{} &&
                result.ptr == element.body.data() + element.body.size()) {
            out.push_back({ parse_target_info(element.attributes), value });
        }
    }
    return out;
}

std::optional<NicntNksEnabled> parse_nks_enabled(std::string_view product) {
    const auto elements = direct_elements_named(product, "NKSEnabled");
    if (elements.empty())
        return std::nullopt;
    const auto &element = elements.front();
    if (element.body != "true" && element.body != "false")
        return std::nullopt;
    NicntNksEnabled out;
    out.versions = parse_version_specifier(element.attributes);
    if (!sane_version_specifier(out.versions))
        return std::nullopt;
    out.enabled = element.body == "true";
    return out;
}

std::string trimmed_xml_text(std::string_view source) {
    while (!source.empty() &&
            std::isspace(static_cast<unsigned char>(source.front())) != 0)
        source.remove_prefix(1);
    while (!source.empty() &&
            std::isspace(static_cast<unsigned char>(source.back())) != 0)
        source.remove_suffix(1);
    return std::string(source);
}

bool ascii_iequals(std::string_view left, std::string_view right) {
    if (left.size() != right.size())
        return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(left[index])) !=
                std::tolower(static_cast<unsigned char>(right[index])))
            return false;
    }
    return true;
}

NicntProductType translate_product_type(std::string_view source) {
    // "3rdparty" and "content" select the same product type
    if (ascii_iequals(source, "app"))
        return NicntProductType::app;
    if (ascii_iequals(source, "utility"))
        return NicntProductType::utility;
    if (ascii_iequals(source, "content") || ascii_iequals(source, "3rdparty")) {
        return NicntProductType::content;
    }
    if (ascii_iequals(source, "plugin"))
        return NicntProductType::plugin;
    if (ascii_iequals(source, "driver"))
        return NicntProductType::driver;
    if (ascii_iequals(source, "bundle"))
        return NicntProductType::bundle;
    return NicntProductType::unknown;
}

std::vector<NicntFactoryLibrary> parse_factory_libraries(
        std::string_view flavour) {
    std::vector<NicntFactoryLibrary> out;
    for (const auto &element :
            direct_elements_named(flavour, "FactoryLibrary")) {
        NicntFactoryLibrary item;
        item.versions = parse_version_specifier(element.attributes);
        if (!sane_version_specifier(item.versions))
            continue;
        if (const auto name = optional_child_text(element.body, "Name")) {
            item.structured = true;
            item.name = std::string(*name);
            if (item.name.empty())
                continue;
            if (const auto upid = optional_child_text(element.body, "UPID")) {
                const auto canonical = canonical_upid(*upid);
                if (canonical != "00000000-0000-0000-0000-000000000000") {
                    item.upid = canonical;
                }
            }
            item.binary_generates_random_upid = !item.upid.has_value();
            if (const auto directory =
                            optional_element_body(element.body, "Directory")) {
                item.directory = std::string(*directory);
                const auto directory_elements =
                        direct_elements_named(element.body, "Directory");
                if (!directory_elements.empty()) {
                    if (const auto mode = xml_attribute(
                                directory_elements.front().attributes, "mode");
                            mode && ascii_iequals(*mode, "registry")) {
                        if (item.directory.empty())
                            continue;
                        item.directory_mode =
                                NicntFactoryLibraryDirectoryMode::registry;
                    }
                }
            }
            item.relevance = parse_relevance(element.body);
            item.dependencies = parse_dependencies(element.body);
        } else {
            item.name = trimmed_xml_text(element.body);
            if (item.name.empty())
                continue;
        }
        // later declarations replace an existing library with the same version
        // range
        const auto duplicate =
                std::find_if(out.begin(), out.end(), [&](const auto &existing) {
                    return existing.versions.min_version ==
                                   item.versions.min_version &&
                           existing.versions.max_version ==
                                   item.versions.max_version;
                });
        if (duplicate == out.end())
            out.push_back(std::move(item));
        else
            *duplicate = std::move(item);
    }
    return out;
}

std::vector<NicntSupersessionRule> parse_supersessions(
        std::string_view flavour) {
    std::vector<NicntSupersessionRule> out;
    for (const auto &outer : direct_elements_named(flavour, "Supersession")) {
        const auto product_versions = parse_version_specifier(outer.attributes);
        if (!sane_version_specifier(product_versions))
            continue;
        for (const auto &child : direct_elements_named(outer.body, "UPID")) {
            const auto upid = canonical_upid(child.body);
            if (upid == "00000000-0000-0000-0000-000000000000")
                continue;
            const auto superseded_versions =
                    parse_version_specifier(child.attributes);
            if (!sane_version_specifier(superseded_versions))
                continue;
            out.push_back({ product_versions, upid, superseded_versions });
        }
    }
    return out;
}

std::vector<NicntProductFlavour> parse_flavours(std::string_view product) {
    std::vector<NicntProductFlavour> out;
    for (const auto &element : direct_elements_named(product, "Flavour")) {
        const auto name = optional_child_text(element.body, "Name");
        if (!name)
            continue; // a flavour needs a Name element, even if it's empty
        NicntProductFlavour flavour;
        flavour.name = std::string(*name);
        if (const auto value =
                        optional_child_text(element.body, "FlavourValue")) {
            std::int32_t parsed{};
            const auto result = std::from_chars(
                    value->data(), value->data() + value->size(), parsed);
            if (result.ec == std::errc{} &&
                    result.ptr == value->data() + value->size()) {
                flavour.flavour_value = parsed;
            }
        }
        if (const auto upgrade = optional_child_text(element.body, "Upgrade")) {
            flavour.used_upgrade_compatibility = true;
            flavour.flavour_value = *upgrade == "Yes" ? -1 : 0;
        }
        flavour.snpid = std::string(child_text(element.body, "SNPID"));
        flavour.serial = std::string(child_text(element.body, "Serial"));
        flavour.auth_systems = parse_auth_system_property(element.body);
        flavour.factory_libraries = parse_factory_libraries(element.body);
        flavour.supersessions = parse_supersessions(element.body);
        out.push_back(std::move(flavour));
    }
    return out;
}

template <typename Integer>
std::optional<Integer> optional_integer_child(
        std::string_view parent, std::string_view name) {
    const auto value = optional_child_text(parent, name);
    if (!value)
        return std::nullopt;
    Integer parsed{};
    const auto result = std::from_chars(
            value->data(), value->data() + value->size(), parsed);
    if (result.ec != std::errc{} ||
            result.ptr != value->data() + value->size()) {
        throw std::runtime_error("invalid NICNT Product " + std::string(name));
    }
    return parsed;
}

bool xml_fx_attribute(std::string_view attributes) {
    const auto value = xml_attribute(attributes, "fx");
    return value && ascii_iequals(*value, "true");
}

std::optional<std::uint32_t> parse_plugin_id_value(std::string_view source) {
    std::uint32_t value{};
    int base = 10;
    if (source.starts_with("0x")) {
        source.remove_prefix(2);
        base = 16;
    }
    if (source.empty())
        return std::nullopt;
    const auto result = std::from_chars(
            source.data(), source.data() + source.size(), value, base);
    if (result.ec != std::errc{} ||
            result.ptr != source.data() + source.size()) {
        return std::nullopt;
    }
    return value;
}

std::vector<NicntPluginId> parse_plugin_ids(std::string_view product) {
    std::vector<NicntPluginId> out;
    for (const auto &element : direct_elements_named(product, "PluginID")) {
        const auto fx = xml_fx_attribute(element.attributes);
        if (std::any_of(out.begin(), out.end(),
                    [fx](const auto &item) { return item.fx == fx; })) {
            continue;
        }
        const auto value = parse_plugin_id_value(element.body);
        if (value)
            out.push_back({ fx, *value });
    }
    return out;
}

std::optional<std::array<std::byte, 16>> parse_vst3_id_value(
        std::string_view source) {
    std::array<std::byte, 16> out{};
    std::array<std::uint8_t, 32> digits{};
    std::size_t digit_count = 0;
    const auto hex_value = [](char c) -> std::optional<std::uint8_t> {
        if (c >= '0' && c <= '9')
            return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f')
            return static_cast<std::uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F')
            return static_cast<std::uint8_t>(c - 'A' + 10);
        return std::nullopt;
    };
    for (const char c : source) {
        const auto digit = hex_value(c);
        if (!digit)
            continue;
        if (digit_count == digits.size())
            return std::nullopt;
        digits[digit_count++] = *digit;
    }
    if (digit_count != digits.size())
        return std::nullopt;
    for (std::size_t index = 0; index < out.size(); ++index) {
        out[index] =
                std::byte((digits[index * 2] << 4) | digits[index * 2 + 1]);
    }
    return out;
}

std::vector<NicntVst3Id> parse_vst3_ids(std::string_view product) {
    std::vector<NicntVst3Id> out;
    for (const auto &element : direct_elements_named(product, "VST3ID")) {
        const auto fx = xml_fx_attribute(element.attributes);
        if (std::any_of(out.begin(), out.end(),
                    [fx](const auto &item) { return item.fx == fx; })) {
            continue;
        }
        // separators don't count, but we need exactly 32 hex digits;
        // skip a malformed ID without rejecting the whole product
        const auto value = parse_vst3_id_value(element.body);
        if (value)
            out.push_back({ fx, *value });
    }
    return out;
}

std::vector<NicntProductSpecificValue> parse_product_specific(
        std::string_view product) {
    constexpr std::string_view open_section = "<ProductSpecific>";
    constexpr std::string_view close_section = "</ProductSpecific>";
    const auto section_begin = product.find(open_section);
    if (section_begin == std::string_view::npos)
        return {};
    const auto content_begin = section_begin + open_section.size();
    const auto section_end = product.find(close_section, content_begin);
    if (section_end == std::string_view::npos) {
        throw std::runtime_error("unterminated NICNT ProductSpecific element");
    }
    const auto section =
            product.substr(content_begin, section_end - content_begin);
    std::vector<NicntProductSpecificValue> out;
    std::size_t pos = 0;
    while ((pos = section.find('<', pos)) != std::string_view::npos) {
        if (pos + 1 >= section.size() || section[pos + 1] == '/' ||
                section[pos + 1] == '!' || section[pos + 1] == '?') {
            ++pos;
            continue;
        }
        const auto tag_end = section.find('>', pos + 1);
        if (tag_end == std::string_view::npos) {
            throw std::runtime_error(
                    "unterminated NICNT ProductSpecific child tag");
        }
        const auto name_end = section.find_first_of(" \t\r\n/>", pos + 1);
        if (name_end == std::string_view::npos || name_end > tag_end ||
                name_end == pos + 1) {
            throw std::runtime_error(
                    "invalid NICNT ProductSpecific child name");
        }
        const auto name = section.substr(pos + 1, name_end - pos - 1);
        const std::string close = "</" + std::string(name) + ">";
        const auto close_begin = section.find(close, tag_end + 1);
        if (close_begin == std::string_view::npos) {
            throw std::runtime_error(
                    "unterminated NICNT ProductSpecific child");
        }
        const auto attributes = section.substr(name_end, tag_end - name_end);
        const auto value =
                section.substr(tag_end + 1, close_begin - tag_end - 1);
        NicntProductSpecificValue parsed;
        parsed.name = std::string(name);
        const auto type_pos = attributes.find("type=\"");
        std::string_view type;
        if (type_pos != std::string_view::npos) {
            const auto type_begin = type_pos + 6;
            const auto type_end = attributes.find('"', type_begin);
            if (type_end == std::string_view::npos) {
                throw std::runtime_error(
                        "unterminated NICNT ProductSpecific type attribute");
            }
            type = attributes.substr(type_begin, type_end - type_begin);
        }
        if (type.empty() || type == "String") {
            parsed.kind = NicntValueKind::string;
            parsed.string_value = std::string(value);
            out.push_back(std::move(parsed));
        } else if (type == "Number") {
            parsed.kind = NicntValueKind::number;
            const auto result = std::from_chars(value.data(),
                    value.data() + value.size(), parsed.number_value);
            if (result.ec != std::errc{} ||
                    result.ptr != value.data() + value.size()) {
                throw std::runtime_error(
                        "invalid NICNT ProductSpecific Number value");
            }
            out.push_back(std::move(parsed));
        }
        pos = close_begin + close.size();
    }
    return out;
}

std::optional<NicntProductFamily> parse_product_family(
        std::string_view parent) {
    const auto body = optional_element_body(parent, "ProductFamily");
    if (!body)
        return std::nullopt;
    const auto name = optional_child_text(*body, "Name");
    if (!name)
        return std::nullopt;
    NicntProductFamily out;
    out.name = std::string(*name);
    out.version = optional_integer_child<std::uint32_t>(*body, "Version");
    return out;
}

std::optional<NicntImageRef> parse_image_ref(
        std::string_view parent, std::string_view element_name) {
    const auto body = optional_element_body(parent, element_name);
    if (!body)
        return std::nullopt;
    NicntImageRef out;
    if (const auto family = parse_product_family(*body)) {
        out.kind = NicntImageRefKind::product_family;
        out.product_family = *family;
    } else if (const auto data = optional_child_text(*body, "Data")) {
        out.kind = NicntImageRefKind::base64_data;
        out.text = std::string(*data);
    } else {
        out.kind = NicntImageRefKind::text;
        out.text = std::string(*body);
    }
    return out;
}

std::optional<std::int64_t> parse_added_at(std::string_view source) {
    std::tm value{};
    std::istringstream stream{ std::string(source) };
    stream >> std::get_time(&value, "%Y-%m-%dT%H:%M:%S");
    // keep passing partial dates to mktime; the stream state isn't checked
    const auto seconds = std::mktime(&value);
    if (seconds == static_cast<std::time_t>(-1))
        return std::nullopt;
    return static_cast<std::int64_t>(seconds) * 1000;
}

void parse_bundle_member_scope(std::string_view scope,
        std::vector<NicntBundleMemberDeclaration> *direct_members,
        std::vector<NicntBundleMemberDeclaration> &all_members) {
    const auto members = optional_element_body(scope, "Members");
    if (!members)
        return;
    for (const auto &element : direct_elements_named(*members, "Member")) {
        NicntBundleMemberDeclaration member;
        member.serial = std::string(element.body);
        if (const auto added_at =
                        xml_attribute(element.attributes, "addedAt")) {
            member.added_at = std::string(*added_at);
            member.added_at_milliseconds = parse_added_at(*added_at);
        }
        if (direct_members)
            direct_members->push_back(member);
        all_members.push_back(std::move(member));
    }
    for (const auto &bundle : direct_elements_named(*members, "Bundle")) {
        // a nested bundle needs an SNPID child before we visit its members
        if (!optional_element_body(bundle.body, "SNPID"))
            continue;
        parse_bundle_member_scope(bundle.body, nullptr, all_members);
    }
}

} // namespace detail::product

NicntProductHints parse_nicnt_product_hints(std::string_view xml) {
    NicntProductHints out;
    const auto roots = direct_elements_named(xml, "ProductHints");
    if (roots.size() != 1) {
        throw std::runtime_error(
                "NICNT reserved data has no unique ProductHints root");
    }
    if (const auto version =
                    xml_attribute(roots.front().attributes, "version")) {
        out.version = std::string(*version);
    }
    if (const auto spec = xml_attribute(roots.front().attributes, "spec")) {
        out.spec = std::string(*spec);
    }
    const auto product_elements =
            direct_elements_named(roots.front().body, "Product");
    for (std::size_t product_index = 0; product_index < product_elements.size();
            ++product_index) {
        const auto &element = product_elements[product_index];
        try {
            const auto body = element.body;
            const auto product_attributes = element.attributes;
            NicntProductInfo product;
            product.version =
                    xml_u32_attribute_or_zero(product_attributes, "version");
            if (const auto hash = xml_attribute(product_attributes, "hash")) {
                product.hash = std::string(*hash);
            }
            if (const auto min =
                            xml_attribute(product_attributes, "minSCVersion")) {
                product.min_sc_version = std::string(*min);
            }
            if (const auto max =
                            xml_attribute(product_attributes, "maxSCVersion")) {
                product.max_sc_version = std::string(*max);
            }
            product.upid = std::string(child_text(body, "UPID"));
            const auto product_name = optional_child_text(body, "Name");
            if (!product_name) {
                throw std::runtime_error(
                        "NICNT Product has no required Name element");
            }
            product.name = std::string(*product_name);
            product.type = std::string(child_text(body, "Type"));
            product.product_type = translate_product_type(product.type);
            product.internal_name =
                    std::string(child_text(body, "InternalName"));
            product.ps = std::string(child_text(body, "PS"));
            product.product_family = parse_product_family(body);
            product.company = std::string(child_text(body, "Company"));
            product.vendor = std::string(child_text(body, "Vendor"));
            product.website = std::string(child_text(body, "Website"));
            product.shop_link = std::string(child_text(body, "ShopLink"));
            product.value = optional_integer_child<std::int32_t>(body, "Value");
            product.bundle_value =
                    optional_integer_child<std::int32_t>(body, "BundleValue");
            product.scan_mode = std::string(child_text(body, "ScanMode"));
            product.bin_names = parse_string_property(body, "BinName");
            product.host_mode = std::string(child_text(body, "HostMode"));
            product.auth_app_id =
                    optional_integer_child<std::uint32_t>(body, "AuthAppID");
            if (product.product_type == NicntProductType::app ||
                    product.product_type == NicntProductType::plugin) {
                if (!product.auth_app_id && product.product_family) {
                    product.auth_app_id = product_family_auth_app_id(
                            product.product_family->name);
                }
                // accepted IDs have (value - 1) >= 0 when interpreted as S32
                if (!product.auth_app_id || *product.auth_app_id == 0 ||
                        *product.auth_app_id > 0x80000000U) {
                    throw std::runtime_error(
                            "NICNT application/plugin has invalid AuthAppID");
                }
            }
            product.plugin_ids = parse_plugin_ids(body);
            product.vst3_ids = parse_vst3_ids(body);
            product.factory_libraries = parse_factory_libraries(body);
            product.file_extension =
                    std::string(child_text(body, "FileExtension"));
            product.icon = parse_image_ref(body, "Icon");
            product.header = parse_image_ref(body, "Header");
            product.logo = parse_image_ref(body, "Logo");
            product.snpid = std::string(child_text(body, "SNPID"));
            product.serial_source_text =
                    std::string(child_text(body, "Serial"));
            product.auth_systems = parse_auth_system_property(body);
            if (!apply_pid_sanity(product.snpid, product.serial_source_text,
                        product.auth_systems, product.snpid_values,
                        product.serial, product.serial_auth_system,
                        product.serial_snpid)) {
                throw std::runtime_error(
                        "NICNT Product failed PID sanity check");
            }
            product.reg_keys = parse_string_property(body, "RegKey");
            product.visibility = parse_u32_property(body, "Visibility");
            parse_bundle_member_scope(body, &product.bundle_members,
                    product.all_bundle_member_declarations);
            if (product.product_type == NicntProductType::unknown &&
                    !product.bundle_members.empty()) {
                product.product_type = NicntProductType::bundle;
            }
            product.nks_enabled = parse_nks_enabled(body);
            product.flavours = parse_flavours(body);
            product.flavours.erase(
                    std::remove_if(product.flavours.begin(),
                            product.flavours.end(),
                            [](auto &flavour) {
                                flavour.serial_source_text = flavour.serial;
                                return !apply_pid_sanity(flavour.snpid,
                                        flavour.serial_source_text,
                                        flavour.auth_systems,
                                        flavour.snpid_values, flavour.serial,
                                        flavour.serial_auth_system,
                                        flavour.serial_snpid);
                            }),
                    product.flavours.end());
            product.relevance = parse_relevance(body);
            product.dependencies = parse_dependencies(body);
            if (product.relevance.empty() &&
                    optional_element_body(body, "PoweredBy")) {
                if (const auto engine = optional_child_text(body, "Engine")) {
                    product.engine = std::string(*engine);
                    product.engine_version =
                            std::string(child_text(body, "Version"));
                } else {
                    product.powered_by =
                            std::string(child_text(body, "PoweredBy"));
                }
            }
            product.product_specific_values = parse_product_specific(body);
            out.products.push_back(std::move(product));
        } catch (const std::exception &error) {
            // one bad product doesn't prevent us from reading the next XML node
            out.rejected_products.push_back({ product_index, error.what() });
        }
    }
    return out;
}

NicntContainer parse_nicnt(std::span<const std::byte> bytes) {
    if (bytes.size() < NicntContainer::metadata_header_size ||
            !has_magic(bytes)) {
        throw std::runtime_error("not an NI FC MTD metadata container");
    }
    NicntContainer out;
    out.product_version = read_product_version(bytes);
    out.metadata_header_kind = u32le(bytes, 0x84);
    if (out.metadata_header_kind != 1) {
        throw std::runtime_error(
                "NICNT metadata header has no supported reserved-data branch");
    }
    out.reserved_data_size = u32le(bytes, 0x90);
    out.metadata_payload_skip = u32le(bytes, 0x94);
    if (out.reserved_data_size >
            bytes.size() - NicntContainer::reserved_data_offset) {
        throw std::runtime_error("NICNT reserved-data region is truncated");
    }
    const auto reserved = bytes.subspan(
            NicntContainer::reserved_data_offset, out.reserved_data_size);
    while (out.product_hints_xml_size < reserved.size() &&
            reserved[out.product_hints_xml_size] != std::byte{ 0 }) {
        ++out.product_hints_xml_size;
    }
    const std::string_view xml(reinterpret_cast<const char *>(reserved.data()),
            out.product_hints_xml_size);
    auto product_hints = parse_nicnt_product_hints(xml);
    out.product_hints_version = std::move(product_hints.version);
    out.product_hints_spec = std::move(product_hints.spec);
    out.products = std::move(product_hints.products);
    out.rejected_products = std::move(product_hints.rejected_products);
    out.content_tocs = parse_file_container_tocs(bytes);
    if (!out.content_tocs.empty())
        out.content_toc = out.content_tocs.front();
    return out;
}

} // namespace libnki
