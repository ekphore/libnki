// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include "libnki/nki.h"

namespace libnki::detail::container {

inline constexpr std::string_view kMetadataMagic{ "/\\ NI FC MTD  /\\" };

inline std::string utf8(std::u16string_view value) {
    std::string out;
    for (std::size_t index = 0; index < value.size(); ++index) {
        std::uint32_t codepoint = value[index];
        if (codepoint >= 0xd800U && codepoint <= 0xdbffU &&
                index + 1 < value.size() && value[index + 1] >= 0xdc00U &&
                value[index + 1] <= 0xdfffU) {
            codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) +
                        (value[++index] - 0xdc00U);
        } else if (codepoint >= 0xd800U && codepoint <= 0xdfffU) {
            codepoint = 0xfffdU;
        }
        if (codepoint <= 0x7fU)
            out.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7ffU) {
            out.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else if (codepoint <= 0xffffU) {
            out.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
            out.push_back(
                    static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
            out.push_back(
                    static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
            out.push_back(
                    static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        }
    }
    return out;
}

} // namespace libnki::detail::container
