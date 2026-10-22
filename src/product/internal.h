// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include "libnki/nki.h"
#include <regex>

namespace libnki::detail::product {

struct BinaryVersionNumber {
    std::uint32_t major{};
    std::uint32_t minor{};
    std::uint32_t patch{};
    std::uint32_t revision{};
    std::vector<std::string> prerelease;
    std::vector<std::string> build;
    bool valid{};
};

bool sane_version_specifier(const NicntVersionSpecifier &versions);

std::string canonical_upid(std::string_view source);

bool apply_pid_sanity(std::string_view snpid_source,
        std::string_view serial_source,
        const std::vector<NicntTargetedAuthSystemValue> &auth_systems,
        std::vector<std::uint32_t> &pid_values, std::string &normalized_serial,
        NicntAuthSystem &serial_auth,
        std::optional<std::uint32_t> &serial_snpid);

} // namespace libnki::detail::product
