// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include "libnki/nki.h"

namespace libnki::detail::protection {

struct ParsedAuthorizationPayload {
    std::uint32_t base_payload_version{};
    std::uint32_t payload_version{};
    std::uint32_t level{};
    std::optional<LicenseInfoPayload> license_info;
};

std::optional<ParsedAuthorizationPayload> parse_authorization_payload(
        std::span<const std::byte> bytes, std::size_t item_record,
        std::size_t auth_end, Document &doc);

std::optional<ProtectedItem> parse_protected_item(
        std::span<const std::byte> bytes, const Frame &frame,
        std::size_t frame_index, ProtectedItemKind kind, Document &doc);

} // namespace libnki::detail::protection
