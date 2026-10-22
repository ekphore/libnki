// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <libnki/nki.h>
#include <sqlite3.h>

namespace libnki {
std::optional<std::string> product_short_name(std::span<const std::byte> bytes,
        std::string_view product, std::string_view resource) {
    if (bytes.size() < 100 || bytes.size() > 32 * 1024 * 1024 ||
            product.size() > 4096 || resource.size() > 4096 ||
            std::memcmp(bytes.data(), "SQLite format 3\0", 16) != 0)
        return {};
    sqlite3 *raw{};
    const auto opened = sqlite3_open_v2(":memory:", &raw,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
            nullptr);
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db(
            raw, sqlite3_close);
    if (opened != SQLITE_OK)
        return {};
    // SQLite borrows these bytes until db closes, READONLY so it doesn't try
    // to write a journal next to a NICNT payload
    if (sqlite3_deserialize(db.get(), "main",
                reinterpret_cast<unsigned char *>(
                        const_cast<std::byte *>(bytes.data())),
                bytes.size(), bytes.size(),
                SQLITE_DESERIALIZE_READONLY) != SQLITE_OK)
        return {};
    sqlite3_limit(db.get(), SQLITE_LIMIT_LENGTH, 1024 * 1024);
    sqlite3_db_config(db.get(), SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
    sqlite3_db_config(db.get(), SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
    int work_budget = 1000;
    sqlite3_progress_handler(
            db.get(), 1000,
            [](void *value) -> int {
                return --*static_cast<int *>(value) <= 0;
            },
            &work_budget);
    sqlite3_stmt *statement{};
    if (sqlite3_prepare_v2(db.get(),
                "SELECT Value FROM shortname WHERE Location = ?1 COLLATE NOCASE "
                "AND Name = ?2 COLLATE NOCASE",
                -1, &statement, nullptr) != SQLITE_OK)
        return {};
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(
            statement, sqlite3_finalize);
    sqlite3_bind_text(statement, 1, product.data(), int(product.size()),
            SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, resource.data(), int(resource.size()),
            SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW ||
            sqlite3_column_type(statement, 0) != SQLITE_TEXT)
        return {};
    const auto size = sqlite3_column_bytes(statement, 0);
    if (size < 0 || size > 4096)
        return {};
    const auto *text = sqlite3_column_text(statement, 0);
    if (!text)
        return {};
    std::string value(reinterpret_cast<const char *>(text), size);
    // more than one matching row isn't a valid short name
    if (sqlite3_step(statement) != SQLITE_DONE)
        return {};
    return value;
}
} // namespace libnki
