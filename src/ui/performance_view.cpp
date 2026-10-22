// SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libnki/model.h>

#include <charconv>
#include <cmath>
#include <map>
#include <stdexcept>
#include <string_view>
#include <variant>

namespace libnki {
namespace {

struct Json;
using JsonObject = std::map<std::string, Json, std::less<>>;
using JsonArray = std::vector<Json>;

struct Json {
    using Value = std::variant<std::nullptr_t, bool, double, std::string,
            JsonArray, JsonObject>;
    Value value;

    const JsonObject *object() const { return std::get_if<JsonObject>(&value); }
    const JsonArray *array() const { return std::get_if<JsonArray>(&value); }
    const std::string *string() const {
        return std::get_if<std::string>(&value);
    }
    const double *number() const { return std::get_if<double>(&value); }
    const bool *boolean() const { return std::get_if<bool>(&value); }

    const Json *get(std::string_view key) const {
        const auto *values = object();
        if (!values)
            return nullptr;
        const auto found = values->find(key);
        return found == values->end() ? nullptr : &found->second;
    }
};

class JsonParser {
  public:
    explicit JsonParser(std::string_view source) : source(source) {}

    Json parse() {
        skip_space();
        auto value = parse_value();
        skip_space();
        if (position != source.size())
            fail("trailing JSON data");
        return value;
    }

  private:
    [[noreturn]] void fail(const char *message) const {
        throw std::runtime_error(std::string("performance-view JSON at byte ") +
                                 std::to_string(position) + ": " + message);
    }

    void skip_space() {
        while (position < source.size() &&
                (source[position] == ' ' || source[position] == '\t' ||
                        source[position] == '\r' || source[position] == '\n'))
            ++position;
    }

    bool consume(const char character) {
        skip_space();
        if (position >= source.size() || source[position] != character)
            return false;
        ++position;
        return true;
    }

    Json parse_value() {
        skip_space();
        if (position >= source.size())
            fail("expected value");
        switch (source[position]) {
            case '{':
                return parse_object();
            case '[':
                return parse_array();
            case '"':
                return Json{ parse_string() };
            case 't':
                return parse_literal("true", Json{ true });
            case 'f':
                return parse_literal("false", Json{ false });
            case 'n':
                return parse_literal("null", Json{ nullptr });
            default:
                return Json{ parse_number() };
        }
    }

    Json parse_literal(const std::string_view literal, Json value) {
        if (source.substr(position, literal.size()) != literal)
            fail("invalid literal");
        position += literal.size();
        return value;
    }

    Json parse_object() {
        if (!consume('{'))
            fail("expected object");
        JsonObject result;
        if (consume('}'))
            return Json{ std::move(result) };
        for (;;) {
            skip_space();
            if (position >= source.size() || source[position] != '"')
                fail("expected object key");
            auto key = parse_string();
            if (!consume(':'))
                fail("expected ':'");
            result.insert_or_assign(std::move(key), parse_value());
            if (consume('}'))
                break;
            if (!consume(','))
                fail("expected ','");
        }
        return Json{ std::move(result) };
    }

    Json parse_array() {
        if (!consume('['))
            fail("expected array");
        JsonArray result;
        if (consume(']'))
            return Json{ std::move(result) };
        for (;;) {
            result.push_back(parse_value());
            if (consume(']'))
                break;
            if (!consume(','))
                fail("expected ','");
        }
        return Json{ std::move(result) };
    }

    static void append_utf8(std::string &target, std::uint32_t codepoint) {
        if (codepoint <= 0x7f)
            target.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7ff) {
            target.push_back(static_cast<char>(0xc0U | (codepoint >> 6)));
            target.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else {
            target.push_back(static_cast<char>(0xe0U | (codepoint >> 12)));
            target.push_back(
                    static_cast<char>(0x80U | ((codepoint >> 6) & 0x3fU)));
            target.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        }
    }

    std::string parse_string() {
        if (source[position++] != '"')
            fail("expected string");
        std::string result;
        while (position < source.size()) {
            const char character = source[position++];
            if (character == '"')
                return result;
            if (character != '\\') {
                result.push_back(character);
                continue;
            }
            if (position >= source.size())
                fail("incomplete escape");
            const char escape = source[position++];
            switch (escape) {
                case '"':
                case '\\':
                case '/':
                    result.push_back(escape);
                    break;
                case 'b':
                    result.push_back('\b');
                    break;
                case 'f':
                    result.push_back('\f');
                    break;
                case 'n':
                    result.push_back('\n');
                    break;
                case 'r':
                    result.push_back('\r');
                    break;
                case 't':
                    result.push_back('\t');
                    break;
                case 'u': {
                    if (position + 4 > source.size())
                        fail("incomplete unicode escape");
                    std::uint32_t codepoint{};
                    const auto first = source.data() + position;
                    const auto parsed =
                            std::from_chars(first, first + 4, codepoint, 16);
                    if (parsed.ec != std::errc{} || parsed.ptr != first + 4)
                        fail("invalid unicode escape");
                    position += 4;
                    append_utf8(result, codepoint);
                    break;
                }
                default:
                    fail("invalid escape");
            }
        }
        fail("unterminated string");
    }

    double parse_number() {
        const auto start = position;
        while (position < source.size()) {
            const char c = source[position];
            if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
                    c == 'e' || c == 'E')
                ++position;
            else
                break;
        }
        double value{};
        const auto parsed = std::from_chars(
                source.data() + start, source.data() + position, value);
        if (parsed.ec != std::errc{} || parsed.ptr != source.data() + position)
            fail("invalid number");
        return value;
    }

    std::string_view source;
    std::size_t position{};
};

std::int32_t integer(const Json *value, const std::int32_t fallback = 0) {
    const auto *number = value ? value->number() : nullptr;
    return number ? static_cast<std::int32_t>(std::lround(*number)) : fallback;
}

std::string string(const Json *value) {
    const auto *text = value ? value->string() : nullptr;
    return text ? *text : std::string{};
}

bool boolean(const Json *value, const bool fallback = true) {
    const auto *flag = value ? value->boolean() : nullptr;
    return flag ? *flag : fallback;
}

PerformanceViewControlInfo control(const Json &source) {
    PerformanceViewControlInfo result;
    result.type_index =
            static_cast<std::uint32_t>(integer(source.get("index")));
    const auto *value = source.get("value");
    const auto *automation = value ? value->get("automation") : nullptr;
    const auto *host_automation =
            automation ? automation->get("hostAutomation") : nullptr;
    if (host_automation && host_automation->get("on"))
        result.host_automation_on = boolean(host_automation->get("on"));
    if (host_automation && host_automation->get("id"))
        result.host_automation_id = integer(host_automation->get("id"));
    if (automation && automation->get("name"))
        result.automation_name = string(automation->get("name"));
    if (automation && automation->get("disableUserAssign"))
        result.disable_user_automation_assignment =
                boolean(automation->get("disableUserAssign"));
    const auto *common = value ? value->get("common") : nullptr;
    const auto *position = common ? common->get("position") : nullptr;
    const auto *size = common ? common->get("size") : nullptr;
    result.id = string(common ? common->get("id") : nullptr);
    result.x = integer(position ? position->get("x") : nullptr);
    result.y = integer(position ? position->get("y") : nullptr);
    result.width = integer(size ? size->get("width") : nullptr);
    result.height = integer(size ? size->get("height") : nullptr);
    result.z_layer = integer(common ? common->get("zLayer") : nullptr);
    result.show = boolean(common ? common->get("show") : nullptr);
    result.image = string(value ? value->get("image") : nullptr);
    if (result.image.empty())
        result.image = string(value ? value->get("backgroundImage") : nullptr);
    const auto *control_background = value ? value->get("background") : nullptr;
    if (result.image.empty())
        result.image =
                string(control_background ? control_background->get("image")
                                          : nullptr);
    if (control_background && control_background->get("frameIndex"))
        result.image_frame = integer(control_background->get("frameIndex"));
    const auto *colors = value ? value->get("colors") : nullptr;
    result.waveform_color = static_cast<std::uint32_t>(
            integer(colors ? colors->get("waveform") : nullptr));
    result.table_bar_color = static_cast<std::uint32_t>(
            integer(colors ? colors->get("bars") : nullptr));
    result.table_zero_color = static_cast<std::uint32_t>(
            integer(colors ? colors->get("zeroLine") : nullptr));
    const auto *steps = value ? value->get("steps") : nullptr;
    result.table_steps = integer(steps ? steps->get("total") : nullptr);
    result.table_visible_steps =
            integer(steps ? steps->get("visible") : nullptr);
    result.table_maximum = integer(value ? value->get("maxValue") : nullptr);
    result.table_bipolar =
            boolean(value ? value->get("bipolar") : nullptr, false);
    const auto *cursors = value ? value->get("cursors") : nullptr;
    if (result.type_index == 14 && cursors && cursors->array()) {
        for (const auto &cursor : *cursors->array()) {
            result.xy_cursor_images.push_back(string(cursor.get("image")));
            for (const auto *axis_name : { "x", "y" }) {
                const auto *axis = cursor.get(axis_name);
                const auto *coordinate = axis ? axis->get("value") : nullptr;
                const auto *number =
                        coordinate ? coordinate->number() : nullptr;
                result.xy_values.push_back(number ? *number : 0.0);
                PerformanceViewAxisAutomationInfo assignment;
                const auto *automation =
                        axis ? axis->get("automation") : nullptr;
                const auto *host = automation
                                           ? automation->get("hostAutomation")
                                           : nullptr;
                if (host && host->get("on"))
                    assignment.on = boolean(host->get("on"));
                if (host && host->get("id"))
                    assignment.id = integer(host->get("id"));
                if (automation && automation->get("name"))
                    assignment.name = string(automation->get("name"));
                result.xy_automation.push_back(std::move(assignment));
            }
        }
    }
    const auto *range = value ? value->get("value") : nullptr;
    if (range && range->object()) {
        if (range->get("min"))
            result.minimum = integer(range->get("min"));
        if (range->get("max"))
            result.maximum = integer(range->get("max"));
        if (range->get("default"))
            result.default_value = integer(range->get("default"));
    }
    const auto *text = value ? value->get("text") : nullptr;
    result.text = string(text ? text->get("string") : nullptr);
    result.text_alignment =
            integer(text ? text->get("horizontalAlignment") : nullptr);
    result.text_position_y = integer(text ? text->get("positionY") : nullptr);
    const auto *font = text ? text->get("font") : nullptr;
    const auto *fonts = text ? text->get("fonts") : nullptr;
    const auto *font_off = fonts ? fonts->get("off") : font;
    const auto *font_on = fonts ? fonts->get("on") : font;
    const auto authored_font_type = [](const Json *value,
                                            const int fallback = 0) {
        const auto encoded = integer(value, fallback > 0 ? fallback + 1 : 0);
        return encoded > 0 ? encoded - 1 : 0;
    };
    result.font_type_off =
            authored_font_type(font_off ? font_off->get("type") : nullptr);
    result.font_type_on = authored_font_type(
            font_on ? font_on->get("type") : nullptr, result.font_type_off);
    result.font_name_off = string(font_off ? font_off->get("custom") : nullptr);
    result.font_name_on = string(font_on ? font_on->get("custom") : nullptr);
    const auto *entries = value ? value->get("entries") : nullptr;
    if (const auto *values = entries ? entries->array() : nullptr) {
        result.menu_entries.reserve(values->size());
        for (const auto &entry : *values) {
            result.menu_entries.push_back({ string(entry.get("string")),
                    integer(entry.get("value")), boolean(entry.get("show")) });
        }
    }
    const auto *children = value ? value->get("controls") : nullptr;
    if (const auto *values = children ? children->array() : nullptr) {
        result.children.reserve(values->size());
        for (const auto &child : *values)
            result.children.push_back(control(child));
    }
    return result;
}

} // namespace

PerformanceViewInfo parse_performance_view(
        const std::span<const std::byte> bytes) {
    const std::string_view source(
            reinterpret_cast<const char *>(bytes.data()), bytes.size());
    const auto root = JsonParser(source).parse();
    const auto *value = root.get("value");
    const auto *view = value ? value->get("performanceView") : nullptr;
    if (!view || !view->object())
        throw std::runtime_error(
                "performance-view JSON has no performanceView");
    PerformanceViewInfo result;
    result.format_version =
            static_cast<std::uint32_t>(integer(root.get("formatVersion")));
    const auto *size = view->get("size");
    result.width = integer(size ? size->get("width") : nullptr, 633);
    result.height = integer(size ? size->get("height") : nullptr, 350);
    const auto *background = view->get("background");
    result.background_color = static_cast<std::uint32_t>(
            integer(background ? background->get("color") : nullptr));
    result.background_image =
            string(background ? background->get("image") : nullptr);
    if (const auto *controls = view->get("controls");
            controls && controls->array()) {
        result.controls.reserve(controls->array()->size());
        for (const auto &item : *controls->array())
            result.controls.push_back(control(item));
    }
    return result;
}

} // namespace libnki
