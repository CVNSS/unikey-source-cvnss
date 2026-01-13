#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cvnss {

// Simple action contract for integrating into UniKey-like engines.
// MVP uses "replace" semantics: delete N UTF-16 code units, then insert `text`.
enum class ActionType : uint8_t {
    PassThrough = 0,   // let host handle the key normally
    Consumed    = 1,   // handled, no output change
    Replace     = 2    // backspace + insert text
};

struct Action {
    ActionType type{ActionType::PassThrough};
    int backspace_utf16{0};          // how many UTF-16 code units to delete
    std::u16string text;             // UTF-16 text to insert
    bool reset_context{false};       // host may reset composition context
};

// Stateless converter: CVN (ASCII) syllable -> CQN (Vietnamese, UTF-16).
// If input isn't a CVN syllable, it will best-effort return the input (UTF-16).
std::u16string ConvertCvnWordToCqn(const std::string& cvn_word);

// Stateful IME-like engine for typing CVN and displaying CQN in-place.
class Engine {
public:
    Engine() = default;

    // Feed a single UTF-32 character from keyboard (usually ASCII).
    // Delimiters (space/punct/newline) will reset internal buffer.
    Action ProcessChar(char32_t ch);

    // Handle backspace within current token.
    Action Backspace();

    void Reset();

    // Debug / telemetry (raw CVN token, current CQN preview).
    const std::string& raw_token() const { return raw_; }
    const std::u16string& preview_cqn() const { return preview_; }

private:
    static bool IsDelimiter(char32_t ch);
    static bool IsAsciiPrintable(char32_t ch);

    std::string raw_;         // CVN token being typed (ASCII)
    std::u16string preview_;  // current CQN preview (UTF-16)
};

} // namespace cvnss
