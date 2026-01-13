#include "cvnss/cvnss_api.h"
#include "cvnss/cvnss_tables.h"

#include <algorithm>
#include <codecvt>
#include <locale>
#include <string>
#include <unordered_map>

namespace cvnss {
namespace {

// --- UTF helpers (MVP) ---
static std::u16string Utf8ToUtf16(const std::string& s) {
#if defined(_MSC_VER)
    // codecvt is deprecated but still available in MSVC; acceptable for MVP.
#endif
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
    return conv.from_bytes(s);
}

static std::string ToLowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    }
    return s;
}

static bool StartsWith(const std::string& s, std::string_view prefix) {
    return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

// Decode first Unicode scalar from a UTF-8 string; returns U+0000 if empty/invalid.
static char32_t FirstCodepointUtf8(std::string_view s) {
    if (s.empty()) return 0;
    const unsigned char* p = (const unsigned char*)s.data();
    size_t n = s.size();
    unsigned char c0 = p[0];
    if (c0 < 0x80) return c0;
    if ((c0 & 0xE0) == 0xC0 && n >= 2) {
        return ((c0 & 0x1F) << 6) | (p[1] & 0x3F);
    }
    if ((c0 & 0xF0) == 0xE0 && n >= 3) {
        return ((c0 & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
    }
    if ((c0 & 0xF8) == 0xF0 && n >= 4) {
        return ((c0 & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
    }
    return 0;
}

// Base vowel groups (from JS baseVowels table in cvnss4.0-converter.js) fileciteturn0file0
static bool InGroup(char32_t ch, const char32_t* group) {
    for (size_t i = 0; group[i] != 0; ++i) if (group[i] == ch) return true;
    return false;
}

static char32_t GetBaseVowel(char32_t ch) {
    // "aàảãáạ"
    static constexpr char32_t g_a[]  = { U'a', U'à', U'ả', U'ã', U'á', U'ạ', 0 };
    // "ăằẳẵắặ"
    static constexpr char32_t g_aw[] = { U'ă', U'ằ', U'ẳ', U'ẵ', U'ắ', U'ặ', 0 };
    // "âầẩẫấậ"
    static constexpr char32_t g_aa[] = { U'â', U'ầ', U'ẩ', U'ẫ', U'ấ', U'ậ', 0 };
    static constexpr char32_t g_e[]  = { U'e', U'è', U'ẻ', U'ẽ', U'é', U'ẹ', 0 };
    static constexpr char32_t g_ee[] = { U'ê', U'ề', U'ể', U'ễ', U'ế', U'ệ', 0 };
    static constexpr char32_t g_i[]  = { U'i', U'ì', U'ỉ', U'ĩ', U'í', U'ị', 0 };
    static constexpr char32_t g_o[]  = { U'o', U'ò', U'ỏ', U'õ', U'ó', U'ọ', 0 };
    static constexpr char32_t g_oo[] = { U'ô', U'ồ', U'ổ', U'ỗ', U'ố', U'ộ', 0 };
    static constexpr char32_t g_ow[] = { U'ơ', U'ờ', U'ở', U'ỡ', U'ớ', U'ợ', 0 };
    static constexpr char32_t g_u[]  = { U'u', U'ù', U'ủ', U'ũ', U'ú', U'ụ', 0 };
    static constexpr char32_t g_uw[] = { U'ư', U'ừ', U'ử', U'ữ', U'ứ', U'ự', 0 };
    static constexpr char32_t g_y[]  = { U'y', U'ỳ', U'ỷ', U'ỹ', U'ý', U'ỵ', 0 };

    if (InGroup(ch, g_a))  return U'a';
    if (InGroup(ch, g_aw)) return U'ă';
    if (InGroup(ch, g_aa)) return U'â';
    if (InGroup(ch, g_e))  return U'e';
    if (InGroup(ch, g_ee)) return U'ê';
    if (InGroup(ch, g_i))  return U'i';
    if (InGroup(ch, g_o))  return U'o';
    if (InGroup(ch, g_oo)) return U'ô';
    if (InGroup(ch, g_ow)) return U'ơ';
    if (InGroup(ch, g_u))  return U'u';
    if (InGroup(ch, g_uw)) return U'ư';
    if (InGroup(ch, g_y))  return U'y';
    return ch;
}

static void ReplaceFirstCharIToY(std::string& utf8) {
    // JS mapping:
    // i: "iìỉĩíị"
    // y: "yỳỷỹýỵ"
    static const std::vector<std::string> from = { u8"i", u8"ì", u8"ỉ", u8"ĩ", u8"í", u8"ị" };
    static const std::vector<std::string> to   = { u8"y", u8"ỳ", u8"ỷ", u8"ỹ", u8"ý", u8"ỵ" };

    for (size_t k = 0; k < from.size(); ++k) {
        const auto& f = from[k];
        if (utf8.rfind(f, 0) == 0) {
            utf8 = to[k] + utf8.substr(f.size());
            return;
        }
    }
}

struct Adjusted {
    std::string cqnPad;
    std::string cqnVan;
};

static Adjusted AdjustConsonantVowel(std::string cqnPad, std::string cqnVan) {
    const char32_t first = FirstCodepointUtf8(cqnVan);
    const char32_t base = GetBaseVowel(first);

    if (cqnPad == "qu" && base == U'u') {
        cqnPad = "q";
    }
    if (cqnPad.empty() && base == U'i') {
        ReplaceFirstCharIToY(cqnVan);
    }
    if (cqnPad == "gi" && base == U'i') {
        cqnPad = "g";
    }

    // phu_am: ["ngh", "gh", "k"] -> ["ng", "g", "c"] when base vowel NOT in "ieê"
    const bool base_is_i_e_ee = (base == U'i' || base == U'e' || base == U'ê');
    if (!base_is_i_e_ee) {
        if (cqnPad == "ngh") cqnPad = "ng";
        else if (cqnPad == "gh") cqnPad = "g";
        else if (cqnPad == "k")  cqnPad = "c";
    }
    return { cqnPad, cqnVan };
}

static const std::unordered_map<std::string, size_t>& VowelIndexCvn() {
    static std::unordered_map<std::string, size_t> map;
    static bool inited = false;
    if (!inited) {
        map.reserve(tables::kVowelsCvn.size() * 2);
        for (size_t i = 0; i < tables::kVowelsCvn.size(); ++i) {
            map.emplace(std::string(tables::kVowelsCvn[i]), i);
        }
        inited = true;
    }
    return map;
}

} // namespace

std::u16string ConvertCvnWordToCqn(const std::string& cvn_word) {
    if (cvn_word.empty()) return u"";

    std::string lower = ToLowerAscii(cvn_word);

    std::string consonant;
    std::string vowelPart = lower;
    std::string cqnConsonant;

    // Find consonant (same order as JS table) fileciteturn0file0
    for (size_t i = 0; i < tables::kConsonantsCvn.size(); ++i) {
        const auto pref = tables::kConsonantsCvn[i];
        if (!pref.empty() && StartsWith(lower, pref)) {
            consonant = std::string(pref);
            cqnConsonant = std::string(tables::kConsonantsCqn[i]);
            vowelPart = lower.substr(pref.size());
            break;
        }
    }

    // Map vowel part
    std::string cqnResult = vowelPart;
    auto& vmap = VowelIndexCvn();
    auto it = vmap.find(vowelPart);
    if (it != vmap.end()) {
        size_t idx = it->second;
        cqnResult = std::string(tables::kVowelsCqn[idx]);
    }

    // Special-case from JS (kept for compatibility) fileciteturn0file0
    if (consonant == "j" && vowelPart == u8"ịa") {
        cqnConsonant = "gi";
        cqnResult = u8"ỵa";
    }

    // Adjust consonant-vowel rules
    auto adj = AdjustConsonantVowel(cqnConsonant, cqnResult);
    const std::string out = adj.cqnPad + adj.cqnVan;

    return Utf8ToUtf16(out);
}

// --- Engine ---

bool Engine::IsDelimiter(char32_t ch) {
    // treat whitespace & common punctuation as delimiters
    if (ch == U' ' || ch == U'\t' || ch == U'\r' || ch == U'\n') return true;
    switch (ch) {
        case U',':
        case U'.':
        case U';':
        case U':':
        case U'!':
        case U'?':
        case U'"':
        case U'\'':
        case U'(':
        case U')':
        case U'[':
        case U']':
        case U'{':
        case U'}':
        case U'/':
        case U'\\':
        case U'-':
        case U'_':
        case U'+':
        case U'=':
        case U'@':
        case U'#':
        case U'$':
        case U'%':
        case U'&':
        case U'*':
        case U'<':
        case U'>':
            return true;
        default:
            return false;
    }
}

bool Engine::IsAsciiPrintable(char32_t ch) {
    return (ch >= 0x20 && ch <= 0x7E);
}

Action Engine::ProcessChar(char32_t ch) {
    // Delimiter: reset token. Host will insert delimiter itself.
    if (IsDelimiter(ch)) {
        raw_.clear();
        preview_.clear();
        return Action{ ActionType::PassThrough, 0, u"", true };
    }

    // Only accept ASCII printable for MVP; otherwise pass-through.
    if (!IsAsciiPrintable(ch)) {
        return Action{ ActionType::PassThrough, 0, u"", false };
    }

    // Append
    raw_.push_back(static_cast<char>(ch));

    // Recompute preview
    std::u16string next = ConvertCvnWordToCqn(raw_);

    // Replace previous preview with next
    Action act;
    act.type = ActionType::Replace;
    act.backspace_utf16 = static_cast<int>(preview_.size());
    act.text = next;
    act.reset_context = false;

    preview_ = std::move(next);
    return act;
}

Action Engine::Backspace() {
    if (raw_.empty()) {
        return Action{ ActionType::PassThrough, 0, u"", false };
    }
    raw_.pop_back();

    std::u16string next = raw_.empty() ? u"" : ConvertCvnWordToCqn(raw_);

    Action act;
    act.type = ActionType::Replace;
    act.backspace_utf16 = static_cast<int>(preview_.size());
    act.text = next;
    act.reset_context = false;

    preview_ = std::move(next);
    return act;
}

void Engine::Reset() {
    raw_.clear();
    preview_.clear();
}

} // namespace cvnss
