# CVNSS4.0 Module (MVP)

This folder is a **standalone CVNSS input module** designed to be integrated into UniKey with minimal impact:
- `cvnss::ConvertCvnWordToCqn()` converts one CVN syllable to Vietnamese (CQN).
- `cvnss::Engine` provides "type-to-replace" behavior: each typed ASCII char updates the current token and returns a `Replace` action (backspace N UTF-16 + insert new text).

## Build (Visual Studio / MSBuild)
Open `vs/cvnss.vcxproj` and build **Static Library** (Win32/x86 recommended for UniKey).

## Integration idea (later step)
In UniKey key-processing pipeline:
- If mode == CVNSS4: call `engine.ProcessChar(ch)` or `engine.Backspace()`
- If action == Replace: send backspaces, then insert UTF-16 text.
- Delimiters: UniKey handles normally; engine resets token.

## Source of mapping tables
Tables are generated from `cvnss4.0-converter.js` (uploaded with this chat). fileciteturn0file0
