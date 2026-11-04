#!/usr/bin/env bash
# tests/bin/doc-anchors.test.sh — guard for markdown heading-ANCHOR links in
# website/docs.
#
# Docusaurus validates link PATHS strictly, but a heading ANCHOR fragment
# (`#some-heading`) is governed by a separate option, `onBrokenAnchors`,
# which Docusaurus 3.x defaults to 'warn'. A fragment that points at a
# heading that does not exist therefore only WARNS in the build and still
# ships a dead anchor. This guard closes that hole: it resolves every
# fragment link in website/docs against the heading IDs the build actually
# renders and fails when a fragment matches no heading. It needs no website
# toolchain, so it runs even on a box where the Pages job is skipped.
#
# The heading IDs are the ones Docusaurus 3.10.2 renders, derived from its
# own pipeline (@docusaurus/mdx-loader :: remark/headings) and the slugger it
# calls (@docusaurus/utils :: createSlugger -> github-slugger 1.5.0), whose
# slugger() is:
#
#   text.toLowerCase().replace(regex, '').replace(/ /g, '-')
#
# so the ID is built in three steps:
#
#   1. the heading's TEXT content (inline markup removed — a code span's
#      backticks, emphasis markers and link syntax are markdown, not text),
#   2. lowercased, then every character the pinned `regex` matches is
#      DELETED, not replaced. That set is GitHub's historical punctuation
#      list PLUS the C0 control characters, so a tab or a newline in a
#      heading is deleted rather than hyphenated. A deleted character
#      sitting between two spaces therefore leaves two hyphens:
#      "MySQL / MSSQL — deferred" renders as "mysql--mssql--deferred",
#   3. each remaining SPACE (U+0020) replaced by exactly ONE hyphen.
#
# Seven rules that are easy to get wrong and are pinned here:
#   * a deleted character is deleted, not substituted — that is where the
#     double hyphen comes from;
#   * a whitespace RUN is not collapsed: the slugger replaces the space
#     character one at a time, so "a  b" is "a--b", not "a-b";
#   * a level-1 heading is the page TITLE. Docusaurus renders it as
#     <header><h1>…</h1></header> with NO id, so it is not an anchor and a
#     fragment may not point at it;
#   * lowercase is JavaScript's toLowerCase, not bash's ${var,,}: a final
#     sigma — a capital Σ preceded by a cased character and followed by
#     none — is ς (U+03C2), so "## ΟΣ" renders ος, not οσ;
#   * fenced code is tracked by the fence's CHARACTER and LENGTH: inside a
#     four-backtick block a three-backtick line is content, not a closer,
#     and only a matching fence line closes the block;
#   * an HTML comment hides its whole contents: a commented-out heading is
#     not an anchor and a commented-out link is not a link;
#   * a trailing {#id} is an EXPLICIT id, rendered verbatim instead of a
#     slug of the whole heading text, and every emitted id — explicit or
#     generated — is reserved: A, A-1, A render a, a-1, a-2.
#
# Run:
#   bash tests/bin/doc-anchors.test.sh
#
# Exits 0 when every fragment resolves (or when there is no docs tree to
# check), 1 on the first unresolved fragment. Self-contained: no network, no
# DB, no cargo, no Node. Requires bash >= 4.2 (the $'\u…' escapes in
# js_lowercase).
set -euo pipefail

# Results of heading_text and slugify, returned in a global instead of on
# stdout so the guard does not fork a subshell per heading.
TEXT_OUT=''
SLUG_OUT=''
LOWER_OUT=''

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCS_ROOT="$REPO_ROOT/website/docs"

# No docs tree -> nothing to guard -> pass. The gate's own fixture repo has no
# website/docs, and a missing tree must not read as a broken link.
if [[ ! -d $DOCS_ROOT ]]; then
  echo '=== doc anchors ==='
  echo 'no website/docs tree — nothing to check (pass)'
  exit 0
fi

# ---------------------------------------------------------------------------
# Locale: the slug rules are Unicode (lowercasing, code points). A UTF-8
# locale makes bash's ${var,,} and ${#var} Unicode-aware; without one, the
# guard would silently compute different IDs than the build does. The
# C.utf8 locale is present on every GNU/Linux image this gate runs on
# (GitHub-hosted runners included); if it is missing the guard fails loudly
# rather than grading against the wrong rules.
# ---------------------------------------------------------------------------
locale_utf8=''
for candidate in C.UTF-8 C.utf8 en_US.UTF-8 en_US.utf8; do
  if locale -a 2>/dev/null | grep -qix "$candidate"; then
    locale_utf8=$candidate
    break
  fi
done
if [[ -z $locale_utf8 ]]; then
  echo 'FAIL: no UTF-8 locale available — the anchor guard cannot compute' \
    'the heading IDs Docusaurus renders' >&2
  exit 1
fi
export LC_ALL="$locale_utf8"

# ---------------------------------------------------------------------------
# The characters github-slugger 1.5.0 DELETES.
#
# Transcribed from the pinned upstream regex (github-slugger 1.5.0,
# regex.js) as inclusive code-point ranges. The upstream set is GitHub's
# historical punctuation list: it is NOT the Unicode punctuation/symbol
# categories, so it cannot be re-derived — it is pinned here verbatim.
#
# The ASCII part (U+0000..U+007F) is handled inline below; the table below
# carries everything from U+0080 up.
#
# Regenerate with:
#   npm pack github-slugger@1.5.0 && tar xzf github-slugger-1.5.0.tgz
#   node -e 'const re = require("./package/regex.js"); /* probe every code
#   point and print the deleted ranges */'
# ---------------------------------------------------------------------------
DELETED_RANGES=(
  '7b a9' 'ab b4' 'b6 b9' 'bb bf' 'd7 d7' 'f7 f7'
  '2c2 2c5' '2d2 2df' '2e5 2eb' '2ed 2ed' '2ef 2ff' '375 375'
  '378 379' '37e 37e' '380 385' '387 387' '38b 38b' '38d 38d'
  '3a2 3a2' '3f6 3f6' '482 482' '530 530' '557 558' '55a 55f'
  '589 590' '5be 5be' '5c0 5c0' '5c3 5c3' '5c6 5c6' '5c8 5cf'
  '5eb 5ee' '5f3 60f' '61b 61f' '66a 66d' '6d4 6d4' '6dd 6de'
  '6e9 6e9' '6fd 6fe' '700 70f' '74b 74c' '7b2 7bf' '7f6 7f9'
  '7fb 7fc' '7fe 7ff' '82e 83f' '85c 85f' '86b 89f' '8b5 8b5'
  '8c8 8d2' '8e2 8e2' '964 965' '970 970' '984 984' '98d 98e'
  '991 992' '9a9 9a9' '9b1 9b1' '9b3 9b5' '9ba 9bb' '9c5 9c6'
  '9c9 9ca' '9cf 9d6' '9d8 9db' '9de 9de' '9e4 9e5' '9f2 9fb'
  '9fd 9fd' '9ff a00' 'a04 a04' 'a0b a0e' 'a11 a12' 'a29 a29'
  'a31 a31' 'a34 a34' 'a37 a37' 'a3a a3b' 'a3d a3d' 'a43 a46'
  'a49 a4a' 'a4e a50' 'a52 a58' 'a5d a5d' 'a5f a65' 'a76 a80'
  'a84 a84' 'a8e a8e' 'a92 a92' 'aa9 aa9' 'ab1 ab1' 'ab4 ab4'
  'aba abb' 'ac6 ac6' 'aca aca' 'ace acf' 'ad1 adf' 'ae4 ae5'
  'af0 af8' 'b00 b00' 'b04 b04' 'b0d b0e' 'b11 b12' 'b29 b29'
  'b31 b31' 'b34 b34' 'b3a b3b' 'b45 b46' 'b49 b4a' 'b4e b54'
  'b58 b5b' 'b5e b5e' 'b64 b65' 'b70 b70' 'b72 b81' 'b84 b84'
  'b8b b8d' 'b91 b91' 'b96 b98' 'b9b b9b' 'b9d b9d' 'ba0 ba2'
  'ba5 ba7' 'bab bad' 'bba bbd' 'bc3 bc5' 'bc9 bc9' 'bce bcf'
  'bd1 bd6' 'bd8 be5' 'bf0 bff' 'c0d c0d' 'c11 c11' 'c29 c29'
  'c3a c3c' 'c45 c45' 'c49 c49' 'c4e c54' 'c57 c57' 'c5b c5f'
  'c64 c65' 'c70 c7f' 'c84 c84' 'c8d c8d' 'c91 c91' 'ca9 ca9'
  'cb4 cb4' 'cba cbb' 'cc5 cc5' 'cc9 cc9' 'cce cd4' 'cd7 cdd'
  'cdf cdf' 'ce4 ce5' 'cf0 cf0' 'cf3 cff' 'd0d d0d' 'd11 d11'
  'd45 d45' 'd49 d49' 'd4f d53' 'd58 d5e' 'd64 d65' 'd70 d79'
  'd80 d80' 'd84 d84' 'd97 d99' 'db2 db2' 'dbc dbc' 'dbe dbf'
  'dc7 dc9' 'dcb dce' 'dd5 dd5' 'dd7 dd7' 'de0 de5' 'df0 df1'
  'df4 e00' 'e3b e3f' 'e4f e4f' 'e5a e80' 'e83 e83' 'e85 e85'
  'e8b e8b' 'ea4 ea4' 'ea6 ea6' 'ebe ebf' 'ec5 ec5' 'ec7 ec7'
  'ece ecf' 'eda edb' 'ee0 eff' 'f01 f17' 'f1a f1f' 'f2a f34'
  'f36 f36' 'f38 f38' 'f3a f3d' 'f48 f48' 'f6d f70' 'f85 f85'
  'f98 f98' 'fbd fc5' 'fc7 fff' '104a 104f' '109e 109f' '10c6 10c6'
  '10c8 10cc' '10ce 10cf' '10fb 10fb' '1249 1249' '124e 124f' '1257 1257'
  '1259 1259' '125e 125f' '1289 1289' '128e 128f' '12b1 12b1' '12b6 12b7'
  '12bf 12bf' '12c1 12c1' '12c6 12c7' '12d7 12d7' '1311 1311' '1316 1317'
  '135b 135c' '1360 137f' '1390 139f' '13f6 13f7' '13fe 1400' '166d 166e'
  '1680 1680' '169b 169f' '16eb 16ed' '16f9 16ff' '170d 170d' '1715 171f'
  '1735 173f' '1754 175f' '176d 176d' '1771 1771' '1774 177f' '17d4 17d6'
  '17d8 17db' '17de 17df' '17ea 180a' '180e 180f' '181a 181f' '1879 187f'
  '18ab 18af' '18f6 18ff' '191f 191f' '192c 192f' '193c 1945' '196e 196f'
  '1975 197f' '19ac 19af' '19ca 19cf' '19da 19ff' '1a1c 1a1f' '1a5f 1a5f'
  '1a7d 1a7e' '1a8a 1a8f' '1a9a 1aa6' '1aa8 1aaf' '1ac1 1aff' '1b4c 1b4f'
  '1b5a 1b6a' '1b74 1b7f' '1bf4 1bff' '1c38 1c3f' '1c4a 1c4c' '1c7e 1c7f'
  '1c89 1c8f' '1cbb 1cbc' '1cc0 1ccf' '1cd3 1cd3' '1cfb 1cff' '1dfa 1dfa'
  '1f16 1f17' '1f1e 1f1f' '1f46 1f47' '1f4e 1f4f' '1f58 1f58' '1f5a 1f5a'
  '1f5c 1f5c' '1f5e 1f5e' '1f7e 1f7f' '1fb5 1fb5' '1fbd 1fbd' '1fbf 1fc1'
  '1fc5 1fc5' '1fcd 1fcf' '1fd4 1fd5' '1fdc 1fdf' '1fed 1ff1' '1ff5 1ff5'
  '1ffd 203e' '2041 2053' '2055 2070' '2072 207e' '2080 208f' '209d 20cf'
  '20f1 2101' '2103 2106' '2108 2109' '2114 2114' '2116 2118' '211e 2123'
  '2125 2125' '2127 2127' '2129 2129' '212e 212e' '213a 213b' '2140 2144'
  '214a 214d' '214f 215f' '2189 24b5' '24ea 2bff' '2c2f 2c2f' '2c5f 2c5f'
  '2ce5 2cea' '2cf4 2cff' '2d26 2d26' '2d28 2d2c' '2d2e 2d2f' '2d68 2d6e'
  '2d70 2d7e' '2d97 2d9f' '2da7 2da7' '2daf 2daf' '2db7 2db7' '2dbf 2dbf'
  '2dc7 2dc7' '2dcf 2dcf' '2dd7 2dd7' '2ddf 2ddf' '2e00 2e2e' '2e30 3004'
  '3008 3020' '3030 3030' '3036 3037' '303d 3040' '3097 3098' '309b 309c'
  '30a0 30a0' '30fb 30fb' '3100 3104' '3130 3130' '318f 319f' '31c0 31ef'
  '3200 33ff' '4dc0 4dff' '9ffd 9fff' 'a48d a4cf' 'a4fe a4ff' 'a60d a60f'
  'a62c a63f' 'a673 a673' 'a67e a67e' 'a6f2 a716' 'a720 a721' 'a789 a78a'
  'a7c0 a7c1' 'a7cb a7f4' 'a828 a82b' 'a82d a83f' 'a874 a87f' 'a8c6 a8cf'
  'a8da a8df' 'a8f8 a8fa' 'a8fc a8fc' 'a92e a92f' 'a954 a95f' 'a97d a97f'
  'a9c1 a9ce' 'a9da a9df' 'a9ff a9ff' 'aa37 aa3f' 'aa4e aa4f' 'aa5a aa5f'
  'aa77 aa79' 'aac3 aada' 'aade aadf' 'aaf0 aaf1' 'aaf7 ab00' 'ab07 ab08'
  'ab0f ab10' 'ab17 ab1f' 'ab27 ab27' 'ab2f ab2f' 'ab5b ab5b' 'ab6a ab6f'
  'abeb abeb' 'abee abef' 'abfa abff' 'd7a4 d7af' 'd7c7 d7ca' 'd7fc f8ff'
  'fa6e fa6f' 'fada faff' 'fb07 fb12' 'fb18 fb1c' 'fb29 fb29' 'fb37 fb37'
  'fb3d fb3d' 'fb3f fb3f' 'fb42 fb42' 'fb45 fb45' 'fbb2 fbd2' 'fd3e fd4f'
  'fd90 fd91' 'fdc8 fdef' 'fdfc fdff' 'fe10 fe1f' 'fe30 fe32' 'fe35 fe4c'
  'fe50 fe6f' 'fe75 fe75' 'fefd ff0f' 'ff1a ff20' 'ff3b ff3e' 'ff40 ff40'
  'ff5b ff65' 'ffbf ffc1' 'ffc8 ffc9' 'ffd0 ffd1' 'ffd8 ffd9' 'ffdd ffff'
  '1000c 1000c' '10027 10027' '1003b 1003b' '1003e 1003e' '1004e 1004f' '1005e 1007f'
  '100fb 1013f' '10175 101fc' '101fe 1027f' '1029d 1029f' '102d1 102df' '102e1 102ff'
  '10320 1032c' '1034b 1034f' '1037b 1037f' '1039e 1039f' '103c4 103c7' '103d0 103d0'
  '103d6 103ff' '1049e 1049f' '104aa 104af' '104d4 104d7' '104fc 104ff' '10528 1052f'
  '10564 105ff' '10737 1073f' '10756 1075f' '10768 107ff' '10806 10807' '10809 10809'
  '10836 10836' '10839 1083b' '1083d 1083e' '10856 1085f' '10877 1087f' '1089f 108df'
  '108f3 108f3' '108f6 108ff' '10916 1091f' '1093a 1097f' '109b8 109bd' '109c0 109ff'
  '10a04 10a04' '10a07 10a0b' '10a14 10a14' '10a18 10a18' '10a36 10a37' '10a3b 10a3e'
  '10a40 10a5f' '10a7d 10a7f' '10a9d 10abf' '10ac8 10ac8' '10ae7 10aff' '10b36 10b3f'
  '10b56 10b5f' '10b73 10b7f' '10b92 10bff' '10c49 10c7f' '10cb3 10cbf' '10cf3 10cff'
  '10d28 10d2f' '10d3a 10e7f' '10eaa 10eaa' '10ead 10eaf' '10eb2 10eff' '10f1d 10f26'
  '10f28 10f2f' '10f51 10faf' '10fc5 10fdf' '10ff7 10fff' '11047 11065' '11070 1107e'
  '110bb 110cf' '110e9 110ef' '110fa 110ff' '11135 11135' '11140 11143' '11148 1114f'
  '11174 11175' '11177 1117f' '111c5 111c8' '111cd 111cd' '111db 111db' '111dd 111ff'
  '11212 11212' '11238 1123d' '1123f 1127f' '11287 11287' '11289 11289' '1128e 1128e'
  '1129e 1129e' '112a9 112af' '112eb 112ef' '112fa 112ff' '11304 11304' '1130d 1130e'
  '11311 11312' '11329 11329' '11331 11331' '11334 11334' '1133a 1133a' '11345 11346'
  '11349 1134a' '1134e 1134f' '11351 11356' '11358 1135c' '11364 11365' '1136d 1136f'
  '11375 113ff' '1144b 1144f' '1145a 1145d' '11462 1147f' '114c6 114c6' '114c8 114cf'
  '114da 1157f' '115b6 115b7' '115c1 115d7' '115de 115ff' '11641 11643' '11645 1164f'
  '1165a 1167f' '116b9 116bf' '116ca 116ff' '1171b 1171c' '1172c 1172f' '1173a 117ff'
  '1183b 1189f' '118ea 118fe' '11907 11908' '1190a 1190b' '11914 11914' '11917 11917'
  '11936 11936' '11939 1193a' '11944 1194f' '1195a 1199f' '119a8 119a9' '119d8 119d9'
  '119e2 119e2' '119e5 119ff' '11a3f 11a46' '11a48 11a4f' '11a9a 11a9c' '11a9e 11abf'
  '11af9 11bff' '11c09 11c09' '11c37 11c37' '11c41 11c4f' '11c5a 11c71' '11c90 11c91'
  '11ca8 11ca8' '11cb7 11cff' '11d07 11d07' '11d0a 11d0a' '11d37 11d39' '11d3b 11d3b'
  '11d3e 11d3e' '11d48 11d4f' '11d5a 11d5f' '11d66 11d66' '11d69 11d69' '11d8f 11d8f'
  '11d92 11d92' '11d99 11d9f' '11daa 11edf' '11ef7 11faf' '11fb1 11fff' '1239a 123ff'
  '1246f 1247f' '12544 12fff' '1342f 143ff' '14647 167ff' '16a39 16a3f' '16a5f 16a5f'
  '16a6a 16acf' '16aee 16aef' '16af5 16aff' '16b37 16b3f' '16b44 16b4f' '16b5a 16b62'
  '16b78 16b7c' '16b90 16e3f' '16e80 16eff' '16f4b 16f4e' '16f88 16f8e' '16fa0 16fdf'
  '16fe2 16fe2' '16fe5 16fef' '16ff2 16fff' '187f8 187ff' '18cd6 18cff' '18d09 1afff'
  '1b11f 1b14f' '1b153 1b163' '1b168 1b16f' '1b2fc 1bbff' '1bc6b 1bc6f' '1bc7d 1bc7f'
  '1bc89 1bc8f' '1bc9a 1bc9c' '1bc9f 1d164' '1d16a 1d16c' '1d173 1d17a' '1d183 1d184'
  '1d18c 1d1a9' '1d1ae 1d241' '1d245 1d3ff' '1d455 1d455' '1d49d 1d49d' '1d4a0 1d4a1'
  '1d4a3 1d4a4' '1d4a7 1d4a8' '1d4ad 1d4ad' '1d4ba 1d4ba' '1d4bc 1d4bc' '1d4c4 1d4c4'
  '1d506 1d506' '1d50b 1d50c' '1d515 1d515' '1d51d 1d51d' '1d53a 1d53a' '1d53f 1d53f'
  '1d545 1d545' '1d547 1d549' '1d551 1d551' '1d6a6 1d6a7' '1d6c1 1d6c1' '1d6db 1d6db'
  '1d6fb 1d6fb' '1d715 1d715' '1d735 1d735' '1d74f 1d74f' '1d76f 1d76f' '1d789 1d789'
  '1d7a9 1d7a9' '1d7c3 1d7c3' '1d7cc 1d7cd' '1d800 1d9ff' '1da37 1da3a' '1da6d 1da74'
  '1da76 1da83' '1da85 1da9a' '1daa0 1daa0' '1dab0 1dfff' '1e007 1e007' '1e019 1e01a'
  '1e022 1e022' '1e025 1e025' '1e02b 1e0ff' '1e12d 1e12f' '1e13e 1e13f' '1e14a 1e14d'
  '1e14f 1e2bf' '1e2fa 1e7ff' '1e8c5 1e8cf' '1e8d7 1e8ff' '1e94c 1e94f' '1e95a 1edff'
  '1ee04 1ee04' '1ee20 1ee20' '1ee23 1ee23' '1ee25 1ee26' '1ee28 1ee28' '1ee33 1ee33'
  '1ee38 1ee38' '1ee3a 1ee3a' '1ee3c 1ee41' '1ee43 1ee46' '1ee48 1ee48' '1ee4a 1ee4a'
  '1ee4c 1ee4c' '1ee50 1ee50' '1ee53 1ee53' '1ee55 1ee56' '1ee58 1ee58' '1ee5a 1ee5a'
  '1ee5c 1ee5c' '1ee5e 1ee5e' '1ee60 1ee60' '1ee63 1ee63' '1ee65 1ee66' '1ee6b 1ee6b'
  '1ee73 1ee73' '1ee78 1ee78' '1ee7d 1ee7d' '1ee7f 1ee7f' '1ee8a 1ee8a' '1ee9c 1eea0'
  '1eea4 1eea4' '1eeaa 1eeaa' '1eebc 1f12f' '1f14a 1f14f' '1f16a 1f16f' '1f18a 1fbef'
  '1fbfa 1ffff' '2a6de 2a6ff' '2b735 2b73f' '2b81e 2b81f' '2cea2 2ceaf' '2ebe1 2f7ff'
  '2fa1e 2ffff' '3134b e00ff' 'e01f0 10ffff'
)

# The printable ASCII characters the upstream regex deletes are matched
# directly in is_deleted_cp below: ' ' (0x20) is NOT among them, because it
# is the separator that becomes the hyphen.

# Is this code point deleted by github-slugger?
is_deleted_cp() {
  local cp=$1 ch=$2 lo hi mid rlo rhi
  if (( cp < 0x80 )); then
    # The C0 controls (0x00-0x1F) and DEL (0x7F) are deleted by the upstream
    # regex. They are matched on the CHARACTER: a decimal code point never
    # matches a character range, so "9" (TAB) would otherwise survive.
    case $ch in
      [$'\x01'-$'\x1f'] | $'\x7f') return 0 ;;  # controls
    esac
    if (( cp == 0 )); then
      return 0                                # NUL
    fi
    # The printable ASCII punctuation, matched on the CHARACTER. ' ' (0x20)
    # is deliberately absent: it is the separator that becomes the hyphen.
    # '-' (0x2D) is deliberately absent too: the upstream regex deletes
    # "!," (0x21-0x2C) and then "." (0x2E) and "/" (0x2F) separately, so a
    # hyphen in "db-mcp-gateway" SURVIVES into the heading ID.
    case $ch in
      ['!'-,] | '.' | '/' | [':'-@] | ['['-\^] | '`' | ['{'-\~]) return 0 ;;
    esac
    return 1
  fi
  # Binary search over the range table (sorted, non-overlapping).
  lo=0
  hi=$((${#DELETED_RANGES[@]} - 1))
  while (( lo <= hi )); do
    mid=$(( (lo + hi) / 2 ))
    read -r rlo rhi <<<"${DELETED_RANGES[mid]}"
    rlo=$((16#$rlo))
    rhi=$((16#$rhi))
    if (( cp < rlo )); then
      hi=$((mid - 1))
    elif (( cp > rhi )); then
      lo=$((mid + 1))
    else
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# JavaScript-compatible lowercase, in LOWER_OUT.
#
# github-slugger lowercases with str.toLowerCase(), and JavaScript's
# toLowerCase is not bash's ${var,,}: it applies Unicode SpecialCasing, so
# a capital sigma (Σ) preceded by a cased character and followed by none
# becomes the FINAL form ς (U+03C2), while bash only ever produces the
# plain form σ (U+03C3) — "## ΟΣ" renders ος, not οσ. The only other
# unconditional multichar lowercase mapping is Turkish İ, which JavaScript
# maps to i + U+0307 and bash to a bare i; it is replaced first so the
# per-character pipeline never sees it. The sigma context is read on the
# original string, and case-ignorable characters between the sigma and its
# neighbour are not skipped, so such a heading degrades to the plain form,
# never to a wrong final form. Every other mapping is one code point to one
# code point, so ${var,,} already matches and the sigma pass only runs
# when a Σ is present at all.
# ---------------------------------------------------------------------------
js_lowercase() {
  local dotted=$'i\u0307'
  local src=${1//İ/"$dotted"}
  local out=${src,,}
  if [[ $1 != *Σ* ]]; then
    LOWER_OUT=$out
    return 0
  fi
  local -i i n=${#src}
  for (( i = 0; i < n; i++ )); do
    [[ ${src:i:1} == Σ ]] || continue
    # Final: a cased character precedes and none follows. [[:alpha:]]
    # approximates "cased" — the scripts it wrongly calls cased (Han, kana)
    # never sit next to a Greek sigma in these docs.
    if (( i == 0 )); then continue; fi
    if [[ ${src:i-1:1} != [[:alpha:]] ]]; then continue; fi
    if (( i < n - 1 )) && [[ ${src:i+1:1} == [[:alpha:]] ]]; then continue; fi
    # ${src,,} maps Σ to σ in place, so the sigma sits at the same index.
    out=${out:0:i}ς${out:i+1}
  done
  LOWER_OUT=$out
}

# ---------------------------------------------------------------------------
# slugify <text> -> the heading ID Docusaurus renders for that text.
#
# The result is returned in SLUG_OUT rather than on stdout: a command
# substitution would fork a subshell per heading, and the guard runs over
# every heading of every doc.
#
# Lowercase (JavaScript rules — js_lowercase), delete the deleted set, then
# one hyphen per SPACE (U+0020) —
# one hyphen per space character, so a run of N spaces becomes N hyphens.
# A deleted character is deleted, NOT replaced: "MySQL / MSSQL — deferred"
# keeps the two spaces that surrounded the slash and the em dash, so it
# renders as "mysql--mssql--deferred".
# ---------------------------------------------------------------------------
slugify() {
  js_lowercase "$1"
  local text=$LOWER_OUT
  local out='' i ch cp
  local -i len=${#text}
  # Fast path: an all-ASCII heading needs no code-point scan. The ASCII
  # deletions are a fixed set of characters, so they can be removed with
  # parameter expansion in one pass per character class.
  if [[ $text == *[!$'\x20'-$'\x7e']* ]]; then
    # Contains a non-ASCII character (or a control): use the general path.
    :
  else
    # Delete the printable ASCII punctuation the upstream regex deletes:
    # "!," (0x21-0x2C) and "." and "/" and ":-@" and "[-^" and "`" and
    # "{-~". '-' (0x2D) is NOT deleted, and ' ' becomes a hyphen.
    # The list is written out so no globbing or word splitting can touch it.
    local p
    for p in '!' '"' '#' '$' '%' '&' "'" '(' ')' '*' '+' ',' '.' '/' ':' ';' \
             '<' '=' '>' '?' '@' '[' '\' ']' '^' '`' '{' '|' '}' '~'; do
      text=${text//"$p"/}
    done
    text=${text// /-}
    SLUG_OUT=$text
    return 0
  fi
  for (( i = 0; i < len; i++ )); do
    ch=${text:i:1}
    printf -v cp '%d' "'$ch"
    if (( cp == 32 )); then
      out+='-'
      continue
    fi
    if is_deleted_cp "$cp" "$ch"; then
      continue
    fi
    out+=$ch
  done
  SLUG_OUT=$out
}

# ---------------------------------------------------------------------------
# heading_text <raw heading> -> the heading's TEXT content, in TEXT_OUT.
#
# The result is returned in TEXT_OUT rather than on stdout, for the same
# reason as slugify: one fork per heading is one fork too many.
#
# Docusaurus takes the heading's text content: markdown markers are syntax,
# not text. This strips the inline constructs that appear in website/docs:
#   `code`      -> code
#   **bold**    -> bold
#   *italic*    -> italic
#   [text](url) -> text
#   ![alt](url) -> alt
#   \*          -> *
# ---------------------------------------------------------------------------
heading_text() {
  local s=$1 out='' rest label target
  local tick='`'
  local -i i n
  while [[ -n $s ]]; do
    n=${#s}
    # Find the earliest markup character that starts a construct.
    i=-1
    for cand in "$tick" '![' '[' '\' '<' '*' '_'; do
      local pos=${s%%"$cand"*}
      if [[ $pos != "$s" ]]; then
        local -i p=${#pos}
        if (( i < 0 || p < i )); then i=$p; fi
      fi
    done
    if (( i < 0 )); then
      out+=$s
      break
    fi
    out+=${s:0:i}
    rest=${s:i}
    case $rest in
      # A code span: its content is literal, so nothing inside it is markup.
      # The text before the span is kept and the span's content is kept as
      # text; only the backticks themselves are syntax.
      "$tick"*)
        rest=${rest:1}
        out+=${rest%%"$tick"*}
        if [[ $rest == *"$tick"* ]]; then
          s=${rest#*"$tick"}
        else
          s=''
        fi
        ;;
      # An image: ![alt](target) -> alt
      '!['*)
        rest=${rest:2}
        label=${rest%%\]*}
        if [[ $rest == *']('* ]]; then
          target=${rest#*']('}
          out+=$label
          s=${target#*')}
        else
          out+='!['$label
          s=$rest
        fi
        ;;
      # A link: [label](target) -> label
      '['*)
        rest=${rest:1}
        label=${rest%%\]*}
        if [[ $rest == *']('* ]]; then
          target=${rest#*']('}
          out+=$label
          s=${target#*')}
        else
          out+=$label
          s=$rest
        fi
        ;;
      # A backslash escape: the escaped character is literal text.
      '\'*)
        rest=${rest:1}
        out+=${rest:0:1}
        s=${rest:1}
        ;;
      # Inline HTML / MDX expressions are not heading text.
      '<'*)
        rest=${rest:1}
        if [[ $rest == *'>'* ]]; then
          s=${rest#*'>'}
        else
          s=''
        fi
        ;;
      # A '*' is emphasis or strong syntax, never text. The slugger deletes
      # '*' anyway, so dropping the marker changes nothing downstream.
      '*'*)
        s=${rest:1}
        ;;
      # A '_' is only a marker at a WORD BOUNDARY: CommonMark leaves an
      # intraword '_' literal, and the slugger KEEPS '_' (unlike '*'), so
      # "run_query" must keep its underscore. Drop a '_' that opens or
      # closes emphasis, keep every other one.
      '_'*)
        rest=${rest:1}
        prev=${out: -1}
        next=${rest:0:1}
        if [[ -z $prev || $prev == [[:space:]] || $prev == '*' || $prev == '_' \
           || $prev == '(' || $prev == '[' || $prev == "$tick" ]]; then
          # Left-flanking: an opening marker.
          s=$rest
        elif [[ -z $next || $next == [[:space:]] || $next == '*' || $next == '_' \
           || $next == ')' || $next == ']' || $next == "$tick" ]]; then
          # Right-flanking: a closing marker.
          s=$rest
        else
          # Intraword: literal text.
          out+='_'
          s=$rest
        fi
        ;;
      *)
        out+=$rest
        s=''
        ;;
    esac
  done
  TEXT_OUT=$out
}

# ---------------------------------------------------------------------------
# One shared line scanner for heading_ids and fragment_links. One call per
# line, in file order; it tracks the two constructs that hide markdown from
# the renderer — fenced code blocks and HTML comments — and leaves the text
# the renderer still sees for this line in CONTENT_OUT (empty for a line
# inside a fence or comment).
#
# A fence is tracked by its CHARACTER and LENGTH: inside a four-backtick
# block a three-backtick line is CONTENT (a fenced example), not a closer,
# and a fence only closes on its own character, at least as many of them,
# with nothing else on the line. A fence opens only at the start of a line.
# ---------------------------------------------------------------------------

scan_reset() {
  SCAN_FENCE=0 SCAN_FENCE_CHAR='' SCAN_FENCE_LEN=0 SCAN_COMMENT=0
}

scan_step() {
  local s=$1 out='' re
  CONTENT_OUT=''
  if (( SCAN_FENCE )); then
    # A closing fence: the opening character, at least the opening length,
    # then nothing but whitespace.
    re='^[[:space:]]*('
    re+=$SCAN_FENCE_CHAR
    re+='{3,})[[:space:]]*$'
    if [[ $s =~ $re ]] && (( ${#BASH_REMATCH[1]} >= SCAN_FENCE_LEN )); then
      SCAN_FENCE=0
    fi
    return 0
  fi
  # A fence opens only at the start of the line: a ``` that follows text on
  # the same line is an inline run of backticks, not a fence.
  if [[ $s =~ ^[[:space:]]*(\`{3,}) ]]; then
    SCAN_FENCE=1 SCAN_FENCE_CHAR='`' SCAN_FENCE_LEN=${#BASH_REMATCH[1]}
    return 0
  fi
  if [[ $s =~ ^[[:space:]]*(\~{3,}) ]]; then
    SCAN_FENCE=1 SCAN_FENCE_CHAR='~' SCAN_FENCE_LEN=${#BASH_REMATCH[1]}
    return 0
  fi
  while [[ -n $s ]]; do
    if (( SCAN_COMMENT )); then
      if [[ $s != *'-->'* ]]; then
        return 0                  # the rest of the line is commented out
      fi
      s=${s#*'-->'}
      SCAN_COMMENT=0
      continue
    fi
    if [[ $s == *'<!--'* ]]; then
      out+=${s%%'<!--'*}
      s=${s#*'<!--'}
      SCAN_COMMENT=1
      continue
    fi
    out+=$s
    break
  done
  CONTENT_OUT=$out
}

# ---------------------------------------------------------------------------
# Heading IDs of one markdown file, one per line.
#
# Fenced code and HTML comments are skipped (scan_step): a '#' line inside a
# shell snippet is not a heading, and a commented-out heading is never
# rendered. Level-1 headings are skipped too: they are the page title,
# which the theme renders without an id.
# ---------------------------------------------------------------------------
heading_ids() {
  local file=$1 line text level slug id base
  local -A seen=()
  local -i n
  scan_reset
  while IFS= read -r line || [[ -n $line ]]; do
    scan_step "$line"
    [[ $CONTENT_OUT =~ ^(#{1,6})(\ |$) ]] || continue
    level=${BASH_REMATCH[1]}
    text=${CONTENT_OUT#"$level"}
    # Strip the space the ATX heading requires.
    text=${text# }
    # Level 1 is the page title: Docusaurus renders <h1> without an id.
    [[ $level == '#' ]] && continue
    # An explicit id: Docusaurus strips a trailing {#id} from the heading
    # BEFORE slugging and renders that id verbatim, so the braces never
    # reach the slug step and the heading's anchor is the id, not a slug of
    # the whole heading text.
    id=''
    if [[ $text =~ \{#([^}]+)\}[[:space:]]*$ ]]; then
      id=${BASH_REMATCH[1]}
      text=${text:0:$(( ${#text} - ${#BASH_REMATCH[0]} ))}
    fi
    heading_text "$text"
    text=$TEXT_OUT
    # CommonMark strips trailing whitespace from an ATX heading's text.
    text=${text%"${text##*[![:space:]]}"}
    slugify "$text"
    slug=$SLUG_OUT
    [[ -n $id ]] && slug=$id
    # github-slugger keeps per-FILE state and RESERVES every id it emits:
    # A, A-1, A render a, a-1, a-2 — the second A climbs the counter PAST
    # the a-1 the literal "A-1" heading already emitted, instead of
    # colliding with it. An explicit {#id} enters the same map, so a later
    # heading cannot re-emit it either.
    if [[ -z ${seen["$slug"]+x} ]]; then
      seen["$slug"]=0
    else
      base=$slug
      n=${seen["$base"]}
      while :; do
        n=$((n + 1))
        seen["$base"]=$n
        slug="$base-$n"
        [[ -z ${seen["$slug"]+x} ]] && break
      done
      seen["$slug"]=0
    fi
    printf '%s\n' "$slug"
  done < "$file"
}

# ---------------------------------------------------------------------------
# Destinations of every markdown link node whose target carries a fragment,
# one per line, accumulated into LINK_DESTS across the calls of one file.
#
# The scan runs on the scanner's visible text only (no fences, no HTML
# comments) and parses link NODES instead of scanning raw lines: a
# [x](#missing) inside an inline code span is literal documentation text,
# and the optional title of [x](#real "title") is link syntax, not part of
# the target — neither may reach the fragment check. Inline code is dropped
# first (a backtick hides everything up to the next backtick), then every
# [label](dest), [label](<dest>) and [label](dest "title") node contributes
# its destination. Anything without a ]( … ) node shape — reference-style
# links ([text][ref]), autolinks, link definitions — stays invisible, as
# before: none are used in website/docs; if one ever carries a fragment,
# this parser must learn the form first, or the guard stays silent about it.
# ---------------------------------------------------------------------------

# One link node's destination. $1 is the text after the `]( `. LINK_DEST
# receives the destination, LINK_REST the text after the node's closing
# ')', and LINK_OK says whether a well-formed node was found at all.
LINK_DEST='' LINK_REST='' LINK_OK=0
parse_link_node() {
  local s=$1
  LINK_DEST='' LINK_REST='' LINK_OK=0
  # Whitespace just inside the parentheses is link syntax.
  s=${s#"${s%%[![:space:]]*}"}
  if [[ $s == '<'* ]]; then
    # An angle destination: everything up to the closing '>'.
    [[ $s == *'>'* ]] || return 0
    LINK_DEST=${s:1}
    LINK_DEST=${LINK_DEST%%'>'*}
    s=${s#*'>'}
  else
    # A bare destination runs to the first whitespace or ')'.
    LINK_DEST=${s%%[[:space:])]*}
    s=${s#"$LINK_DEST"}
  fi
  # An optional title — "…", '…' or (…) — is link syntax: the destination
  # already ended before it, and it never contains a bare closer.
  s=${s#"${s%%[![:space:]]*}"}
  case $s in
    '"'* ) s=${s#'"'}; s=${s#*'"'} ;;
    "'"* ) s=${s#"'"}; s=${s#*"'"} ;;
    '('* ) s=${s#*'('}; s=${s#*')'} ;;
  esac
  # Whitespace between the node and its closing ')' is link syntax too.
  s=${s%"${s##*[![:space:]]}"}
  [[ $s == ')'* ]] || return 0
  LINK_REST=${s#')'}
  LINK_OK=1
}

collect_link_destinations() {
  local s=$1 seg head out=''
  local tick='`'
  while [[ -n $s ]]; do
    # An inline code span's content is literal — drop it whole.
    if [[ $s == *"$tick"* ]]; then
      seg=${s%%"$tick"*}
      s=${s#*"$tick"}
      if [[ $s == *"$tick"* ]]; then
        s=${s#*"$tick"}
      else
        s=''                       # unpaired backtick: the rest is code text
      fi
    else
      seg=$s
      s=''
    fi
    while [[ $seg == *']('* ]]; do
      head=${seg%%']('*}
      parse_link_node "${seg#*']('}"
      if (( ! LINK_OK )); then
        # No well-formed node here: resume after this ]( so a later one on
        # the same line is still found.
        seg=${seg#*']('}
        continue
      fi
      seg=$LINK_REST
      # It is only a link if the label is bracketed text: the last '['
      # before the ]( must carry no ']' after it.
      if [[ $head != *'['* || ${head##*'['} == *']'* ]]; then
        continue
      fi
      [[ $LINK_DEST == *'#'* ]] && out+="$LINK_DEST"$'\n'
    done
  done
  LINK_DESTS+=$out
}

fragment_links() {
  local file=$1
  scan_reset
  LINK_DESTS=''
  while IFS= read -r line || [[ -n $line ]]; do
    scan_step "$line"
    collect_link_destinations "$CONTENT_OUT"
  done < "$file"
  # One destination per line, already newline-terminated: stdout feeds the
  # main loop's read, as the old printf-per-target scan did.
  printf '%s' "$LINK_DESTS"
}

# ---------------------------------------------------------------------------
# Main: collect every heading ID per file, then check every fragment link.
# ---------------------------------------------------------------------------
declare -A FILE_IDS=()
declare -A FILE_SEEN=()

DOC_FILES=()
doc_list=''
# The inventory must be COMPLETE before anything is graded. As a process
# substitution the pipeline's exit status was lost, so a failing find, sed
# or sort read as an empty — silently partial — list and every link passed.
# Command substitution keeps the status under pipefail: a discovery error
# fails the guard instead of shrinking the checked set.
if ! doc_list=$(cd "$DOCS_ROOT" && find . -type f -name '*.md' | sed 's|^\./||' | sort); then
  echo 'FAIL: website/docs discovery failed — the guard refuses to grade a partial inventory' >&2
  exit 1
fi
while IFS= read -r rel; do
  [[ -n $rel ]] || continue         # the herestring's trailing newline
  DOC_FILES+=("$rel")
done <<< "$doc_list"

for rel in "${DOC_FILES[@]}"; do
  FILE_SEEN["$rel"]=1
  FILE_IDS["$rel"]=$(heading_ids "$DOCS_ROOT/$rel")
done

echo '=== doc anchors ==='
printf 'checked %d markdown file(s) under website/docs\n' "${#DOC_FILES[@]}"

# Resolve a link target path to a path relative to the docs root.
resolve_target() {
  local from_dir=$1 path=$2
  local base
  # A leading '/' is site-root-relative: the docs root is the page root.
  if [[ $path == /* ]]; then
    from_dir=''
  fi
  base=$(cd "$DOCS_ROOT/$from_dir" 2>/dev/null && cd "$(dirname "$path")" 2>/dev/null \
    && printf '%s/%s' "$(pwd)" "$(basename "$path")" || true)
  [[ -n $base ]] || return 1
  base=${base#"$DOCS_ROOT"/}
  printf '%s' "$base"
}

FAILURES=0
for rel in "${DOC_FILES[@]}"; do
  dir=$(dirname "$rel")
  while IFS= read -r target; do
    [[ -n $target ]] || continue
    path=${target%%#*}
    fragment=${target#*#}
    [[ $fragment == "$target" ]] && fragment=''
    [[ -n $fragment ]] || continue
    # An external target carries no local heading to resolve against.
    case $path in
      http://*|https://*|mailto:*) continue ;;
    esac
    if [[ -z $path ]]; then
      target_file=$rel
    else
      target_file=$(resolve_target "$dir" "$path") || continue
    fi
    # An EXTENSIONLESS page URL renders from its markdown source: ./other
    # serves other.md and ./sub/ serves sub/index.md. Resolve those before
    # the fragment check — a URL with no source file behind it is a broken
    # PATH (Docusaurus's onBrokenMarkdownLinks, not this guard), but one
    # that resolves must have its fragment checked, not skipped as an
    # unknown key.
    if [[ -z ${FILE_SEEN["$target_file"]+x} ]]; then
      if [[ -n ${FILE_SEEN["$target_file.md"]+x} ]]; then
        target_file=$target_file.md
      elif [[ -n ${FILE_SEEN["$target_file/index.md"]+x} ]]; then
        target_file=$target_file/index.md
      else
        continue
      fi
    fi
    if ! grep -qxF -- "$fragment" <<<"${FILE_IDS["$target_file"]}"; then
      printf 'FAIL: %s: link to #%s resolves to no heading in %s\n' \
        "$rel" "$fragment" "$target_file" >&2
      FAILURES=$((FAILURES + 1))
    fi
  done < <(fragment_links "$DOCS_ROOT/$rel")
done

if (( FAILURES > 0 )); then
  printf '%d unresolved heading fragment(s)\n' "$FAILURES" >&2
  exit 1
fi

echo 'every heading fragment link resolves to a rendered heading ID'
exit 0
