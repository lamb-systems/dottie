# Local exclude patterns

Configuration and filesystem capture share `internal/ignore` as their single validator and matcher. `Compile` validates an ordered list once; `Matcher.Exclude` returns the first matching pattern and whether it matched.

Patterns match root-relative slash paths with `github.com/bmatcuk/doublestar/v4` v4.10.3. The supported subset is `*` within one segment, `**` as a complete recursive segment, `?` for one non-separator character and `[class]` character classes. Braces, `!`, backslashes, leading `/`, empty patterns, `.`, any `..` segment, trailing `/` and `//` are rejected. A list is limited to 64 patterns; each pattern is limited to 4096 bytes and 16 `**` segments. Validation combines doublestar's `ValidatePattern` with the local restriction scan. The library validator alone accepts forms outside this dialect, including braces and malformed path separators.

Golden-vector tests pin the supported matching semantics to the selected version. Review those vectors and the restricted dialect when upgrading doublestar; do not silently reinterpret stored excludes.
