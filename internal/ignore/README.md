# Local exclude patterns

`internal/ignore` is the single validator and matcher used by configuration and filesystem capture. `Compile` validates an ordered list once; `Matcher.Exclude` returns the first matching pattern and whether it matched.

Patterns match root-relative slash paths with `github.com/bmatcuk/doublestar/v4` v4.10.3. The supported subset is `*` within one segment, `**` as a complete recursive segment, `?` for one non-separator character and `[class]` character classes. Braces, `!`, backslashes, leading `/`, empty patterns, `.`, any `..` segment, trailing `/` and `//` are rejected. A list is limited to 64 patterns; each pattern is limited to 4096 bytes and 16 `**` segments. Validation uses both doublestar's `ValidatePattern` and the local restriction scan: the library validator alone accepts forms outside this dialect, including braces and malformed path separators.

Golden-vector tests pin the supported matching semantics to the selected version. Upgrading doublestar requires reviewing those vectors and the restricted dialect, rather than silently reinterpreting stored excludes.
