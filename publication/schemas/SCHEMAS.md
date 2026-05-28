# Vendored OSV / CSAF schemas

## OSV — `osv.upstream.json`

Source: <https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json>

### Local patch

The upstream `id` allowlist (`$defs/prefix.pattern`) restricts the leading
namespace to known database prefixes (CVE, GHSA, …). AdvisoryHub uses the
`ECL-` prefix for Eclipse Foundation advisories, so we patch the vendored
copy to add `ECL|` next to the other entries:

```diff
- "pattern": "^(x_|(ASB-A|PUB-A|ALPINE|...|CVE|DEBIAN|...)-)"
+ "pattern": "^(x_|(ASB-A|PUB-A|ALPINE|...|CVE|ECL|DEBIAN|...)-)"
```

The patch is idempotent — re-applying after a schema refresh is safe.

For full interoperability with downstream OSV consumers (osv.dev, the OSV
CLI, ecosystem-specific scanners), the right long-term move is to PR
`ECL` into <https://github.com/ossf/osv-schema/blob/main/validation/schema.json>
so consumers stop falling back to `x_` heuristics.

To refresh from upstream:

```sh
curl -sSf -L \
  https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json \
  -o publication/schemas/osv.upstream.json
# then re-apply the patch above
```

## CSAF — `csaf.upstream.json`

Source: <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json>

This is the canonical OASIS CSAF 2.0 schema. We vendor it unmodified.

The `publication.csaf.build_csaf` builder currently emits the **mandatory**
top-level shape (`document` with `category`, `csaf_version`, `publisher`,
`title`, `tracking`; `vulnerabilities[]` with at least a title) and a
`product_tree` that AdvisoryHub fills in from the advisory's affected
products. Validation against the upstream schema is **strict** — any
gap produces a `CsafValidationError` and prevents the publish. Known
gaps are tracked in the README's "Known limitations" section.

To refresh:

```sh
curl -sSf -L \
  https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json \
  -o publication/schemas/csaf.upstream.json
```
