# Vendored OSV / CSAF / CVE schemas

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

## CVE — `cve.upstream.json` (+ `cvss/`)

Source: <https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/CVE_Record_Format.json>
(CVE JSON record format, currently **v5.2.0**). We vendor it unmodified.

A CVE record is exported by `publication.cve.build_cve` only for advisories
that carry an Eclipse-Foundation-assigned CVE (`Advisory.assigned_cve_id`).
It is a `PUBLISHED` record with the mandatory CNA-container fields
(`providerMetadata`, `descriptions`, `affected`, `references`) plus
`problemTypes` (CWE), `metrics` (CVSS) and `credits`. Validation is **strict**
— any gap raises `CveValidationError` and prevents the publish.

### CVSS imports

The CVE schema references its CVSS sub-schemas with opaque `file:` URIs
(`file:imports/cvss/cvss-v3.1.json`, …). `jsonschema` cannot fetch those, so we
vendor the referenced files under `cvss/` and resolve the URIs with a
`referencing.Registry` (see `publication.cve._validator`). The v2.0 import is a
draft-04 document; the v3.0/v3.1/v4.0 imports are draft-07. The
`reference-tags` / `cna-tags` / `adp-tags` external schemas are **not** vendored
because the builder never emits the optional `tags` fields that reference them.

Base score and base severity (required by the typed `cvssV3_1` / `cvssV4_0`
fields, but not stored on the advisory) are computed from the vector string with
the `cvss` library. An unparseable vector falls back to an `other` metric so the
severity is never silently dropped.

To refresh:

```sh
base=https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema
curl -sSf -L "$base/CVE_Record_Format.json" -o publication/schemas/cve.upstream.json
for v in v2.0 v3.0 v3.1 v4.0; do
  curl -sSf -L "$base/imports/cvss/cvss-$v.json" \
    -o "publication/schemas/cvss/cvss-$v.json"
done
```
