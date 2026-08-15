# Field Masking Transform — `dev.mcpg.transform.masking`

> class `transform` · `wasm` · package `mcpg-plugin-transform-masking` · artifact `mcpg_plugin_transform_masking.wasm` · Apache-2.0

WASI Component Model transform that redacts sensitive fields — personal data,
card numbers, credentials — out of tool arguments before dispatch and out of
tool results before they reach the client. Field names to redact are listed in
the plugin's config, matched case-insensitively, with an optional trailing
wildcard so one entry covers a family of keys. Because it ships as a Wasm
component rather than a native library, it runs inside the gateway's Wasmtime
sandbox under operator-set memory, fuel, and wall-clock limits. Reach for it
when a downstream system returns more than a caller should see and you want the
redaction enforced at the gateway rather than trusted to the backend.

## What it does
- Walks arguments and results and redacts every field whose name matches an entry in `redact_fields`, comparing case-insensitively.
- Matches an exact field name, or a `prefix_*` pattern that covers every key starting with that prefix.
- Replaces a string value with `mask_char` repeated `mask_length` times, regardless of the original length, so the redacted value leaks no length information.
- Replaces every value inside a matched object or array, so redacting a container redacts all of it.
- Selects the side to redact through `policy`: `strict` covers both arguments and results, `input_only` covers arguments, `output_only` covers results.
- Leaves a payload untouched when it does not parse as JSON, and reports an unusable config as a transform error.
- Declares no `required_capabilities` — it performs no I/O and reads nothing beyond the value it is handed.

## Configuration
Loaded from the flat top-level `plugins:` list with `kind: wasm`. The gateway
must be built with the `wasm-plugins` feature for the Wasmtime loader to be
present; without it the entry fails the load at boot with a message telling you
to rebuild with `--features wasm-plugins`.

A runtime-loaded Wasm artifact also needs its descriptor beside it: copy this
crate's `plugin.yaml` next to the component as `<artifact>.plugin.yaml` — here
`mcpg_plugin_transform_masking.wasm.plugin.yaml`. The gateway takes the class
and protocol version from that sidecar and cross-checks its id against the
manifest the component reports, so a swapped artifact cannot masquerade as a
different plugin.

```yaml
plugins:
  - id: dev.mcpg.transform.masking
    class: transform
    kind: wasm
    source: { path: ./plugins/mcpg_plugin_transform_masking.wasm }
    limits: { memory_mb: 16, fuel: 5000000, timeout_ms: 50 }
    config:
      policy: strict
      redact_fields: [ssn, credit_card, password, "card_*"]
      mask_char: "*"
      mask_length: 8
      preserve_type: true
      nested: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `policy` | `strict` \| `input_only` \| `output_only` | `strict` | Which dispatch side is redacted. An unrecognised value is a config error. |
| `redact_fields` | list of string | *(required, non-empty)* | Field names to redact. Exact match, or a trailing `*` for a prefix pattern. Matching is case-insensitive. |
| `mask_char` | string | `"*"` | Replacement character for string values; only the first character is used. |
| `mask_length` | integer | `8` | Number of `mask_char` characters in a redacted string. |
| `preserve_type` | bool | `true` | Keep numbers and booleans as they are. Set `false` to replace them with `null`. |
| `nested` | bool | `true` | Descend into nested objects. With `false`, only the top level of the payload is examined. |

An empty or absent `redact_fields` is a config error, so the plugin cannot be
deployed in a state where it silently redacts nothing. Config keys the plugin
does not recognise are ignored rather than rejected — check spelling against the
table above, because a mistyped `redact_feilds` reads as absent.

## Security
`preserve_type: true` is the default and it means exactly what it says: a
matched field holding a **number or a boolean is not redacted**. A social
security number stored as `123456789` rather than `"123-45-6789"` passes
through in the clear. Set `preserve_type: false` whenever a redacted field can
carry a numeric value; the field then becomes `null`, which changes the payload
shape but guarantees the value does not leave the gateway.

Two more behaviours are worth knowing before you rely on this as a control:

- Matching is by field **name**, not by value. A card number that appears inside
  a free-text field, or under a key nobody listed, is not found. Pair name-based
  redaction with backend-side controls rather than treating it as complete.
- With `nested: false` only the top level is examined, so a sensitive field one
  object deeper survives. On the result side the top level is the serialised
  tool result — `content`, optional `structuredContent`, `isError` — so nothing
  a backend named ever matches there. The default is `true`; leave it there
  unless payload depth is a measured cost.

The component runs in the Wasmtime sandbox with no WASI capabilities granted for
network or filesystem access, and the per-entry `limits:` block bounds each
invocation — `memory_mb` (default 64), `fuel` (default 10000000), and
`timeout_ms` (default 100).

## Observability
Redaction is invisible in the plugin itself; the host is the emit point. Each
application increments `mcpg_transform_applies_total` (labels `plugin_id`,
`phase` of `pre` or `post`, `outcome` of `unchanged`, `modified`, or `error`)
and records `mcpg_transform_apply_ms`. A redaction also emits the
`mcpg.transform.applied` audit event, which records hashes and byte counts of
the before and after values — never their plaintext, which is what makes the
audit trail safe to keep for a masking plugin.

## Build
The artifact is a WASI Component Model component, built for `wasm32-wasip2`:

```bash
cargo build -p mcpg-plugin-transform-masking --target wasm32-wasip2 --release
# → target/wasm32-wasip2/release/mcpg_plugin_transform_masking.wasm
```

The exported world is `transform-plugin` from `wit/plugin.wit`, whose
`transform` interface supplies `manifest`, `transform-arguments`, and
`transform-output`. The masking logic is also compiled natively for unit tests;
the WIT bindings themselves are gated to `wasm32` so a host workspace build
stays green.

## Testing
```bash
cargo test -p mcpg-plugin-transform-masking
```

The suite runs on the host and covers the masking logic directly — nesting,
wildcard patterns, case-insensitive matching, the `preserve_type` branches, and
config parsing including the rejected-policy and empty-`redact_fields` cases.

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin signing, trust roots, and revocation: <https://mcpg.dev/docs/security/plugin-security>
- What a plugin is and how the ABI works: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Native transforms in the same class: `libs/plugins/transform/jsonata`, `libs/plugins/transform/template`
- The other in-tree Wasm component: `libs/plugins/testing/wasm-test-gate`
