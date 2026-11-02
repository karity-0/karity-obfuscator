# Runtime hardening

- Karity / Lua 5.3 enables `encoded_bitwise` and `distributed_integrity` by default; disable either with `--vm-option NAME=false`.
- Karity protects internal integer and string values; coercions and native boundaries retain Lua behavior.
- All backends validate metadata and private-coroutine hook behavior through protected IR before guest execution.
- Sensitive host boundaries check immediately; proven Bare internal calls use lightweight polling with the existing 127-event period.
- `environment_policy=compatible` is the default; `strict` requires directly owned APIs and rejects functional environment proxies.
- Compatible debug, coroutine and function-dump APIs are required. Protection adds output, startup and execution cost.
- Dump/line binding and constant checks cover specific edits; fingerprints are not MACs and cannot authenticate a fully controlled host.

- Classic/Karity/MOV validate decoded instructions, metadata and scalar constants; Bare checks its factory bank and external constants.
- Checks run at initialization, entry, constant use and periodic checkpoints; persistent region edits can take up to `127 * region_count` guard events to detect.

- Guest entry and its protected-data access require completed validation; failure revokes program admission and subsequent protected-string reads.
- Policy fields use exact build-derived comparisons and captured helpers without changing key/blob formats. Private-state forgery and restored-between-checks edits remain limits.
