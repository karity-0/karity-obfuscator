# Packer

`pack` is an outer load-based wrapper, not another VM backend. It chooses a small
raw-DEFLATE candidate, encodes the compressed stream and binds a rolling-XOR key
to its loader. An external context and state-derived routes couple the payload
to the wrapper. VM call constants may be externalized without rewriting the
already captured VM function. Non-VM payloads use conservative eligible
function/constant/reference externalization.

## Configuration and requirements

Add `pack` to the main `passes` list after source/VM processing. Configure loader
transforms with `packer_output_passes`. Neither `pack` nor `vm` can be nested in
output-pass lists; validation rejects that configuration. The packer works with
all supported VM backends and with source-only output.

The loader needs Lua 5.3 facilities including dynamic loading and the standard
libraries used by its decoding and integrity code. A sandbox that removes or
replaces these facilities is not automatically compatible. Compression does not
hide plaintext from a runtime that controls the loader. Integrity/tamper behavior
can reject modified loaders or replacement loading functions; it is not a
cryptographic authenticity guarantee against a fully controlled host.

Compression can reduce repetitive VM output, while the decoder and external
context add overhead. Small inputs may grow. Loader output transforms can add
substantial build/runtime cost; use `high` rather than assuming `max` is a bounded
production preset. Do not edit finalized loader/runtime code after hashes are
computed.

## Verification and implementation

`test/run_packer_regression.py` covers source-only and VM semantics, signatures,
randomized builds, tamper cases and a runtime budget. MOV regression additionally
checks its CLI packing path. Both run through `python test/run_ci.py`.
Implementation: [packer.py](../../obfuscator/passes/packer.py).
