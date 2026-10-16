# Performance measurements

The Markdown documents in this directory retain benchmark summaries and methods.
Raw JSON reports are generated locally and are excluded from version control.

Use `local/performance/` for raw reports and other machine-specific benchmark output.
For example:

```sh
python tools/profile_synthesis_selection.py --output local/performance/synthesis-pipeline.json
```

Tools with a default report destination use `local/performance/`. Tools requiring
`--output` should also use that directory. Keep personal checkout paths out of
published summaries. Raw reports can be regenerated with the documented tools.

- [VM lifetime corrections and preset measurements (2026-10-16)](vm-lifetimes.md): native equivalence coverage, before/after VM costs and current full preset costs.
