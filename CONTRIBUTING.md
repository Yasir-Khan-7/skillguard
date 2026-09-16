# Contributing to SkillGuard

Thanks for helping make agent skills safer to share.

## Adding a detection rule

Rules live in `skillguard/rules.py` as plain data — no code changes needed.
Add a `Rule(...)` to the `RULES` tuple with:

- a unique `id` (next number in its category range),
- a short `name`,
- a `severity` (`critical` / `high` / `medium` / `low` / `info`),
- a `category`,
- a `pattern` (Python regex, case-insensitive by default),
- a one-sentence `why` explaining the real-world risk.

Then add a test in `tests/` with a minimal skill that should trip it, and one
that should not. Keep false positives low: a rule that fires on every README is
worse than no rule.

## Running the tests

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Principles

- **Static only, for now.** Rules must not execute skill code.
- **Explain, don't just flag.** Every finding tells the user why it matters.
- **Low noise.** Documentation files get a pass on hygiene-level rules.
- **Data over code.** Prefer expressing a check as a rule pattern.
