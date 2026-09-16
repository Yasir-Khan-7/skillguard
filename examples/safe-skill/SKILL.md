---
name: csv-summary
description: Summarize a CSV file — row count, column types, missing values, and a preview table. Use when the user uploads a .csv and wants a quick overview before analysis.
allowed-tools: Read, Bash(python3:*)
---

# CSV Summary

## When to use
The user has a CSV file and wants to understand its shape before doing anything else.

## Steps
1. Read the file path the user provided.
2. Run `scripts/summarize.py <path>`.
3. Report row count, column dtypes, null counts, and the first five rows.

## Notes
- Do not modify the source file.
- If the file is larger than 100 MB, read it in chunks.
