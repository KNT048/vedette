# docs/decisions

New decisions go here, one file per decision (D-250): `D-nnn.md` holding exactly one table row,
`| D-nnn | decision | reason + sources | date |`. Never append to `docs/DECISIONS.md` in a feature PR: rows added by
parallel PRs collide in the merge queue. The supervisor folds these files into the table (sorted by number) and deletes them.
