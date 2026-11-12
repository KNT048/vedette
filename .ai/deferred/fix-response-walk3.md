# Deferred: fix/response-walk3 (G11, D-390)

- [ ] Opus review LOW 6: RuleEditor `refused()` puts a box refusal `Action "X": ...` under the first action named X (two actions with the same name: the second one's error lands on the first) and parameter-level refusals (mix of text and a trigger field, over 200 characters) under the action select, not the parameter input. Fix: the box names the action index or parameter in the message or a field code.
- [ ] Opus review LOW 5: no Go test that `loadData` refuses a number/port field without min/max, an upper-case choice, or a template condition outside its range / on an unknown field (the checks run on every start, but a broken test fixture is the only proof). Add a table test with patched copies of the data.
- [ ] Opus review LOW 5: no vitest for an existing honeypot rule edited on a container-only install keeping its trigger marked "(not on this install)".
- [ ] The mock engine (`engine.ts`) does not fail closed on a stored rule whose condition is out of range, as the box does (`storedCondsOK`); mock rules can only be stored through `checkRule`, so it cannot happen today in the preview.
