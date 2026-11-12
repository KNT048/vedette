# Deferred from session fix-gui-contract-align (WP-06)

- [ ] `modules/findings/` (MANIFEST `fnd_`, depends core+feeds+inventory) does not exist yet and `modules/mitigation/MANIFEST.yaml` still says `mit_`, depends core+feeds+inventory (D-57 (6): depends on findings). The GUI mock already has module `findings` and `mitigation` depending on it. WP-21 owns the manifests.
