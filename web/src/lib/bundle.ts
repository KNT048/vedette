// D-408: the offline update bundle is not in v1; core answers GET/POST /core/updates/bundle with 501 not_implemented. While false
// the GUI offers no bundle: no "Bundle for air-gapped networks" block on Updates and no sentence that points to one. The bundle code
// (mock, contract, import form) is kept. Post-v1: set true, put the bundle back into the texts that dropped it (updates.advisoriesNotYet,
// updates.vedette.desc, Privacy flows 1 and 6 with PRIVACY.md) and recheck S-CORE-2.
export const BUNDLE_IN_UI = false
