// D-417: the credentialed scan (module scan-credentialed, S-SCAN-5) has no backend in v1: core answers /scans/credentialed* with
// 501 not_implemented. While false the GUI does not offer it: no Credentialed scan tab on Vulnerability scans, and the module is not
// listed in Settings → Modules or in the setup wizard, so nothing tells a customer it runs. The GUI code (tab, contract, mock) is kept.
// Post-v1: build the module's backend, set true, recheck S-SCAN-5.
export const CREDENTIALED_IN_UI = false
