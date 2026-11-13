// D-403: SPAN hidden for v1, backend kept. While false the GUI offers no SPAN (switch mirror port, a second card without an
// address): no SPAN settings or switch guides, no SPAN choice for a card, no sentence about mirrored traffic. A box that
// already has SPAN set up still shows that state, read-only, with the way to stop it. Post-v1: set true, recheck S-CORE-8
// (D-56, D-387, D-393, D-399) and S-LOG-4.
export const SPAN_IN_UI = false
