// The modules left out of v1 (POST_V1_MODULES in ./v1) are not offered while this is false; a box that has one on
// sees it read-only with the way out. Its own file, as span.ts and credentialed.ts, so a test can run those modules as offered.
// Post-v1: set true and recheck the stories of response, mcp-server, auth-oidc and scan-credentialed.
export const POST_V1_IN_UI = false
