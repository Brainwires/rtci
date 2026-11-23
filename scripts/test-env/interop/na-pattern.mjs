// The form of a cited n/a skip description (na.mjs writes it, matrix.mjs reads it):
// "na-browser: <reason> [<citation>]", "na-env: ..." or "na-peer: ..." (a non-browser peer's
// stack lacks the feature: peers.spec.mjs). Kept apart from
// na.mjs so matrix.mjs can read it without loading the test runner.
export const NA_PATTERN = /^na-(browser|env|peer): (.+) \[(.+)\]$/s;
