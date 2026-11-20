// The form of a cited n/a skip description (na.mjs writes it, matrix.mjs reads it):
// "na-browser: <reason> [<citation>]" or "na-env: <reason> [<citation>]". Kept apart from
// na.mjs so matrix.mjs can read it without loading the test runner.
export const NA_PATTERN = /^na-(browser|env): (.+) \[(.+)\]$/s;
