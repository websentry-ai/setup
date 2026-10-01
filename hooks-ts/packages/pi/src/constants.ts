// User-facing text that only makes sense for pi.
//
// Core's `constants.ts` holds the strings every agent shares (the deny prefix, the confirm title,
// the engine-unavailable reason). A string whose wording names pi or one of pi's own CLI modes lives
// here instead, so core never carries an agent's name.

/**
 * The block reason when a verdict needs a confirmation and there is nobody to ask. `-p` and `json`
 * are pi's non-interactive modes; locked verbatim by 08-CONTEXT.md.
 */
export const NO_UI_REASON =
  "Requires confirmation but pi is running without a UI (-p/json). Run interactively or adjust the policy.";
