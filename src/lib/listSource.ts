/// Which list the results pane shows, as the backend is asked for it. The
/// rows and the statistics both derive from this, so they cannot disagree.

export type SearchMode = {
  query: string;
  /// The search was a rule condition; its hits are stored under `ruleId`.
  condition: { ruleId: string; hits: number } | null;
  error?: string;
} | null;

/// `ruleId` null: every event. `search`: the text filter to send.
export type ListSource = { ruleId: string | null; search: string };

/// The list for the settled `search`, or null while it is still unknown:
/// the search box's text has not been classified yet (`mode` is pending or
/// belongs to an older query). `selectedRule` null means every event.
export function listSource(
  search: string,
  mode: SearchMode,
  selectedRule: string | null,
): ListSource | null {
  if (mode === null || mode.query !== search) return null;
  if (mode.condition) return { ruleId: mode.condition.ruleId, search: "" };
  return { ruleId: selectedRule, search };
}

/// The list statistics may count: only a list whose filter resolved and
/// succeeded, and not while a rule it depends on is being evaluated (its
/// matches are still being written).
export function statsSource(
  search: string,
  mode: SearchMode,
  selectedRule: string | null,
  ruleBusy: boolean,
): ListSource | null {
  if (ruleBusy || mode?.error) return null;
  return listSource(search, mode, selectedRule);
}
