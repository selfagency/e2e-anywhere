# Localization Strategy

## Scope

All user-visible strings in extension UI surfaces must be externalized into locale files.

Target surfaces:

- Popup UI.
- Sidebar/panel UI.
- Settings UI.
- Onboarding UI.
- Error and status messages.

## Baseline languages

- Default language: English (`en`).
- Additional v1 language: Spanish (`es`).

## String architecture

- Use i18next JSON resource files.
- No hardcoded user-facing strings in component logic.
- Namespaced keys by feature area (e.g., `popup.*`, `settings.*`, `onboarding.*`, `errors.*`).

## File layout (planned)

- `packages/extension/locales/en.json`
- `packages/extension/locales/es.json`

## Runtime behavior

- On first install, default to `en`.
- Persist selected language in local extension settings.
- Apply language changes without requiring browser restart where possible.

## Adding a new language

1. Copy `en.json` to `<lang>.json`.
2. Translate all keys; do not delete keys.
3. Validate fallback behavior for missing keys.
4. Run UI checks for truncation/overflow on long strings.
5. Verify accessibility labels remain equivalent in translated locale.

## Quality checks

- Ensure one-to-one key coverage across locales.
- Run pseudo-localization checks before adding RTL languages.
- Include layout regression checks for long text and narrow viewport sizes.

## Non-goals for v1

- Full pluralization for all locales beyond current product string set.
- Server-side localization infrastructure.
