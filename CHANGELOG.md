## 0.1.4 - 2025-11-28

- Fix: remove stray/unimplemented auth/1 head to avoid CI compile errors when used as a dependency.

## 0.1.3 - 2025-11-28

- Update dependencies: httpoison -> ~> 2.0, credo -> ~> 1.7

## 0.1.5 - 2025-11-29

- Fix: Proper CSRF state handling and validation:
	- Strategy now stores a 'state' token during the request phase (session + response cookie) and validates state on callback.
	- Callback validation checks session, cookie, and CSRF-derived state candidates and short-circuits early on CSRF mismatches so later validation cannot overwrite the error.
- Tests: Added/updated unit tests to cover state round-trip flows, cookie-only scenarios, session-only scenarios, missing/mismatched state cases, and valid happy paths.
- Changed: bumped package version to 0.1.5 and updated HTTP client dependency to HTTPoison ~> 2.0.
- Note: This release will be published to Hex under the package name `ueberauth_steam_strategy` due to the original `ueberauth_steam` name being already registered.
