# Verification

## Automated checks run

- Backend: `JWT_SECRET=<temporary test secret> PYTHONPATH=. .venv/bin/pytest -q` — **14 passed**. The run reported 25 dependency deprecation warnings from Starlette/FastAPI under Python 3.14.
- Frontend: `npm test` — **15 passed** across 2 test files.
- Frontend: `npm run build` — **passed**. Rollup emitted harmless annotation-placement warnings from bundled Zod dependencies.
- Database: Alembic `upgrade head` completed successfully against an isolated temporary SQLite database.

## Browser smoke checks run

- Authenticated through the UI using an isolated temporary administrator and database.
- Imported a synthetic JSON alert and verified its source ID, source system, timestamp, and pending status in the review queue.
- Promoted the alert, verified it appeared in the promoted queue, and confirmed the resulting incident appeared in the incident list.
- Measured document and body widths at 320, 375, 768, 1024, and 1440 CSS pixels on the imported-alert page; no horizontal page overflow was measured.

These checks do not imply that every workflow or every responsive page has been manually re-tested. Use the remaining checklist when making substantial UI or API changes.

## Manual responsive checks

At 320, 375, 768, 1024, and 1440 CSS pixels:

1. Sign in and sign out; verify protected routes redirect or show an authorization error.
2. Open every navigation item and verify the matching view loads.
3. Open the mobile navigation with the keyboard and touch; verify it closes after choosing a route.
4. Confirm no page-level horizontal overflow and that controls remain reachable.
5. Filter and paginate incidents, open an incident, add a timeline event, and confirm chronological display.
6. Register evidence metadata and an IOC; check validation and duplicate handling.
7. Generate a report and verify print layout and simulated-data labeling where applicable.
8. Check empty, loading, and API failure states with an empty database and stopped backend.
9. Verify charts resize and retain readable labels.

Do not treat the remaining checklist as evidence that those additional manual checks have been run.
