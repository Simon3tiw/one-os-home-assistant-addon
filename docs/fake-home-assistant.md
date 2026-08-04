# Fake Home Assistant boundary

`FakeHomeAssistant.standard()` implements the exact read-only seam used by the API tests. It contains a floor, area, physical device, device entities, a standalone diagnostic entity and current states. Tests mutate this in-memory source to model unavailable values, disappearance and capability drift.

The production adapter exposes only registry list commands from ADR-0012, Core `GET /api/states`, `config/auth/list`, and state-event subscription. There is intentionally no generic request/send method. The fake's `mutation_attempts` recorder must remain empty for the complete suite.

Additional scenarios should be added as versioned JSON fixtures under `backend/tests/fixtures/ha/<core-version>/`; fixtures must use synthetic identifiers and no tokens.
