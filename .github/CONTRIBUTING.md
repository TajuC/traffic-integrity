# Contributing

Thanks for your interest in Traffic Integrity. This document covers how to
build the project, the quality bar every change must clear, and how to propose
changes.

## Build and test

Node.js 22.18 or newer is required. The version CI uses is recorded in `.nvmrc`.

```
npm install
npm run check
```

`npm run check` is typecheck, lint, the test suite, the synthetic evaluation CLI, and a production build.
Without `TEST_REDIS_URL` the Redis contract tests and the multi-instance suite
are skipped. Without `TEST_DATABASE_URL` database tests use PGlite. To include them:

```
docker run -d --name ti-redis -p 6379:6379 redis:7.4-alpine
TEST_REDIS_URL=redis://127.0.0.1:6379/0 npm test
```

PostgreSQL is not required for the suite. Tests that need a database use
PGlite unless `TEST_DATABASE_URL` points at a real server.

## Quality bar

Every change must pass the same gates CI enforces, before review:

```
npm run typecheck
npm run lint
npm test
npm run build
```

- TypeScript is strict (`noUncheckedIndexedAccess`, `verbatimModuleSyntax`,
  `erasableSyntaxOnly`). Do not weaken those flags to land a change.
- ESLint runs `typescript-eslint` recommended type-checked rules. Do not
  disable a lint without a short explanation in the pull request.
- New behavior needs tests. The HTTP and conversion suites are end-to-end
  through the real Express application and the real SQL schema.

## Commits and pull requests

- Write commit subjects in the imperative mood, describing the change itself.
- Keep each pull request focused on a single concern.
- Fill in the pull request template and confirm the quality bar passes.
- The default branch is protected. Direct pushes to `main` are not the
  contribution path.

## Reporting bugs and requesting features

Open an issue using the templates under `.github/ISSUE_TEMPLATE`. For anything
with a security impact, follow `SECURITY.md` instead of opening a public issue.
