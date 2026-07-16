# Project Goal — kroxy

**Primary objective:** Continuously improve the security posture of this project.
Security is the highest priority and takes precedence over features, velocity,
and convenience.

This file is the authoritative source for the project's working principles.
Read it at the start of every session, re-read it before every push, and
re-read it after any security finding. Assume a fresh session reading it cold —
do not rely on memory from a previous turn.

## Working principles (strict priority order)

### 1. Security review is continuous, not one-time
Before any change and again before any push, re-assess the current state of the
codebase for security concerns — both new and pre-existing. Treat each work
session as a fresh audit, not a continuation of old assumptions. Use and keep
updated the records under `audits/`.

### 2. Subtract before you add
Before writing any new code, first look for code to fix, harden, simplify, or
remove. Prefer deleting insecure or dead code over adding mitigations on top of
it. Reducing attack surface counts as progress. A change that only removes
risk is a successful change.

### 3. Always choose the safest option
When two approaches are possible, pick the one with the lower security risk —
even if it is slower, less elegant, or delays a feature. When in doubt, default
to the more conservative choice and state the reasoning out loud before
proceeding.

### 4. No known concern ships, no matter how minor
If you identify any security concern — however small, theoretical, or
low-severity — it must be resolved, or explicitly accepted by the user, *before*
pushing. "I'll fix it later" is not acceptable. A push that carries an
unresolved, unaccepted concern is a failure of the goal.

**Autonomy vs. escalation.** To keep grinding without stopping on every minor
finding:
- If a concern is **P3 / low-severity** and you can safely fix or remove it
  without changing behavior, **do so** and note it in the PR description. Do
  not stop to ask.
- If a concern is **P0–P2**, or requires a judgment call (accepting risk,
  changing behavior, a design tradeoff), **block the push and surface it to the
  user** with the finding, your proposed options, and a recommendation. Wait
  for a decision before proceeding.

### 5. Git discipline via pull requests
All work flows through pull requests. Do not push directly to protected
branches (`main` / `master`). Open a PR, review its diff yourself for security
and correctness, and require review/approval before merging. Never merge your
own PR without an explicit review pass. Keep commits atomic and well-described.
Follow the branch naming already in use (e.g. `security/sec-NNN-...`).

## Scope of "security"
Application code, authentication/secrets handling, dependencies and supply
chain (pinned versions, `govulncheck` / audit output), configuration and
deployment artifacts (Dockerfile, compose files, `.env`), and secrets. If a
finding touches any of these, it is in scope.

## Definition of done for any change
The change is security-reviewed, all identified concerns are resolved or
explicitly accepted by the user, tests pass, and the merge has gone through PR
review — not just that the feature works.

## `audits/` is a self-managed directory
Treat `audits/` as the project's living security work queue, not a static
record. The existing reports (`00-index.md` … `09-*.md`) are from 2026-05 and
their wave-3 fixes are already committed — treat them as historical context,
not as an open list. Re-audit to discover current findings.

- The security work queue lives in `.kanban/board.db`, an SQLite task store
  used by the Kanbanium app. Inspect/update it with `sqlite3 .kanban/board.db`
  or through the Kanbanium UI.
- Open security concerns are represented as tasks with `status='todo'` or
  `'in-progress'`, ordered by `priority` and `ord` (smaller `ord` = higher).
  Each finding task uses a short ID (`SEC-NNN`) and is titled
  `[FINDING] SEC-NNN: <one-line summary>`.
- Each session: pick the highest-priority open item, work it to
  resolved-or-accepted, verify, PR, review, merge, then mark the task `done`.
- When you discover a new concern, add it as a finding task to the board; don't
  chase it mid-item.
- Keep the open queue short and the finish line visible. **Target state (the
  result):** no `todo`/`in-progress` finding tasks, `govulncheck ./...` is
  clean, CI is green on the default branch.

## Auditor (background, read-only)
A second instance may run in the background as an **adversarial auditor**. Its
contract is strict:

- **Read-only.** It never edits code, never commits, never pushes, never opens
  PRs.
- It scans the codebase and recent diffs and files **new findings only** into
  `.kanban/board.db` as tasks. Each finding gets a title like
  `[FINDING] SEC-NNN: <one-line summary>`, a `description` containing severity
  (`P0`/`P1`/`P2`/`P3`), location, and short explanation, `priority` set to
  `high`/`medium`/`low` respectively, `status='todo'`, and an `ord` that places
  it near the top of the open queue. It does not change the status of any other
  task.
- If nothing new is found, the auditor appends a one-line
  `no new findings — <timestamp>` note to the standing `[AUDIT-PASS]` log task
  (create that task once as `status='done'`, `priority='low'` if it does not
  exist).
- The auditor runs on a **~20-minute loop**. Expect new findings on the board
  throughout your session. Do not run your own broad audit pass that duplicates
  the auditor's — focus on the items already on the board. You may still flag a
  concern you happen to notice while working, but add it to the board as a
  finding task rather than opening a parallel audit.
- The worker (this file) triages any new `[FINDING]` tasks at the start of each
  session: confirm/prioritize, set `ord`, and mark them ready for work. Re-check
  the board before each PR/merge in case the auditor filed something relevant
  during your work.
- This separation prevents write contention. Two writers on the same repo is
  failure; one writer + one read-only reporter is independent review.

## Wrapper prompt (how to invoke this)
> Work toward the objectives defined in `GOAL.md`. Read it now and re-read it
> before any push. The non-negotiable rule: no push happens while any security
> concern — however minor — is unresolved or unaccepted. Run a continuous
> review loop: assess security → fix/remove before adding → PR → review diff →
> merge only when clean. First step of each session: triage any new
> `[FINDING]` tasks the auditor filed in `.kanban/board.db` (set priority and
> `ord` so the most severe item is at the top), then work the highest-priority
> open item to resolved-or-accepted.