# Release Notes

This directory is the **single source of truth** for release content
(Istio-style). One file per release: `releasenotes/<version>.md`
(no `v` prefix, e.g. `0.4.2.md`). Copy `TEMPLATE.md` to start.

## File format

```markdown
# Release <version>

date: YYYY-MM-DD

## Notes

- English bullets — become the GitHub Release body.

## 公告

- 中文要点 — 同步到官网公告栏（kdubbo.github.io）。
```

## How it is consumed

1. **GitHub Release** — pushing a tag `x.y.z` runs
   `.github/workflows/release.yaml`, which **fails** if
   `releasenotes/x.y.z.md` is missing, and otherwise uses the `## Notes`
   section as the release body. No more hand-edited release text in CI.

2. **Website announcement + version bumps** — run:

   ```bash
   make sync-website VERSION=x.y.z [WEBSITE_DIR=/path/to/kdubbo.github.io]
   ```

   This inserts the `## 公告` bullets as a new entry at the top of the
   website announcement board (`docs/latest/release/index.md`) and replaces
   the previous version number with the new one in all files listed in
   `release/sync-website.sh` (`VERSION_FILES`). The script is idempotent —
   re-running it is a no-op. Review the diff in the website repo, then
   commit and push it.

   The `sync_website` job in `release.yaml` does the same automatically on
   tag push and opens a PR against the website repo when the
   `WEBSITE_SYNC_TOKEN` secret is configured.

## Release flow

1. Open a PR adding `releasenotes/<version>.md` (edit release content here,
   review it like code).
2. Merge, then push the tag `<version>`.
3. CI creates the GitHub Release from the notes and syncs the website
   (or run `make sync-website` locally).
