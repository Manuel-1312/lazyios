# Releasing

The release workflow builds and attests the binaries and the `SHA256SUMS` file, then leaves
them in the run's `release-files` artifact. It does not publish a GitHub release: a release
created by the workflow shows `github-actions[bot]` as its author, so the maintainer creates it.

1. Bump `version` in `pyproject.toml` and `src/lazyios/__init__.py`, run `uv lock`, rename
   "Unreleased" in `CHANGELOG.md`, merge.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`, wait for the `release` run to finish.
3. `gh run download <run-id> -n release-files -D out`
4. `gh release create vX.Y.Z out/* --verify-tag --title vX.Y.Z --notes-file <notes>`
   (the notes are the version's section of `CHANGELOG.md`).

PyPI publishing stays in the workflow and needs the `pypi` environment approved on GitHub.
Check a binary with `gh attestation verify <file> --repo Manuel-1312/lazyios` and
`sha256sum -c SHA256SUMS`.
