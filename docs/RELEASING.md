# Releasing ctxsentry

## One-time PyPI setup (Trusted Publishing)

No API token is stored anywhere — PyPI trusts this repo's GitHub Actions via
OIDC. Configure it once:

1. Sign in at <https://pypi.org> (create an account if needed).
2. Go to **Your projects → Publishing** (or, for a brand-new name,
   <https://pypi.org/manage/account/publishing/>) and add a **pending publisher**:
   - PyPI Project Name: `ctxsentry`
   - Owner: `EivinDDu`
   - Repository name: `ctxsentry`
   - Workflow name: `publish.yml`
   - Environment name: *(leave blank)*
3. That's it. The first published Release will create the project and upload to
   it; afterwards the pending publisher becomes a normal trusted publisher.

## Cutting a release

1. Update `CHANGELOG.md` (move `Unreleased` to the new version + date).
2. Bump the version in **both** `pyproject.toml` and
   `src/ctxsentry/__init__.py`.
3. Verify locally:
   ```bash
   pip install -e ".[dev]"
   pytest -q
   ctxsentry bench --min-recall 1.0 --max-fp-rate 0.0 --min-rule-accuracy 1.0
   ctxsentry scan . --fail-on high
   python -m build && python -m twine check dist/*
   ```
4. Commit, then tag and push:
   ```bash
   git tag -a vX.Y.Z -m "ctxsentry X.Y.Z"
   git push && git push origin vX.Y.Z
   ```
5. Create the GitHub Release for the tag. Publishing it triggers
   `.github/workflows/publish.yml`, which builds and uploads to PyPI.
6. Confirm: `pip index versions ctxsentry` (or check the PyPI page).

## Version scheme

Semantic versioning. Pre-1.0: new detectors / rules and CLI additions are minor
bumps; a rule that changes existing findings for the same input, or any breaking
CLI change, is also a minor bump and called out in the changelog.
