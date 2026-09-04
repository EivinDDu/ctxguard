# Pending CI workflow

`ci.yml` here is the GitHub Actions workflow for this repo. It is not yet at
`.github/workflows/` because the token used for the initial push lacked the
`workflow` OAuth scope.

To activate it:

```bash
gh auth refresh -h github.com -s workflow
mkdir -p .github/workflows
git mv .ci-pending/ci.yml .github/workflows/ci.yml
rmdir .ci-pending 2>/dev/null || git rm .ci-pending/README.md
git commit -m "ci: enable GitHub Actions workflow"
git push
```
