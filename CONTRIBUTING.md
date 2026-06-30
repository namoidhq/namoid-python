# Contributing to NamoID

Thanks for your interest in improving NamoID! This repo holds the
[`namoid`](https://pypi.org/project/namoid/) Python package, and is one of
several open-source projects under the
[`namoidhq`](https://github.com/namoidhq) org.

## Filing issues

Found a bug or have a feature request? Open an issue in this repo's
[Issues](../../issues) tab. Please search existing issues first, and include
enough detail for us to reproduce (package version, Python version, steps).
Security issues should **not** be filed publicly — see
[SECURITY.md](./SECURITY.md).

## Submitting a pull request

1. Fork and create a branch from `main`.
2. Make your change. Keep it focused — one logical change per PR.
3. Make sure the package builds and imports cleanly (see below).
4. Open the PR and link the related issue (e.g. `#123`).

We aim to review PRs promptly. Be patient and kind — this is maintained by a
small team.

## Local development

The package uses a [Hatch](https://hatch.pypa.io)/`hatchling` build backend and
targets Python 3.9+:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # editable install
python -m build             # build wheel + sdist (pip install build)
```

Publishing is done via manual-dispatch, tokenless OIDC — never commit PyPI
tokens or other secrets.

## Code of Conduct

By participating, you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE) that covers this project.

## Questions

Reach us at `hello@namoid.in` or see the docs at
[docs.namoid.in](https://docs.namoid.in).
