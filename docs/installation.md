# Installation

## From PyPI (when published)

```bash
pip install tn3270lib
```

Extra IBM SBCS codecs (beyond the encodings in the Python standard library):

```bash
pip install tn3270lib[i18n]
```

That extra pulls in the [`ebcdic`](https://pypi.org/project/ebcdic/) package.

## From a source checkout

```bash
pip install .
pip install '.[i18n]'
pip install '.[docs]'    # Sphinx, MyST, Furo
```

Build an sdist and wheel locally (does not upload):

```bash
python3 -m pip install build twine
python3 -m build
python3 -m twine check dist/*
```

Documentation:

```bash
pip install '.[docs]'
sphinx-build -b html docs docs/_build/html
# or: make -C docs html
```

Requires Python 3.8+ for the library. The docs extra uses Sphinx 8, which needs
Python 3.10+ (Read the Docs builds with 3.12).
