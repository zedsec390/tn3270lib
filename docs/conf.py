"""Sphinx configuration for tn3270lib (Read the Docs)."""

import os
import sys

sys.path.insert(0, os.path.abspath('..'))

project = 'tn3270lib'
copyright = '2015–2026, Phil Young'
author = 'Phil Young'
release = '0.3.0'
version = '0.3.0'

extensions = [
    'myst_parser',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx_autodoc_typehints',
]

myst_enable_extensions = ['colon_fence']
myst_heading_anchors = 2

autosummary_generate = True
autodoc_member_order = 'bysource'
autodoc_typehints = 'description'
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_use_param = True
napoleon_use_rtype = False

templates_path = []
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'furo'
html_title = 'tn3270lib'
html_static_path = []
