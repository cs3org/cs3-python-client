# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys

sys.path.insert(0, os.path.abspath("/Users/account/Documents/project/code_from_git/python-cs3apis"))
sys.path.insert(0, os.path.abspath("/Users/account/Documents/project/code_from_git/cs3-python-client/src/"))

project = "cs3client"
copyright = "2024, Rasmus Welander, Diogo Castro, Giuseppe Lo Presti"
author = "Rasmus Welander, Diogo Castro, Giuseppe Lo Presti"
release = "0.0.1"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",  # Optional for Google/NumPy-style docstrings
    "sphinx.ext.viewcode",  # Optional to add links to source code
]

templates_path = ["_templates"]
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "alabaster"
html_static_path = ["_static"]
