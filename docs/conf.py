import sys
from datetime import datetime

# Do not touch these. They use the local asyncprawcore over the global asyncprawcore.
sys.path.insert(0, ".")
sys.path.insert(1, "..")

from asyncprawcore import __version__

always_use_bars_union = True
autodoc_typehints = "description"
copyright = datetime.today().strftime("%Y, Joel Payne")
exclude_patterns = ["_build"]
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
    "sphinxcontrib_trio",
]
html_theme = "furo"
intersphinx_mapping = {
    "aiohttp": ("https://docs.aiohttp.org/en/stable/", None),
    "python": ("https://docs.python.org/3", None),
}
nitpicky = True
project = "asyncprawcore"
release = __version__
version = ".".join(__version__.split(".", 2)[:2])
