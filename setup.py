"""asyncprawcore setup.py."""

from codecs import open
from os import path
from setuptools import setup


PACKAGE_NAME = "asyncprawcore"
HERE = path.abspath(path.dirname(__file__))
with open(path.join(HERE, "README.rst"), encoding="utf-8") as fp:
    README = fp.read()
with open(path.join(HERE, PACKAGE_NAME, "const.py"), encoding="utf-8") as fp:
    VERSION_LINE = next(
        line for line in fp.readlines() if "__version__" in line
    )
    VERSION = VERSION_LINE.split("=")[-1].strip().replace('"', "")

extras = {
    "ci": ["coveralls"],
    "lint": ["black", "flake8", "pre-commit", "pydocstyle"],
    "test": [
        "pytest-vcr",
        "vcrpy @ git+https://github.com/LilSpazJoekp/vcrpy.git@asyncpraw#egg=vcrpy-4.0.2",  # temporary fix
        "mock >=0.8",
        "pytest",
        "testfixtures >4.13.2, <7",
        "asynctest >=0.13.0",
    ],
}
extras["dev"] = extras["lint"] + extras["test"]

setup(
    name=PACKAGE_NAME,
    author="LilSpazJoekp,vikramaditya91",
    author_email="lilspazjoekp@gmail.com,vikramaditya91@gmail.com",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Low-level asynchronous communication layer for PRAW 4+.",
    extras_require=extras,
    install_requires=["aiohttp", "yarl"],
    keywords="praw reddit api async",
    license="Simplified BSD License",
    long_description=README,
    packages=[PACKAGE_NAME],
    url="https://github.com/praw-dev/asyncprawcore",
    version=VERSION,
)
