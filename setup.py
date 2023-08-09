"""asyncprawcore setup.py."""

from codecs import open
from os import path

from setuptools import setup

PACKAGE_NAME = "asyncprawcore"
HERE = path.abspath(path.dirname(__file__))
with open(path.join(HERE, "README.rst"), encoding="utf-8") as fp:
    README = fp.read()
with open(path.join(HERE, PACKAGE_NAME, "const.py"), encoding="utf-8") as fp:
    VERSION_LINE = next(line for line in fp.readlines() if "__version__" in line)
    VERSION = VERSION_LINE.split("=")[-1].strip().replace('"', "")

extras = {
    "ci": ["coveralls"],
    "lint": ["black", "flake8", "isort", "pre-commit", "pydocstyle", "flynt"],
    "test": [
        "aiofiles ==23.*",
        "mock ==4.*",
        "pytest ==7.*",
        "pytest-asyncio ==0.18.*",
        "pytest-vcr ==1.*",
        "urllib3 ==1.*",
        "vcrpy ==4.2.1",
        "urllib3 ==1.26.*, <2",
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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    description="Low-level asynchronous communication layer for Async PRAW 7+.",
    extras_require=extras,
    install_requires=["aiohttp <4", "yarl"],
    python_requires=">=3.8",
    keywords="praw reddit api async",
    license="Simplified BSD License",
    long_description=README,
    packages=[PACKAGE_NAME],
    url="https://github.com/praw-dev/asyncprawcore",
    version=VERSION,
)
