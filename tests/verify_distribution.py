"""Check release archives without extracting them or executing archive content."""

import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from wagtail_soca import __version__

REQUIRED = {
    "wagtail_soca/__init__.py",
    "wagtail_soca/migrations/0001_initial.py",
    "wagtail_soca/migrations/0002_socasettings.py",
    "wagtail_soca/migrations/0003_claiminspection.py",
    "wagtail_soca/templates/wagtailadmin/login.html",
    "wagtail_soca/templates/wagtail_soca/settings.html",
    "wagtail_soca/templates/wagtail_soca/error.html",
    "wagtail_soca/management/commands/soca_check.py",
    "wagtail_soca/management/commands/soca_cleanup.py",
}


def check_paths(names):
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Unsafe archive path")
        if any(part in (".git", ".env", "__pycache__") for part in path.parts) or path.suffix in (
            ".pem",
            ".key",
            ".sqlite3",
            ".pyc",
        ):
            raise ValueError("Unexpected private or generated archive member")


def main(directory):
    directory = Path(directory)
    with zipfile.ZipFile(directory / f"wagtail_soca-{__version__}-py3-none-any.whl") as archive:
        names = set(archive.namelist())
        check_paths(names)
        if not REQUIRED <= names or any(name.startswith(("tests/", "demo/")) for name in names):
            raise ValueError("Wheel resources or package boundaries are incorrect")
        metadata_name = f"wagtail_soca-{__version__}.dist-info/METADATA"
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        if metadata["Version"] != __version__ or metadata["License-Expression"] != "AGPL-3.0-only":
            raise ValueError("Incorrect release metadata")
        if not any(name.endswith("/licenses/LICENSE") for name in names):
            raise ValueError("Missing packaged license")
    with tarfile.open(directory / f"wagtail_soca-{__version__}.tar.gz") as archive:
        names = {"/".join(PurePosixPath(name).parts[1:]) for name in archive.getnames()}
        check_paths(archive.getnames())
        if not REQUIRED | {"LICENSE", "README.md", "Containerfile", "tests/run-tests.sh"} <= names:
            raise ValueError("Incomplete source distribution")
    print(f"Wheel and source distribution {__version__} verified")


if __name__ == "__main__":
    main(sys.argv[1])
