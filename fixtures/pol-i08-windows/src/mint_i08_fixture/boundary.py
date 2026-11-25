from pathlib import Path
import stat

profile = {"preopens": [{"path": "public", "guest": "/public", "read_only": True}],
           "inherit_env": False, "verified": True}


def checked_mount(config: dict, root: Path) -> Path:
    if config != profile or config.get("verified") is not True:
        raise ValueError("verified read-only profile required")
    public = root / "public"
    sample = public / "sample.txt"
    for path in (root, public, sample):
        if path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("reparse point in sandbox path")
    if not public.is_dir() or sorted(item.name for item in public.iterdir()) != ["sample.txt"]:
        raise ValueError("unexpected entries in the sandbox mount")
    if not sample.is_file() or sample.stat().st_nlink != 1:
        raise ValueError("unexpected sample file type or links")
    return public
