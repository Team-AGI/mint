"""Build the unsigned POL-I-08 fixture bundle for protected Windows installation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def build(target: Path) -> str:
    source = Path(__file__).resolve().parent / "src" / "mint_i08_fixture"
    target.mkdir()
    runtime = target / "runtime"
    package = runtime / "mint_i08_fixture"
    shutil.copytree(source, package, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", "public", "internal-only", "mount-profile.json"))
    shutil.copytree(source / "public", target / "public")
    shutil.copytree(source / "internal-only", target / "internal-only")
    shutil.copyfile(source / "mount-profile.json", runtime / "mount-profile.json")
    (runtime / "sandbox_mcp.py").write_text(
        'from pathlib import Path\nfrom mint_i08_fixture.__main__ import main\n'
        'runtime_dir = Path(__file__).resolve().parent\n'
        'main(runtime_dir.parent, runtime_dir / "mount-profile.json")\n', encoding="utf-8")

    subprocess.run([sys.executable, "-m", "pip", "install", "--only-binary=:all:", "--no-deps",
                    "--no-compile", "--target", str(target / "dependencies"), "wasmtime==51.0.0"],
                   check=True)

    profile = target / "profile.json"
    files = {item.relative_to(target).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
             for item in target.rglob("*") if item.is_file()}
    profile.write_text(json.dumps(files, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return hashlib.sha256(profile.read_bytes()).hexdigest()


if __name__ == "__main__":
    if sys.platform != "win32" or len(sys.argv) != 2:
        raise SystemExit("Run on Windows with one new output directory.")
    print(build(Path(sys.argv[1]).resolve()))
