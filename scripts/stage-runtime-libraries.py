"""Stage native runtime libraries next to a built WutherCore executable."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATTERNS = ("*.dylib", "*.so", "*.so.*", "*.dll")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", default="release")
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        dest="required",
        help="Runtime library filename that must be staged; may be repeated.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        dest="sources",
        type=Path,
        help=(
            "Extra directory to stage libraries from; may be repeated. Needed when "
            "NSS was prebuilt outside the crate's OUT_DIR."
        ),
    )
    return parser.parse_args()


def discover(library_dirs: list[Path]) -> list[Path]:
    candidates: dict[str, Path] = {}
    for library_dir in library_dirs:
        for pattern in RUNTIME_PATTERNS:
            for source in library_dir.glob(pattern):
                if not source.is_file():
                    continue
                current = candidates.get(source.name)
                if current is None or source.stat().st_mtime_ns > current.stat().st_mtime_ns:
                    candidates[source.name] = source
    return [candidates[name] for name in sorted(candidates)]


def main() -> int:
    args = arguments()
    profile_dir = ROOT / "target" / args.target / args.profile
    build_dir = profile_dir / "build"
    if not profile_dir.is_dir():
        raise FileNotFoundError(f"build profile directory not found: {profile_dir}")

    # nss-rs writes NSS under the crate's OUT_DIR when it builds NSS itself. On
    # targets where CI supplies a prebuilt NSS through NSS_DIR the libraries sit
    # outside the target directory instead, so callers pass --source.
    library_dirs = list(build_dir.glob("*/out/dist/Release/lib"))
    for source_dir in args.sources:
        if not source_dir.is_dir():
            raise FileNotFoundError(f"runtime library source not found: {source_dir}")
        library_dirs.append(source_dir)

    staged: set[str] = set()
    for source in discover(library_dirs):
        destination = profile_dir / source.name
        shutil.copy2(source.resolve(strict=True), destination)
        staged.add(source.name)
        print(f"staged {source} -> {destination}")

    missing = sorted(set(args.required) - staged)
    if missing:
        raise FileNotFoundError(
            "required runtime libraries were not produced: " + ", ".join(missing)
        )

    print(f"staged {len(staged)} runtime libraries in {profile_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
