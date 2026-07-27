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
    return parser.parse_args()


def discover(build_dir: Path) -> list[Path]:
    candidates: dict[str, Path] = {}
    for library_dir in build_dir.glob("*/out/dist/Release/lib"):
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

    staged: set[str] = set()
    for source in discover(build_dir):
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
