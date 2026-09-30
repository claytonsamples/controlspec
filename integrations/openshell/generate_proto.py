"""Regenerate only the vendored, hash-pinned upstream protocol bindings."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import grpc_tools


def main() -> None:
    here = Path(__file__).resolve().parent
    manifest = json.loads((here / "proto" / "manifest.json").read_text())
    for name, digest in manifest["sha256"].items():
        if hashlib.sha256((here / "proto" / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"Upstream hash mismatch: {name}")
    dest = here.parents[1] / "backend/src/assurance/controlspec/openshell_demo/proto"
    dest.mkdir(parents=True, exist_ok=True)
    include = Path(grpc_tools.__file__).parent / "_proto"
    subprocess.run([
        sys.executable, "-m", "grpc_tools.protoc", f"-I{here / 'proto'}", f"-I{include}",
        f"--python_out={dest}", f"--pyi_out={dest}", f"--grpc_python_out={dest}",
        str(here / "proto/extension.proto"), str(here / "proto/supervisor_middleware.proto"),
    ], check=True)
    for path in [*dest.glob("*.py"), *dest.glob("*.pyi")]:
        text = path.read_text()
        for module in ("extension_pb2", "supervisor_middleware_pb2"):
            text = text.replace(f"import {module} as", f"from . import {module} as")
        path.write_text(text, encoding="utf-8", newline="\n")
    (dest / "__init__.py").write_text(
        '"""Generated pinned NVIDIA protocol bindings."""\n', encoding="utf-8", newline="\n",
    )


if __name__ == "__main__":
    main()
