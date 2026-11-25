"""Isolated MCP stdio trial for the two synthetic POL-I-08 samples."""
import json
from pathlib import Path
import sys

from wasmtime import Config, Engine, Linker, Module, Store, WasiConfig

from .boundary import checked_mount

runtime = Path(__file__).resolve().parent
tool = {
    "name": "sample_access",
    "description": "Check one of the fixed, synthetic POL-I-08 samples inside Windows WASI.",
    "inputSchema": {"type": "object", "properties": {
        "sample": {"enum": ["public", "internal-only"]}, "operation": {"enum": ["read", "write"]},
    }, "required": ["sample", "operation"], "additionalProperties": False},
}


def access(arguments, engine, linker, fixture, config, root):
    cases = {("public", "read"): (3, 0), ("public", "write"): (3, 1), ("internal-only", "read"): (4, 0)}
    choice = (arguments.get("sample"), arguments.get("operation"))
    if set(arguments) != {"sample", "operation"} or choice not in cases:
        raise ValueError("Unsupported fixed sample request")
    store = Store(engine)
    store.set_fuel(100_000)
    wasi = WasiConfig()
    wasi.preopen_dir(str(checked_mount(config, root)), "/public", False)
    store.set_wasi(wasi)
    instance = linker.instantiate(store, fixture)
    errno = instance.exports(store)["access"](store, *cases[choice])
    return {"content": [{"type": "text", "text": json.dumps({"file_access": errno == 0, "wasi_errno": errno})}],
            "isError": errno != 0}


def main(root=runtime, mount_profile=runtime / "mount-profile.json"):
    config = json.loads(mount_profile.read_text(encoding="utf-8"))
    checked_mount(config, root)
    settings = Config()
    settings.consume_fuel = True
    engine = Engine(settings)
    fixture = Module.from_file(engine, str(runtime / "sample-io.wat"))
    linker = Linker(engine)
    linker.define_wasi()

    def handle(request):
        method = request["method"]
        if method == "initialize":
            return {"protocolVersion": request["params"]["protocolVersion"], "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mint-pol-i08-windows-wasi", "version": "1.0.0"}}
        if method == "tools/list":
            return {"tools": [tool]}
        if method == "tools/call" and request["params"].get("name") == tool["name"]:
            return access(request["params"].get("arguments", {}), engine, linker, fixture, config, root)
        if method == "ping":
            return {}
        raise ValueError("Unsupported fixture method")

    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        try:
            response = {"result": handle(request)}
        except (ValueError, KeyError, TypeError):
            response = {"error": {"code": -32602, "message": "Unsupported fixture request"}}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], **response}), flush=True)


if __name__ == "__main__":
    main()
