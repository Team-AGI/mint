# POL-I-08 Windows isolation fixture

This fixture contains two synthetic text files and a diagnostic MCP tool. It gives the WebAssembly guest one read-only directory. The internal sample, host environment, and guest networking are unavailable to the guest. This runtime is scoped to the designated trial server and Windows device.

## Build the trial bundle on Windows

Use Python 3.13 and run `python build_windows_bundle.py <new-output-directory>` from this directory. The build installs the pinned Windows Wasmtime wheel into the bundle and writes `profile.json` with the hashes of the bundle files. It prints the profile SHA-256 for the gateway configuration.

Install the bundle as `pol-i08-trial` next to `local-runner.py` in the managed Windows kit. Administrators or SYSTEM must own the directory and its contents. The employee account needs read and execute access. The agent checks those permissions, the file hashes, and the read-only mount profile before requesting permission to launch.

## Register the fixture and run the test

Submit the `fixtures/pol-i08-windows` directory from the repository's default branch via the MINT repository intake, select stdio, and use the usual source validation and approval flow. Include `MINT_I08_WINDOWS_TRIAL=1` in the signed local execution settings. Set these values in the test deployment before running on the designated device.

| Setting | Value |
|---|---|
| `MINT_I08_WINDOWS_TEST_SERVER` | ID assigned to the approved sample MCP server |
| `MINT_I08_WINDOWS_TEST_DEVICE` | Enrolled Windows test endpoint ID |
| `MINT_I08_WINDOWS_PROFILE_SHA256` | SHA-256 printed by the bundle builder |
| `MINT_I08_OPA_URL` | OPA connection-policy findings endpoint |

For each employee request, correlate the local job ID, the OPA decision ID, the returned tool result, and the sample hash or process evidence. The three file cases are public read, public write, and internal-only read. Test an unavailable isolation profile against the same trial configuration and confirm that the start request is denied before a process starts.
