<div align="center">

<img src="assets/mint-logo.svg" width="84" alt="MINT">

# MINT

MCP Governance Gateway

[한국어](README.md) · English

![Version](https://img.shields.io/badge/version-1.0.3-1f4287)
![MCP](https://img.shields.io/badge/MCP-2025--11--25-1f4287)
![Docker](https://img.shields.io/badge/install-Docker%20Compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-1f4287)

</div>

MINT is a governance solution that manages MCP servers for AI agents within a company, from onboarding to disposal.
After reviewing and approving the MCP servers employees request, it applies them to the connection settings on employee PCs, and decides on and records every tool call before it runs.
When use ends, MINT blocks the connection and keeps the credential revocation results together with their evidence.

Security teams can see in the console who uses which MCP server for what purpose, and employees can use approved MCP servers right away without extra setup.
MINT currently supports only Claude Code and Codex CLI.

<p align="center">
  <img src="assets/architecture.png" alt="MINT overall architecture" width="100%">
</p>

## Contents

- [Key features](#key-features)
- [Supported environments](#supported-environments)
- [Getting started](#getting-started)
- [Operations](#operations)
- [Before you adopt MINT](#before-you-adopt-mint)
- [Documentation](#documentation)
- [License](#license)

## Key features

MINT supports MCP servers in the order they are used, from the onboarding request through deployment, tool use, call records, and termination and disposal.

### 1. MCP onboarding request and approval

Employees request the MCP server they need on the Onboarding screen of the console, stating the purpose and the data classification involved.
In the case of a remote MCP server, MINT summarizes the tools it provides and their terms of use in a report. In the case of an MCP server delivered as source code, the report contains the supply-chain check results for a pinned version.

Administrators review the report and approve it, setting which tools may be used, by whom, and until when.
By default, an administrator who is not the requester approves, so no single person both requests and approves.

<p align="center">
  <img src="assets/screenshots/onboarding-light.jpg" alt="MCP onboarding request screen" width="90%">
</p>

### 2. Deployment to employee PCs

Approved MCP servers are applied to the managed settings of Claude Code and Codex CLI through the MINT kit installed on employee PCs.
Employees do not need to enter MCP server addresses or credentials themselves. The gateway keeps the credentials needed for each MCP server separately and does not hand them to employees.

Administrators can change who may use each MCP server, or suspend it immediately, on the AI connection management screen.
On Windows and Linux, employees can use the `mint` command in a terminal to check the connection status, the MCP servers available to them, and their own call records, and to request a new MCP server.

### 3. Tool usage consent

For tools that require consent, employees review the purpose, the information they will enter, and the external destinations that information goes to before first use, and then decide whether to consent.
Consents and their expiry dates can be reviewed and changed on the Tool usage consent screen.

### 4. Call decisions and response protection

Every tool call that passes through the gateway is checked before it runs against the user, the tool type, the input, organization policy, and usage consent, and is decided as `allow`, `alert`, `restrict`, `pending approval`, or `block`.
For calls pending approval, an administrator reviews the details on the Dashboard and decides whether to run them.

When personal or secret information is found in a response, that part is masked before the response is returned. Responses that cannot be returned are withheld.
If the checks before execution cannot be completed, the call is blocked. If the response check after execution cannot be completed, the response is withheld.

### 5. Call records and security monitoring

Every decision and execution result is recorded in order in the audit record. The audit record prevents ordinary edits and deletions, and changes to it can be detected.
Employees can search their own calls and administrators can search all calls in the organization, viewing the decision result, the tool actually executed, and the response handling separately. Administrators can export the results as audit evidence.
Administrators can select the trace ID in a call's details to see each processing step the call went through in the gateway and how long each step took.

The Security monitoring screen shows alerts, incident report evidence, and the status of the SIEM integration.
When an unapproved MCP setting is found on an employee PC, an alert is raised, and the alert details link straight to the related screen.

<p align="center">
  <img src="assets/screenshots/call-records-light.jpg" alt="Call logs screen" width="90%">
</p>

### 6. Termination and disposal

To stop using an MCP server, the Termination and disposal screen blocks calls to that MCP server and lists the credentials and settings to revoke.
After completing revocation and collecting evidence, the administrator records the termination verdict and checks any remaining follow-up actions.

See [Console screenshots (Korean)](docs/user-guide/screenshots.md) for the actual console screens.

## Supported environments

| AI coding agent | Status |
| --- | --- |
| Claude Code | Supported |
| Codex CLI | Supported |

| Employee PC operating system | Installation | Status |
| --- | --- | --- |
| Windows 11 (x64) | Run the installer, approve User Account Control (UAC) once | Supported |
| Linux (Ubuntu 20.04 or later, x86-64, Python 3.8 or later) | Run the executable, enter the administrator password once | Supported |
| macOS | Run one command, enter the administrator password once | In testing |

| Gateway host | Requirements |
| --- | --- |
| Operating system | Linux x86_64 |
| Software | Docker Engine 24 or later, Docker Compose v2, git, openssl, python3 |
| Docker | MINT needs its own Docker environment. Do not share the same Docker with MCP runtimes of other services. |
| Recommended resources | 4 vCPU, 16 GB memory, 40 GB disk |
| Network | One internal IPv4 address reachable from employee PCs, and internet access for installation and onboarding checks |
| Ports | 443 (console, MCP connections, sign-in), 3128 (model API connections from AI coding agents) |

## Getting started

### 1. Install the gateway

Run the following on the Linux machine that will serve as the gateway.

```bash
git clone --branch v1.0.3 https://github.com/MCP-governance/mint.git
cd mint/deploy
./install.sh --bind <internal IPv4>
```

When installation finishes, the required settings and keys are created automatically, and the root certificate for console access is saved to `deploy/ca/root.crt`.
For installation options such as a DNS name or a trusted certificate, see [Gateway installation and operations (Korean)](deploy/README.md).

### 2. Sign in to the console

1. Register the root certificate `deploy/ca/root.crt` on the administrator PC. Before registering, obtain the fingerprint in `deploy/ca/root.sha256` through a separate channel and confirm it matches.
2. Open `https://<internal IPv4>/` in a browser and sign in as the administrator `root`.
3. The initial password is in `deploy/initial-admin-password`. After signing in, change it right away with Change password at the top of the console.
4. On the User management screen, add the administrator accounts that will share approvals, and the employee accounts.

### 3. Connect employee PCs

Employees sign in to the console, download the installer for their operating system from the PC connection setup screen, run it, and sign in with their MINT account.
The gateway address and certificate information are built into the installer, so nothing needs to be entered. Claude Code or Codex CLI and a model account are prepared separately, and the MINT sign-in and the model sign-in are done separately.

| Operating system | Installer | How to run |
| --- | --- | --- |
| Windows | `mcp-managed-setup-windows.exe` | Run the file and approve User Account Control once. If Windows shows an "Unknown publisher" warning, choose Run once more. |
| Linux | `mcp-managed-setup-linux` | Paste the command shown in the console into a terminal and enter the administrator password once. |
| macOS | `mcp-connect-macos.command` | Run the command shown in the console in a terminal and enter the administrator password once. Run it within 5 minutes of downloading. If it expires or fails, download a new file from the console. |

Windows and Linux install in simple mode by default, and once the installation check passes the PC can be used right away, depending on organization settings.
If stronger control is needed, choose isolated account mode in PC connection setup. PCs installed in isolated account mode and macOS PCs can be used after an administrator activates them on the Endpoint management screen.
For what gets installed and how to remove it, see the [Employee PC kit guide (Korean)](endpoint-agent/README.md).

## Operations

Administrators handle most operations in the web console.

| What you want to do | Console menu |
| --- | --- |
| Check to-do items and decision status, approve pending calls | Dashboard |
| Review and approve MCP onboarding requests | Adoption management (employees use Onboarding) |
| Set who may use each MCP server and suspend it, control built-in features and connectors | AI connection management |
| Search calls and export audit evidence | Call logs |
| See a call's processing steps and timing | Trace ID in Call logs (trace screen) |
| Check alerts, incident reports, SIEM integration | Security monitoring |
| Review the security policies in effect | Security management policies |
| Add accounts, suspend use, handle sign-up requests, reset passwords | User management |
| Activate employee PCs and check their status | Endpoint management |
| End usage relationships and review revocation evidence | Termination and disposal |
| Download employee PC installers | PC connection setup |

Gateway status checks, backup and restore, upgrades, and the LiteLLM integration are handled with the `deploy/mint.sh` command on the gateway host.
If the console cannot be reached, run `./mint.sh status` in `deploy/` to check status and `./mint.sh logs gateway` to check logs. The administrator password can be reset with `./mint.sh set-password root`.
The full command list is in [Gateway installation and operations (Korean)](deploy/README.md).

## Before you adopt MINT

| Topic | Details |
| --- | --- |
| Scope of control | MINT manages calls that pass through the gateway. PCs without the kit, unmanaged accounts, and built-in connectors of AI services are shown in the console with their control status, and must be controlled together with PC, network, and AI service settings. |
| Simple mode | It installs in the employee account and is easy to use, but it does not stop other programs on the PC from connecting outside without going through the gateway. If there is no PC security solution such as EDR or DLP, isolated account mode is recommended. |
| Approval | By default, an administrator other than the requester approves. An organization with only one administrator can set `ROOT_SOLO_APPROVAL` to `1` in `deploy/.env` so that the top-level administrator root can approve its own requests. Such approvals are marked separately in the audit record. |
| Trace screen | Trace data is a temporary record for investigating performance and failures, and is cleared when the gateway restarts. The audit record is the official record. Organizations with their own trace collector can change where traces are sent in the settings. |
| Termination verdict | The termination result is judged from the evidence collected and submitted. MINT does not directly verify that the MCP service provider actually revoked the credentials. |

## Documentation

The guides below are written in Korean.

| Document | Contents |
| --- | --- |
| [User guide](docs/user-guide/README.md) | Getting started, how to use each feature, and troubleshooting for employees and administrators |
| [Console screenshots](docs/user-guide/screenshots.md) | Actual console screens |
| [Gateway installation and operations](deploy/README.md) | Installation options, console certificate, operation commands, backup and upgrade |
| [Employee PC kit guide](endpoint-agent/README.md) | Installation and removal by operating system, using the `mint` command |
| [LiteLLM integration](addons/litellm/README.md) | Integration for organizations that also use LiteLLM |
| [Security policy](policy/README.md) | How the security policies included in MINT are organized |
| [Changelog](CHANGELOG.md) | Changes by version |
| [Versions and tags](docs/RELEASING.md) | How solution versions are distinguished from documentation history |

The MCP specification is available at [modelcontextprotocol.io](https://modelcontextprotocol.io).

## License

MINT is provided under the [MIT License](LICENSE). Anyone may use, copy, modify, and distribute it. The software is provided as is, without warranty of any kind, and the authors accept no liability arising from its use.
Third-party components included in MINT (OPA, Presidio, Caddy, Gitea, Jaeger, PostgreSQL, and others) are subject to their own licenses.
