# Security Policy

## Native mods are unsandboxed by design
Packages of kind native-mod (.hnmod) contain Rust code that Horizon compiles into a custom game client. They run with your OS account's full privileges - NOT sandboxed. Install native mods only from sources you have read or trust; the launcher shows a red warning before building one. That is Horizon's native-mod design, not a defect of this project.

## Reporting
Use GitHub's "Report a vulnerability" (the Security tab of this repository) for anything sensitive; regular issues are fine for the rest. Please do not post exploit details publicly before we acknowledge.

## Scope
This repository's code only. Vulnerabilities in the Horizon game itself belong to https://github.com/horizon-rust/horizon (or the project's Discord).

## Note
horizon-inspector never executes mod packages during inspection: the analysis is static (archive structure, manifests, checksums, signatures).
