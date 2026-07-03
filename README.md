# Microsoft Store Package Execution POC

This repository contains a proof-of-concept Windows dropper that copies a supplied executable to a seemingly benign system path and then launches it through PowerShell by abusing the Microsoft Store package-execution path exposed by `Invoke-CommandInDesktopPackage`.

> Warning: This project is intended for defensive research, public awareness, and authorized testing only. It should not be used to bypass security controls on systems you do not own or are not explicitly authorized to assess.

## What the program does

The workflow in [bypass/src/main.cpp](bypass/src/main.cpp) is roughly:

1. Accepts a target executable as an argument.
2. Copies that executable into a randomly chosen Windows path such as a `System32`, `Temp`, or `ProgramData` location.
3. Attempts to reduce forensic visibility by disabling or tampering with common telemetry and logging surfaces:
   - PowerShell logging and script-block logging
   - Windows event logging
   - ETW/AMSI-related hooks and logging paths
   - Prefetch and event-log artifacts
4. Builds a PowerShell payload that calls `Invoke-CommandInDesktopPackage` using the Microsoft Store package family name `Microsoft.WindowsStore_8wekyb3d8bbwe` with `PreventBreakaway=$true`.
5. Executes that payload through WMI, Task Scheduler, or a direct `CreateProcessW` fallback.

The core behavior is visible in the payload construction near the `Invoke-CommandInDesktopPackage` call in [bypass/src/main.cpp](bypass/src/main.cpp).

## Why this matters

This sample is relevant because it demonstrates a public-awareness case of how a trusted Windows package-execution primitive can be repurposed in a way that complicates standard detection and execution control assumptions. The technique is not a conventional memory-corruption exploit. Instead, it highlights a trust-boundary problem: a legitimate Windows capability can be abused to run code under a package context that may be perceived as more trusted or less suspicious than a normal process launch.

From a defensive perspective, the behavior is important because it can be observed through:

- suspicious PowerShell execution and encoded commands
- WMI `Win32_Process` creation activity
- Task Scheduler task registration and execution
- unexpected file drops into `System32`, `Temp`, `ProgramData`, or other trusted locations
- changes to AMSI/ETW/PowerShell logging settings

## Vulnerability / abuse angle

The underlying mechanism here is an abuse of the AppX/desktop-bridge package execution path, not a classic local privilege-escalation bug in the usual CVE sense. In practical terms, the issue is that Windows exposes a package-execution interface that is intended for package debugging and app-hosting scenarios, but that interface can be abused to launch arbitrary commands under a package context.

That makes this a useful public-awareness example for defenders and security researchers because it shows how execution control assumptions can be bypassed when a trusted OS feature is repurposed for code execution.

## Public references and CVE-adjacent context

The following references are useful for understanding the underlying Windows behavior and the broader security context:

- Microsoft Learn: `Invoke-CommandInDesktopPackage`
  - https://learn.microsoft.com/en-us/powershell/module/appx/invoke-commandindesktoppackage
- Microsoft Learn: AppX / package deployment documentation
  - https://learn.microsoft.com/en-us/windows/msix/
- Microsoft Learn: desktop-bridge and packaged app guidance
  - https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-root
- NVD search for Windows AppX / AppContainer / PowerShell package-execution issues
  - https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=Windows%20AppX%20AppContainer
- NVD search for PowerShell / AMSI / execution-control related Windows issues
  - https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=PowerShell%20AMSI%20Windows

There is no single CVE that cleanly maps to this exact sample’s workflow. Public reporting typically treats this as an abuse of Windows package-execution and AppContainer-related behavior, and related issues are often discussed alongside broader Windows AppX, package-identity, PowerShell, and AMSI abuse research.

## Repository layout

- [bypass/src/main.cpp](bypass/src/main.cpp) — main dropper logic and PowerShell payload generation
- [bypass/src/backup_original.cpp](bypass/src/backup_original.cpp) — backup of the earlier implementation
- [bypass/headers/cloakwork.h](bypass/headers/cloakwork.h) and [bypass/headers/xorstr.hpp](bypass/headers/xorstr.hpp) — helper headers used by the sample

## Disclaimer

This software is provided for educational, security research, and authorized testing purposes only. The authors and contributors assume no liability for misuse, system damage, or issues arising from deploying this code in production or untrusted environments.
