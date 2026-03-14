# Safe Windows Security Audit

A safe, read-only PowerShell audit script for assessing Windows baseline security posture without making configuration changes or breaking operational dependencies.

## Purpose

This repository provides PowerShell-based audit tooling to inspect Windows security posture safely.

The scripts in this repository are designed to:

- inspect, not modify
- validate exposure before remediation
- reduce the risk of self-inflicted hardening damage
- support disciplined security engineering and operational resilience

## Current script

- `Safe-Consolidated-Windows-Security-Audit.ps1`

This script performs a read-only audit of:

- Windows Defender status
- Firewall posture
- BitLocker
- Secure Boot
- TPM
- RDP exposure
- SMBv1 state
- Local administrator exposure
- Built-in Administrator account state
- Windows Update service
- Listening ports
- Network profile state
- PowerShell logging posture
- Recent failed logons
- Deep exposure analysis for ports 135, 139, and 445
- SMB shares, related services, firewall rules, and NetBIOS posture

## Safety boundary

This is an inspection script only.

It does **not**:

- modify registry settings
- change firewall rules
- disable or enable services
- modify Defender configuration
- alter VPN, DNS, or adapter settings
- change user or admin rights

## Why this exists

Too many security changes are applied blindly, without understanding dependencies.  
That often leads to degraded functionality, broken VPNs, or weaker real-world resilience.

This project follows a different principle:

**measure first, understand second, change last.**

## How to run

Open PowerShell as Administrator and run the script directly.

Example:

```powershell
.\Safe-Consolidated-Windows-Security-Audit.ps1
