# Vedette terms of use

Version: 2026-11-26

Vedette asks you to read and accept these terms once, when the box is first set up or restored from a backup. Settings → General shows when they were accepted and which version.

## Free software, provided as-is

Vedette is free, open-source software under the Apache License 2.0 (the LICENSE file). It is provided as-is, without warranty of any kind. Its authors are not responsible for how you use it, nor for any damage, data loss, outage or legal claim that results from that use.

## A security testing device: you are responsible for every scan

- Vedette is a security testing tool. It tests your systems the way an attacker would, with nmap, nuclei, ZAP and OpenVAS.
- On a domain you verified or the box's public IP, once you accept that target's testing terms, every scan is a deep scan at the full depth of those tools: every port, service version detection, vulnerability checks, including checks that confirm a flaw by sending the exploit request itself in a harmless form (for example reading a file or running a harmless command), checks for known authentication bypasses and the public anonymous login a service may offer (for example anonymous FTP); some checks, OpenVAS's in particular, may write a harmless test file or record to confirm a flaw and then try to remove it; and web scanning that follows links and may submit forms. A deep scan can slow down a service, fill it with test data and set off your security alarms. Vedette also scans the target by itself on the schedule set on its page (weekly unless changed), never with the disruptive checks below, until that schedule is turned off.
- The testing terms of a target also cover the disruptive checks, and they run only in a scan a person starts (Scan now), never in a scheduled scan: denial of service, password guessing, sign-in attempts with default or well-known passwords, and the exploit checks of nuclei and nmap that send more than a harmless read, such as POST exploit requests that may create or change data and SQL injection probes. They can crash a service, lock accounts, change data or take a device offline.
- A verified name is scanned at full depth on every IP address it resolves to. Verifying a name proves you control its DNS, not that you own the machines behind it or may test them. With shared or cloud hosting, a CDN or a proxy, that address can also serve other people's systems: you are responsible for having the provider's permission. Vedette does not check who owns those addresses. A name that points (CNAME) to a name outside your domain is scanned at whatever address the owner of that other name sets. On a domain, the disruptive checks run only on an address that is a proven public IP of this box; every other address it resolves to (hosting, a CDN, a proxy, or a name that points outside your domain) gets the deep scan without them.
- Scan only networks, devices, addresses and domains you own or are authorized to test. Scanning systems without permission can be illegal and can get the box's IP address reported or blocked.

## What Vedette tells you, and what it does not

- Vedette alerts you when a CVE on a list of vulnerabilities being exploited (CISA KEV, and VulnCheck KEV if you turn it on) matches a device it knows, whatever the CVE's age. For such a CVE that was published, and added to that list, more than 12 months ago, a match on the product name alone, without a version Vedette could compare, is not reported.
- It also lists, without alerts, on the page Recommended updates, the CVEs published in the last 12 months that affect the exact version a device reports: the version its agent reads (for an Ubuntu or Debian package, compared with the fixed version that distribution's own security data gives for the device's release), one you entered, or one the device states itself. Among them it marks those likely to be exploited (an EPSS score of 10% or more: FIRST's estimate of the chance of exploitation in the next 30 days). A version guessed from what a service announces on the network, or a product name alone, is not enough for this list. Older CVEs that are not on an exploited list are listed only when a scan found them. These lists help you plan updates; they are not a promise that a CVE left off them is harmless.
- Matches come from public data (CISA, FIRST, NVD, CVE.org, Ubuntu, Debian) and from what Vedette can see of your devices. Public data has gaps and mistakes, and a device or version Vedette cannot see is not checked. Because of these rules, an old vulnerability Vedette cannot confirm is not reported. Vedette does not find every vulnerability, and an empty list does not mean your systems are safe.

## Your data stays on the box

Your devices, findings, logs and keys stay on the box. The only data that leaves it is listed in [PRIVACY.md](PRIVACY.md), which the app also shows under Settings → Privacy, with a switch for each flow that can be turned off.

## Accepting

By ticking "I have read, understood and agree to the terms of use" you confirm that you have read these terms, that you understand them, and that you accept them for this box and for the people you let use it.
