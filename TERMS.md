# Vedette terms of use

Version: 2026-11-14

Vedette asks you to read and accept these terms once, when the box is first set up or restored from a backup. Settings → General shows when they were accepted and which version.

## Free software, provided as-is

Vedette is free, open-source software under the Apache License 2.0 (the LICENSE file). It is provided as-is, without warranty of any kind. Its author is not responsible for how you use it, nor for any damage, data loss, outage or legal claim that results from that use.

## A security testing device: you are responsible for every scan

- Vedette is a security testing tool. It tests your systems the way an attacker would, with nmap, nuclei, ZAP and OpenVAS.
- On a domain you verified or the box's public IP, once you accept that target's testing terms, every scan is a deep scan at the full depth of those tools: every port, service version detection, vulnerability checks, including checks that confirm a flaw by sending the exploit request itself in a harmless form (for example reading a file or running a harmless command) and checks for known authentication bypasses, and web scanning that follows links and may submit forms. A deep scan can slow down a service, fill it with test data and set off your security alarms.
- Disruptive checks are off by default and run only when you tick them for a target: denial of service, password guessing, sign-in attempts with default or well-known passwords, and exploit checks built to send data that changes something on the target. They can crash a service, lock accounts, change data or take a device offline.
- A verified name is scanned at full depth on every IP address it resolves to. Verifying a name proves you control its DNS, not that you own the machines behind it or may test them. With shared or cloud hosting, a CDN or a proxy, that address can also serve other people's systems: you are responsible for having the provider's permission. Vedette does not check who owns those addresses. A name that points (CNAME) to a name outside your domain is scanned at whatever address the owner of that other name sets; the disruptive checks never run on an address reached only that way.
- Scan only networks, devices, addresses and domains you own or are authorized to test. Scanning systems without permission can be illegal and can get the box's IP address reported or blocked.

## Your data stays on the box

Your devices, findings, logs and keys stay on the box. The only data that leaves it is listed in [PRIVACY.md](PRIVACY.md), which the app also shows under Settings → Privacy, with a switch for each flow that can be turned off.

## Accepting

By ticking "I have read, understood and agree to the terms of use" you confirm that you have read these terms, that you understand them, and that you accept them for this box and for the people you let use it.
