# Vedette cookbook

Short recipes for the main things you do with Vedette. Each one states its goal and what you need before you start, then walks through numbered steps with a screenshot; the numbers drawn on a screenshot (①, ②…) are explained right under it. Each recipe ends with how to check that it worked.

The same recipes are in the Vedette interface under **Help** in the menu, and each main screen links to its recipe. They work offline: nothing is fetched from the Internet.

| Recipe | You want to |
| --- | --- |
| [Install Vedette and finish the setup wizard](01-install-and-setup.md) | put Vedette on a machine and set it up |
| [Add your devices (and an agent on a server)](02-add-devices-and-agents.md) | get every device you care about into the list |
| [Read a finding and fix it](03-read-and-fix-a-finding.md) | know what to fix first, fix it, and have Vedette close it |
| [Get alerts by email, Telegram, Zalo or Slack](04-alerts-email-telegram-zalo.md) | be told when an exploited vulnerability matches your devices |
| [Check what your company exposes to the Internet](05-external-exposure-scan.md) | scan your public IP or domain |
| [Set a trap for intruders](06-honeypot-decoys.md) | catch someone moving around your network |
| [Send a weekly security report](07-periodic-report.md) | email a summary every week or month |
| [Keep Vedette up to date, back it up, restore it](08-updates-backup-restore.md) | update, roll back, back up and restore the box |

The screenshots come from the sample data (setup wizard → **Use sample data**), never from a real network. To regenerate them after a change to the interface, run `make cookbook-shots` (or `make cookbook-shots ONLY=03` for one recipe).
