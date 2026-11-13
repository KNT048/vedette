# Deferred: feat/notify-email-mlee

- [ ] 2026-11-13 — Send one real test email through each OAuth preset (a Microsoft 365 tenant with the app registration + service principal + mailbox permission, a Google Workspace domain with a service account and domain-wide delegation) and one app-password preset (Gmail) from a lab box — vì sao để sau: the session may not call a real provider (fakes only); needs kien's test tenants and keys — ở đâu: Settings → Alert channels → Email on the lab appliance, `modules/notify/channel/smtpauth.go`
