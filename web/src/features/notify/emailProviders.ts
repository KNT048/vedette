// Presets of the email channel (S-NOT-1, D-449). Choosing one fills host, port and encryption; the box knows only how each one signs in
// (modules/notify/channel/smtpauth.go emailProviders). Every value is checked against the provider's own page in `doc` (D-449).

/** How a preset signs in: SMTP AUTH PLAIN/LOGIN with a password or API key, the secret as both username and password (Postmark), or OAuth2. */
export type EmailAuth = 'password' | 'token_as_user' | 'microsoft_oauth' | 'google_oauth'

export interface EmailProvider {
  id: string
  group: 'password' | 'service' | 'oauth'
  auth: EmailAuth
  host: string
  port: string
  security: 'starttls' | 'ssl'
  /** A username the provider fixes (SendGrid's literal "apikey"). */
  username?: string
  /** The provider's own instructions, linked from the dialog. */
  doc?: string
}

export const EMAIL_PROVIDERS: EmailProvider[] = [
  { id: 'custom', group: 'password', auth: 'password', host: '', port: '587', security: 'starttls' },
  { id: 'gmail', group: 'password', auth: 'password', host: 'smtp.gmail.com', port: '587', security: 'starttls', doc: 'https://support.google.com/accounts/answer/185833' },
  { id: 'yahoo', group: 'password', auth: 'password', host: 'smtp.mail.yahoo.com', port: '465', security: 'ssl', doc: 'https://help.yahoo.com/kb/SLN4724.html' },
  { id: 'icloud', group: 'password', auth: 'password', host: 'smtp.mail.me.com', port: '587', security: 'starttls', doc: 'https://support.apple.com/en-us/102525' },
  { id: 'zoho', group: 'password', auth: 'password', host: 'smtp.zoho.com', port: '465', security: 'ssl', doc: 'https://www.zoho.com/mail/help/zoho-smtp.html' },
  { id: 'fastmail', group: 'password', auth: 'password', host: 'smtp.fastmail.com', port: '465', security: 'ssl', doc: 'https://www.fastmail.help/hc/en-us/articles/1500000278342' },
  { id: 'sendgrid', group: 'service', auth: 'password', host: 'smtp.sendgrid.net', port: '587', security: 'starttls', username: 'apikey', doc: 'https://www.twilio.com/docs/sendgrid/for-developers/sending-email/integrating-with-the-smtp-api' },
  { id: 'mailgun', group: 'service', auth: 'password', host: 'smtp.mailgun.org', port: '587', security: 'starttls', doc: 'https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/send-smtp' },
  { id: 'ses', group: 'service', auth: 'password', host: 'email-smtp.us-east-1.amazonaws.com', port: '587', security: 'starttls', doc: 'https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html' },
  { id: 'postmark', group: 'service', auth: 'token_as_user', host: 'smtp.postmarkapp.com', port: '587', security: 'starttls', doc: 'https://postmarkapp.com/developer/user-guide/send-email-with-smtp' },
  { id: 'brevo', group: 'service', auth: 'password', host: 'smtp-relay.brevo.com', port: '587', security: 'starttls', doc: 'https://help.brevo.com/hc/en-us/articles/7924908994450' },
  { id: 'microsoft365', group: 'oauth', auth: 'microsoft_oauth', host: 'smtp.office365.com', port: '587', security: 'starttls', doc: 'https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth' },
  { id: 'google-workspace', group: 'oauth', auth: 'google_oauth', host: 'smtp.gmail.com', port: '587', security: 'starttls', doc: 'https://developers.google.com/identity/protocols/oauth2/service-account' },
]

/** The preset of a saved channel: a channel saved before the presets (or by the setup wizard) has none and is Custom SMTP. */
export const emailProvider = (id: string | undefined) => EMAIL_PROVIDERS.find((p) => p.id === (id || 'custom'))
export const isOAuth = (a: EmailAuth) => a === 'microsoft_oauth' || a === 'google_oauth'
