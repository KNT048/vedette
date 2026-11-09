// Step-by-step setup of the pull method for each firewall (D-44). Menu paths are those of current releases; names differ a little between versions.
export interface Guide { id: string; title: string; steps: string[]; note?: string; code?: { label: string; text: string } }

export const guides = (url: string): Guide[] => [
  {
    id: 'fortigate', title: 'FortiGate: External Block List (threat feed)',
    steps: [
      'Open Security Fabric, then External Connectors, then Create New, then Threat Feeds, then IP Address.',
      `Name it Vedette-Blocklist. In URI of external resource paste: ${url}`,
      'Set Refresh Rate to 5 minutes. Leave HTTP basic authentication off (the token in the address is the credential). Click OK.',
      'Open Policy & Objects, then Firewall Policy, then Create New. Action: DENY. In Destination pick Vedette-Blocklist (it is listed under Threat Feeds). Leave Source as all and turn on Log Violation Traffic.',
      'Drag the new policy above your ALLOW policies for outgoing traffic. Open Security Fabric, External Connectors, select the feed and use Refresh to see the entry count.',
    ],
    note: 'If the feed shows a certificate error, import the box certificate under System, Certificates, Create/Import, CA Certificate, and enable it as a trusted CA.',
  },
  {
    id: 'paloalto', title: 'Palo Alto: External Dynamic List',
    steps: [
      'Open Device, then Certificate Management, then Certificate Profile, Add. Add the box certificate as a CA and name the profile Vedette-Box.',
      'Open Objects, then External Dynamic Lists, then Add. Name: Vedette-Blocklist. Type: IP List.',
      `Source: ${url}`,
      'Certificate Profile: Vedette-Box. Check for updates: Every Five Minutes. Click OK.',
      'Open Policies, then Security, then Add. Destination Address: Vedette-Blocklist. Action: Deny. Move the rule above your allow rules.',
      'Commit. Then open Objects, External Dynamic Lists, select the list and click List Entries to check the content.',
    ],
  },
  {
    id: 'pfsense', title: 'pfSense: URL Table alias',
    steps: [
      'Open Firewall, then Aliases, then the URLs tab, then Add.',
      'Name: Vedette_Blocklist. Type: URL Table (IPs).',
      `URL: ${url}`,
      'Update Frequency: 1 (day, the lowest pfSense offers). Save, then Apply Changes.',
      'Open Firewall, then Rules, then Floating, then Add. Action: Block. Interface: LAN. Direction: out. Destination: Single host or alias, then Vedette_Blocklist. Save and Apply Changes.',
      'To force an update now, open Diagnostics, then Command Prompt and run: pfctl -t Vedette_Blocklist -T show after clicking Reload under Status, Filter Reload.',
    ],
    note: 'pfSense checks the certificate. Import the box certificate under System, Certificates, Authorities first.',
  },
  {
    id: 'opnsense', title: 'OPNsense: URL Table alias',
    steps: [
      'Open Firewall, then Aliases, then click Add (+).',
      'Name: Vedette_Blocklist. Type: URL Table (IPs).',
      `Content: ${url}`,
      'Refresh Frequency: 0 days and 1 hour or more (OPNsense accepts days and hours). Save, then Apply.',
      'Open Firewall, then Rules, then LAN, then Add. Action: Block. Destination: Vedette_Blocklist. Save and Apply changes.',
      'Open Firewall, then Diagnostics, then Aliases, select Vedette_Blocklist to see the loaded addresses.',
    ],
  },
  {
    id: 'mikrotik', title: 'MikroTik: scheduled fetch script',
    steps: [
      'Open System, then Scripts, then Add. Name: vedette-blocklist. Policy: read, write, test. Paste the script below.',
      'Open System, then Scheduler, then Add. Name: vedette-blocklist. Interval: 00:05:00. On Event: /system script run vedette-blocklist. Policy: read, write, test.',
      'Open IP, then Firewall, then Filter Rules, then Add. Chain: forward. Dst. Address List: vedette-block. Action: drop. Move the rule to the top.',
      'Run the script once from System, Scripts. Open IP, Firewall, Address Lists to see the entries.',
    ],
    code: {
      label: 'RouterOS script',
      text: `/tool fetch url="${url}" mode=https check-certificate=no dst-path=vedette-blocklist.txt
:local data [/file get vedette-blocklist.txt contents]
/ip firewall address-list remove [find where list=vedette-block]
:while ([:len $data] > 0) do={
  :local eol [:find $data "\\n"]
  :if ([:typeof $eol] = "nil") do={ :set eol [:len $data] }
  :local line [:pick $data 0 $eol]
  :if ([:len $line] > 0 && [:pick $line 0 1] != "#") do={ :do { /ip firewall address-list add list=vedette-block address=$line timeout=1d } on-error={} }
  :if ($eol < [:len $data]) do={ :set data [:pick $data ($eol + 1) [:len $data]] } else={ :set data "" }
}`,
    },
    note: 'check-certificate=no is used because the box certificate is self-signed. The address is only reachable from your LAN and the token is the credential.',
  },
]
