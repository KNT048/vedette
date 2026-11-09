// Nội dung mẫu cho mock: gói giảm thiểu đã xác nhận (D-21), dấu hiệu bị khai thác (S-MIT-3). Gói rule vá ảo (S-MIT-2) đã bỏ (D-31).
// Bản thật: content pack ký của dự án Vedette (soạn với AI, người duy trì xác nhận qua PR trên GitHub) (content/mitigation/<CVE>.yaml, status: confirmed). `{IP}`/`{HOST}` được thay bằng thiết bị thật của khách.
// Mọi chuỗi hiển thị bằng tiếng Anh (D-28).
import type { CompromiseCheck, MitigationPack } from './types'

const QNAP = 'https://www.qnap.com/en/security-advisory/qsa-22-24'

// Nguồn đã đối chiếu 2026-11-06:
// - QNAP QSA-22-24 (qnap.com): bản vá Photo Station theo từng dòng QTS (bảng FIXED_*).
// - FortiOS: `show … | grep -f` hiện cả khối cấu hình chứa dòng khớp (Fortinet CLI "Using grep to filter get and show command output"); tuỳ bản FortiOS, nên có ghi chú.
// - FortiOS config firewall address (type geography, country): Fortinet admin guide 7.2.8 "Geography based addresses" (docs.fortinet.com/document/fortigate/7.2.8/administration-guide/286826); config firewall policy `set status enable|disable`: FortiOS CLI reference 6.4.x/7.2 (supervisor đối chiếu 2026-11-06).
// - RouterOS filter: connection-nat-state, in-interface-list, place-before (wiki.mikrotik.com Firewall filter, help.mikrotik.com).
export function packs(): Record<string, MitigationPack> {
  return {
    'CVE-2022-27593': {
      cve: 'CVE-2022-27593',
      confirmed_by: 'a Vedette maintainer',
      confirmed_at: '2026-09-20T03:00:00Z',
      drafted_with: 'claude-sonnet-5-5',
      sources: [
        { title: 'QNAP advisory QSA-22-24', url: QNAP },
        { title: 'NVD CVE-2022-27593', url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-27593' },
        { title: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      ],
      patch: {
        summary: 'Update Photo Station to the fixed version, then update QTS. QNAP fixed this flaw in advisory QSA-22-24.',
        fixed: 'Per advisory QSA-22-24: QTS 5.0.1 needs Photo Station 6.1.2 or later; QTS 5.0.0 and 4.5.x need 6.0.22 or later; QTS 4.3.6 needs 5.7.18 or later; QTS 4.3.3 needs 5.4.15 or later; QTS 4.2.6 needs 5.2.14 or later. Older QTS: check the advisory or upgrade QTS.',
        steps: [
          'Back up: create a Snapshot or run Hybrid Backup Sync for the important data on {HOST}.',
          'Sign in to QTS from a machine on the internal network: http://{IP}:8080 (default port), with an administrator account.',
          'Open App Center, find Photo Station and click Update. If you no longer use Photo Station, click Uninstall.',
          'Open Control Panel, then System, then Firmware Update, and click Live Update to bring QTS to the latest version.',
          'Back in Vedette, click "Rescan this device" to confirm the vulnerability is gone.',
        ],
        side_effect: 'Photo Station stops for a few minutes during the update. Updating QTS needs a restart, and the NAS is unavailable for about 5 to 10 minutes; do it outside working hours.',
        url: QNAP,
      },
      workaround: {
        summary: 'Cannot patch yet: stop Photo Station and cut the NAS off from the Internet. Together these block the attack seen in the wild (a NAS with Photo Station exposed to the Internet).',
        steps: [
          'In App Center, stop Photo Station (the Stop button) or uninstall it if unused.',
          'Block Internet access to {HOST} on the firewall (see section 3 below).',
          'In myQNAPcloud, turn off Auto Router Configuration so the NAS does not open ports to the Internet by itself.',
          'If you need remote access to the NAS, use the firewall VPN, not a direct port forward.',
        ],
        side_effect: 'Users cannot view photos through the Photo Station web page. Access to the NAS from outside the company without the VPN stops.',
      },
      firewall: [
        {
          vendor: 'fortigate',
          label: 'FortiGate (FortiOS)',
          detected: false,
          intro: 'Find the port-forward rule (VIP) that points to {HOST}, then disable the policy that uses that VIP. Type these in the FortiGate CLI (SSH or the CLI Console button in the web UI). If the FortiGate uses several VDOMs, enter the right VDOM first: config vdom, then edit <VDOM name>.',
          steps: [
            { title: 'Step 1. Find the VIP that points to the NAS', code: 'show firewall vip | grep -f {IP}', note: 'The output contains a line edit "<VIP name>". Note the VIP name. Depending on the FortiOS version the -f option may be missing; then run show firewall vip and look for {IP} by eye.' },
            { title: 'Step 2. Find the policy that uses that VIP', code: 'show firewall policy | grep -f "<VIP-NAME>"', note: 'Replace <VIP-NAME> with the VIP name from step 1 and keep the double quotes. The output contains a line edit <ID>; note the policy ID.' },
            { title: 'Step 3. Disable the policy', code: 'config firewall policy\nedit <ID>\nset status disable\nnext\nend', note: 'Replace <ID> with the number from step 2. Paste the whole block.', side_effect: 'Access to the NAS from the Internet stops immediately, including open sessions. Remote users must use the VPN. If the policy also serves other machines, those stop too.' },
          ],
          alternative: {
            title: 'Alternative: only allow Vietnamese IPs to the NAS',
            intro: 'Use this when you cannot cut outside access completely. It only reduces noise from abroad; attackers can still use servers in Vietnam, so you must still patch.',
            steps: [
              { title: 'Create a country address object', code: 'config firewall address\nedit "geo-VN"\nset type geography\nset country "VN"\nnext\nend' },
              { title: 'Limit the source of the policy', code: 'config firewall policy\nedit <ID>\nset srcaddr "geo-VN"\nnext\nend', note: 'The policy must be enabled (set status enable). This command replaces the whole previous source of the policy with geo-VN.', side_effect: 'Users abroad lose access to the NAS until they use the VPN.' },
            ],
          },
          verify: [
            { title: 'Check the policy is disabled', code: 'show firewall policy <ID>', note: 'The output must contain the line set status disable.' },
            { title: 'Check from outside', code: '', note: 'Use a phone on 4G (company Wi-Fi off) and open the NAS public IP address and port. The page must not open.' },
          ],
          undo: [
            { title: 'Re-enable the policy once patched', code: 'config firewall policy\nedit <ID>\nset status enable\nnext\nend' },
          ],
        },
        {
          vendor: 'mikrotik',
          label: 'MikroTik (RouterOS)',
          detected: false,
          intro: 'Find the NAT rule that forwards ports to {HOST}, then add a rule that drops new connections from the Internet to the NAS. Type these in the WinBox Terminal or over SSH.',
          steps: [
            { title: 'Step 1. Find the NAT rules that point to the NAS', code: '/ip firewall nat print where to-addresses={IP}', note: 'Lines with chain=dstnat are the ports open to the Internet.' },
            { title: 'Step 2. Check the WAN interface list', code: '/interface list member print where list=WAN', note: 'The rule in step 3 uses the default RouterOS WAN interface list. If this command prints nothing or you named it differently, replace in-interface-list=WAN with in-interface=<Internet-facing port> (for example ether1).' },
            {
              title: 'Step 3. Add the drop rule',
              code: '/ip firewall filter add chain=forward action=drop in-interface-list=WAN connection-state=new connection-nat-state=dstnat dst-address={IP} comment="Vedette: block Internet access to NAS" place-before=0',
              side_effect: 'The rule sits at the top of the forward chain and drops every new connection from the Internet to the forwarded NAS. Access from the internal network is not affected. Remote access to the NAS stops; use the VPN.',
            },
          ],
          verify: [
            { title: 'Check the rule is at the top of the list', code: '/ip firewall filter print where comment~"Vedette"' },
            { title: 'Check from outside', code: '/ip firewall filter print stats where comment~"Vedette"', note: 'Use a phone on 4G to open the NAS public IP address and port. The page does not open, and the packets counter of the rule goes up.' },
          ],
          undo: [
            { title: 'Remove the rule once patched', code: '/ip firewall filter remove [find where comment~"Vedette: block Internet access"]' },
          ],
        },
        {
          vendor: 'generic',
          label: 'Other device',
          detected: false,
          intro: 'There is no dedicated syntax for your firewall yet. Follow these general steps.',
          steps: [],
          verify: [],
          undo: [],
          plain: [
            'Sign in to the firewall or router admin page.',
            'Find the port forwarding section (port forwarding, virtual server, NAT, VIP) with destination address {IP}.',
            'Disable or delete those rules. Write down the ports that were open so you can restore them if needed.',
            'From a phone on 4G, open the NAS public IP address and its old port. The page must not open.',
          ],
        },
      ],
      checklist: [
        'Photo Station is patched or uninstalled.',
        'QTS is on the latest version.',
        'No port-forward rule pointing to {IP} remains on the firewall or router.',
        'From a 4G network, the public address of the NAS does not open.',
        'There are no .deadbolt files and the QTS login page looks normal (see "Am I already compromised?").',
        'The NAS admin password was changed and 2-step verification is on if the NAS was ever exposed to the Internet.',
        'There is a recent offline backup and you tested restoring one file.',
        'Vedette rescans and the finding moves to "Patched" or "Mitigated".',
      ],
    },
  }
}

export function compromise(): Record<string, CompromiseCheck> {
  return {
    'CVE-2022-27593': {
      summary: 'The Deadbolt ransomware group exploits this flaw on QNAP NAS: it encrypts files, renames them with a .deadbolt extension and replaces the QTS login page with a ransom message.',
      indicators: [
        {
          kind: 'web', title: 'QTS login page replaced',
          detail: 'Open http://{IP}:8080 in a browser. If you see a ransom message naming Deadbolt instead of the login page, the NAS is encrypted. Or run the command below from a machine on the network; printing nothing is normal.',
          commands: [
            { label: 'Linux or macOS', code: 'curl -s http://{IP}:8080/ | grep -i deadbolt' },
            { label: 'Windows PowerShell', code: "(Invoke-WebRequest -UseBasicParsing http://{IP}:8080/).Content -match 'deadbolt'" },
          ],
        },
        {
          kind: 'file', title: 'Files with a .deadbolt extension',
          detail: 'In File Station, type *.deadbolt in the search box and search all shared folders. Or sign in to the NAS over SSH with an administrator account and run the command below (-L follows the QTS shared-folder links).',
          commands: [{ label: 'SSH to the NAS', code: 'find -L /share -maxdepth 5 -name "*.deadbolt" 2>/dev/null | head -n 20' }],
        },
        {
          kind: 'log', title: 'Unusual QTS sign-ins',
          detail: 'Open Control Panel, System, System Logs, System Access Logs. Look for sign-ins at hours when nobody works or from IP addresses that are not the company.',
        },
      ],
      if_found: [
        'Unplug the NAS network cable right away. If you can, keep the NAS powered on to preserve evidence.',
        'Do not pay. Take a screenshot of the message and the list of renamed files.',
        'Cut Internet access (section 3 of "What to do") and change the admin password and the passwords of accounts shared with the NAS.',
        'Restore from an offline backup after patching. For help, contact your incident response team or IT support provider.',
      ],
    },
  }
}
