package feeds

import (
	"fmt"
	"strings"
)

// displaySlugs is the vendor_product_slug of DATA_PIPELINE section 3: the name a person recognises for a
// vendor|product pair of KEV (slug.ts of the GUI mock; English, D-28). Pairs not listed read "Vendor Product".
var displaySlugs = map[string]string{
	"qnap|photo station":                              "Photo Station app on QNAP NAS",
	"qnap|qts":                                        "QNAP NAS (QTS)",
	"synology|diskstation manager":                    "Synology NAS (DSM)",
	"wordpress|wordpress core":                        "WordPress website",
	"wordpress|core":                                  "WordPress website",
	"microsoft|windows":                               "Windows PCs and servers",
	"microsoft|sharepoint":                            "Microsoft SharePoint",
	"microsoft|sql server":                            "Microsoft SQL Server",
	"microsoft|exchange server":                       "Microsoft Exchange mail server",
	"fortinet|fortios":                                "FortiGate firewall (FortiOS)",
	"fortinet|multiple products":                      "Several Fortinet products",
	"mikrotik|routeros":                               "MikroTik router (RouterOS)", //nolint:misspell // RouterOS is the product name
	"ivanti|connect secure":                           "Ivanti Connect Secure VPN",
	"palo alto networks|pan-os":                       "Palo Alto firewall (PAN-OS)",
	"broadcom|vmware esx":                             "VMware ESXi hypervisor",
	"apple|multiple products":                         "Apple devices (iPhone, iPad, Mac)",
	"php group|php":                                   "PHP on web servers",
	"linux|kernel":                                    "Linux servers (kernel)",
	"hikvision|multiple products":                     "Hikvision cameras and recorders",
	"adobe|commerce and magento":                      "Magento online store",
	"plex|media server":                               "Plex Media Server",
	"atlassian|multiple products":                     "Atlassian software (Jira, Confluence)",
	"beyondtrust|remote support":                      "BeyondTrust Remote Support",
	"google|brotli":                                   "Brotli compression library (in many products)",
	"gitlab|community edition and enterprise edition": "Self-hosted GitLab",
	"cisco|secure firewall asa software and cisco secure ftd software": "Cisco ASA/FTD firewall",
}

// DisplayOf is the name people recognise for a vendor and product.
func DisplayOf(vendor, product string) string {
	if d, ok := displaySlugs[ProductKey(vendor, product)]; ok {
		return d
	}
	return vendor + " " + product
}

// KindOf is the device type suggested when someone answers "I have it" (S-FEED-2): a hint for the manual
// device, not a classification.
func KindOf(key string) string {
	has := func(sub string) bool { return strings.Contains(key, sub) }
	switch {
	case strings.HasPrefix(key, "qnap|") || strings.HasPrefix(key, "synology|"):
		return "nas"
	case has("fortios") || has("pan-os") || has("asa"):
		return "firewall"
	case strings.HasPrefix(key, "mikrotik|"):
		return "router"
	case strings.HasPrefix(key, "hikvision|"):
		return "camera"
	case strings.HasPrefix(key, "wordpress|") || has("magento"):
		return "web"
	case strings.HasPrefix(key, "microsoft|windows"):
		return "server"
	}
	return "unknown"
}

// weeklyText is the "This week, in short" sentence, built from a template on the box (INV-14); English (D-28).
func weeklyText(v Vuln) string {
	what := "that is being exploited in the wild"
	if v.Ransomware {
		what = "that ransomware groups are exploiting"
	}
	day := v.DateAdded
	if t, err := parseDate(v.DateAdded); err == nil {
		day = fmt.Sprintf("%d %s", t.Day(), t.Format("Jan"))
	}
	return fmt.Sprintf("%s has a vulnerability %s (added to the CISA list on %s). If your company uses it, update it following %s's advisory this week.",
		DisplayOf(v.Vendor, v.Product), what, day, v.Vendor)
}
