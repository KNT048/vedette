package nmapargv

// ReviewedNmapVersion is the nmap version whose scripts the lists of scripts.go were reviewed against (testdata/
// nse-7.95-categories.txt; FULL-4 review r2 LOW-3): the names are pinned, but -sV runs every "version" script by itself and a
// listed script's code can change with a Debian bump. The worker runs and advertises the full shapes (heartbeat nmap.full) only
// when its nmap reports exactly this version; any other version is reviewed again, the lists and this constant together.
const ReviewedNmapVersion = "7.95"
