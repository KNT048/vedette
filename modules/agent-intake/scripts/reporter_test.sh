#!/bin/sh
# Runs the package reporter (embedded in osquery.sh) twice in a throwaway alpine container against a stub curl, and checks that it enrols
# exactly once: the second run reuses the node key. Needs podman; wrap it in heavy: ~/vedette-wt/heavy sh modules/agent-intake/scripts/reporter_test.sh
# The reporter's own paths are the real ones, so it only runs inside the container (nothing on this machine is touched).
set -eu
if [ "${REPORTER_TEST_INNER:-}" != 1 ]; then
  here=$(cd "$(dirname "$0")" && pwd)
  exec podman run --rm --network host -e REPORTER_TEST_INNER=1 -v "$here/osquery.sh:/t/osquery.sh:ro" -v "$here/reporter_test.sh:/t/reporter_test.sh:ro" docker.io/library/alpine:3.23 sh /t/reporter_test.sh
fi
mkdir -p /etc/vedette-reporter/capath /var/lib/vedette-reporter /usr/local/sbin
sed -n "/<<'VEDETTE_REPORTER'/,/^VEDETTE_REPORTER/p" /t/osquery.sh | sed '1d;$d' > /usr/local/sbin/vedette-reporter
chmod 755 /usr/local/sbin/vedette-reporter
printf 'https://192.0.2.1:8443\n' > /etc/vedette-reporter/box
printf 'testhost\n' > /etc/vedette-reporter/host-id
printf 'vdt_osquery_abcdefghijklmnopqrstuvwxyz012345\n' > /etc/vedette-reporter/enroll.secret
printf 'stub\n' > /etc/vedette-reporter/ca.pem
cat > /usr/local/bin/curl <<'STUB'
#!/bin/sh
# stub box: logs the endpoint, answers an enrol with a node key and a log with an empty answer
out=''; url=''
while [ $# -gt 0 ]; do
  case "$1" in -o) out=$2; shift 2 ;; -w|-H|--cacert|--capath|--max-time|--proto|--data-binary) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac
done
echo "${url##*/}" >> /tmp/calls
case "$url" in */enroll) printf '{"node_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","node_invalid":false}' > "$out" ;; *) printf '{"node_invalid":false}' > "$out" ;; esac
printf 200
STUB
chmod 755 /usr/local/bin/curl
: > /tmp/calls
/usr/local/sbin/vedette-reporter >/dev/null
/usr/local/sbin/vedette-reporter >/dev/null
n=$(grep -c '^enroll$' /tmp/calls); l=$(grep -c '^log$' /tmp/calls)
if [ "$n" -ne 1 ] || [ "$l" -ne 2 ]; then echo "FAIL: $n enrols and $l logs for two runs (want 1 and 2):"; cat /tmp/calls; exit 1; fi
echo "ok: two runs, one enrol, two reports"
