# fix/store-write-limit (issue #251, D-246)

- [ ] Open: no test fails if `hs.Handler = limitWrites(...)` is removed from `openSensorLink` (`cmd/vedette/sensorwire.go`); `limitWrites` itself is tested. Owner: whoever next touches the sensor link e2e (`cmd/vedette` sensor tests); add an assertion through a real link that a held writer gives 503 store_busy.
- [ ] Open (not this change; packages do not import core/store): two tests fail only on macOS during `make check` — `modules/logs/listen` `TestAHugeDatagramIsCutAndCounted` (UDP write "message too long": macOS `net.inet.udp.maxdgram` 9216) and `scripts/release` `TestMinisignCLIHandling` (`/private/var` vs `/var` temp path symlink). Owners: logs (AI-Mlee), release WP-08 (AI-Trưởng). Reported to the supervisor in the PR.
