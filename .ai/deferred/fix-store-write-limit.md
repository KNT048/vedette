# fix/store-write-limit (issue #251, D-246)

- [ ] Open: no test fails if `hs.Handler = limitWrites(...)` is removed from `openSensorLink` (`cmd/vedette/sensorwire.go`); `limitWrites` itself is tested. Owner: whoever next touches the sensor link e2e (`cmd/vedette` sensor tests); add an assertion through a real link that a held writer gives 503 store_busy.
