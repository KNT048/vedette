package auth

import "time"

// SetHashProbe makes the service call f(+1) when an argon2 run starts and f(-1) when it ends.
func SetHashProbe(s *Service, f func(delta int)) { s.probe = f }

// TempAlphabet exposes the alphabet of NewTempPassword to the tests.
const TempAlphabet = tempAlphabet

// HashPassword hashes with DefaultParams, for the tests of the format. It is not exported by the package:
// code outside it must go through Service, which holds the argon2 concurrency cap.
func HashPassword(password string) (string, error) { return DefaultParams.Hash(password) }

// VerifyPassword verifies against DefaultParams (see Params.Verify), for the tests of the format.
func VerifyPassword(encoded, password string) (ok, needsRehash bool, err error) {
	return DefaultParams.Verify(encoded, password)
}

// WaitTouched waits until no last_seen refresh is running. A request waits at most touchWait for the
// refresh, so a test that then moves a fake clock could outrun the write on a slow machine.
func WaitTouched(s *Sessions) {
	for s.touching.Load() {
		time.Sleep(time.Millisecond)
	}
}
