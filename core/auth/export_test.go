package auth

// SetHashProbe makes the service call f(+1) when an argon2 run starts and f(-1) when it ends.
func SetHashProbe(s *Service, f func(delta int)) { s.probe = f }

// TempAlphabet exposes the alphabet of NewTempPassword to the tests.
const TempAlphabet = tempAlphabet
