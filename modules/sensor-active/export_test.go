package sensoractive

// SetBeforeSNMPBatch makes fn run as every SNMP batch starts, before it registers (a test acting in that window; review #855 r2 L1).
func SetBeforeSNMPBatch(s *Service, fn func()) { s.beforeSNMPBatch = fn }
