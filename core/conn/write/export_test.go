package write

// SetAfterCredentialForTest runs f between opening the credential and dialling.
func (w *Writer) SetAfterCredentialForTest(f func()) { w.afterCredential = f }
