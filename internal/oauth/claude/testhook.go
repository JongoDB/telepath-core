package claude

// setTokenURL is a test-only hook that lets tests override the production
// TokenURL with an httptest.Server endpoint. Lives in a non-_test.go file
// so it's compiled in normal builds but is only called from the test file.
// Kept unexported so external callers can't repoint it.
func setTokenURL(u string) { TokenURL = u }
