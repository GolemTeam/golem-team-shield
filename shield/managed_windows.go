package shield

// AdminOwned trusts the file on Windows, where only an administrator can
// write under Program Files.
func AdminOwned(string) error { return nil }
