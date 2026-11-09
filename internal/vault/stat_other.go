//go:build !unix

package vault

import "os"

// ownerUID returns the uid that owns the file. It is not known on this system.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }
