package nwstream

import "errors"

// Sentinel errors for the container layer.
var (
	// ErrNotNWD means the 48-byte signature prefix matched no known mode.
	ErrNotNWD = errors.New("nwstream: not an NWD container")

	// ErrUnsupportedVersion means the container version is outside the
	// implemented range (currently only v8; v2–7 use the unimplemented
	// LoadOld path).
	ErrUnsupportedVersion = errors.New("nwstream: unsupported container version")

	// ErrFooterMismatch means the 52-byte footer signature does not equal
	// the file header (Load@0xbd386f error 4).
	ErrFooterMismatch = errors.New("nwstream: footer signature mismatch")

	// ErrTOCChecksum means the Blowfish-encrypted Adler-32 trailer does not
	// match the rolling TOC checksum (Load@0xbd3ef3 error 6).
	ErrTOCChecksum = errors.New("nwstream: toc checksum mismatch")
)
