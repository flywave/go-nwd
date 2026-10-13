package nwstream

import "strings"

// Header signature prefixes, excluding the trailing mode-specific tail word.
// Evidence: E2 sFirstSignatureAscii rodata 0x115bc08 / 0x115bb98 / 0x115bbd0;
// Load@0xbd353f reads 0x34 bytes and compares left(0x30)=48 bytes.
const (
	// SigPrefix is the common 20-byte prefix of every signature.
	SigPrefix = "#LcUStream-V1.1 "

	// HeaderSize is the fixed ASCII header block size read by Load (0x34).
	HeaderSize = 52

	// SigCmpLen is the number of leading signature bytes compared by Load (0x30).
	SigCmpLen = 48
)

// The three complete 48-byte signature bodies (mode-specific tails included).
// Word grammar: #LcUStream-V1.1 <binary|ascii> <double|single> <release|debug> <utf8|C> [tail]
const (
	// SigASCIILichunk is the ASCII / C-lichunk signature (48 bytes).
	// "#LcUStream-V1.1 ascii double release C lichunka-"
	SigASCIILichunk = "#LcUStream-V1.1 ascii double release C lichunka-"

	// SigBinaryLichunk is the binary / C-lichunk signature (48 bytes).
	// "#LcUStream-V1.1 binary double release C lichunk-"
	SigBinaryLichunk = "#LcUStream-V1.1 binary double release C lichunk-"

	// SigBinaryNavisworksPrefix is the first 48 bytes of the binary / utf8 /
	// navisworks signature. The full rodata string is 54 bytes
	// ("#LcUStream-V1.1 binary double release utf8 navisworks:") but Load
	// only compares left(48); on-disk headers therefore carry this 48-byte
	// body followed by version digits (findings N2/N4).
	SigBinaryNavisworksPrefix = "#LcUStream-V1.1 binary double release utf8 navis"
	SigBinaryNavisworksFull   = "#LcUStream-V1.1 binary double release utf8 navisworks:"
)

// Mode identifies the container byte mode from the signature.
type Mode uint8

const (
	// ModeUnknown means no known signature matched.
	ModeUnknown Mode = iota
	ModeASCIILichunk
	ModeBinaryLichunk
	ModeBinaryNavisworks
)

func (m Mode) String() string {
	switch m {
	case ModeASCIILichunk:
		return "ascii-lichunk"
	case ModeBinaryLichunk:
		return "binary-lichunk"
	case ModeBinaryNavisworks:
		return "binary-navisworks"
	default:
		return "unknown"
	}
}

// Precision / Build mirror the signature word pairs.
type Precision uint8

const (
	PrecisionDouble Precision = iota
	PrecisionSingle
)

type Build uint8

const (
	BuildRelease Build = iota
	BuildDebug
)

// Config is the decoded signature line (TNwStreamConfig companion fields
// recovered from readStreamConfig@0xbd2da6). Field semantics beyond the
// documented ones remain inferred (findings N10).
type Config struct {
	Mode      Mode
	Precision Precision
	Build     Build

	// NavisworksID is the decimal N from a trailing "navisworks:<N>" or
	// "lcodapi-<N>" word; 0 when absent.
	NavisworksID uint32

	// Lizlib is true when a trailing "lizlib" word is present.
	Lizlib bool

	// Version is the container format version parsed from the ASCII digits
	// that immediately follow the 48-byte signature (findings N4).
	Version int
}

// DetectHeader classifies a HeaderSize-byte ASCII header block and extracts
// the container version. hdr must contain at least HeaderSize bytes.
func DetectHeader(hdr []byte) (Config, bool) {
	if len(hdr) < HeaderSize {
		return Config{}, false
	}
	head := string(hdr[:SigCmpLen])
	var cfg Config
	switch {
	case strings.HasPrefix(head, SigASCIILichunk):
		cfg.Mode = ModeASCIILichunk
	case strings.HasPrefix(head, SigBinaryLichunk):
		cfg.Mode = ModeBinaryLichunk
	case strings.HasPrefix(head, SigBinaryNavisworksPrefix):
		cfg.Mode = ModeBinaryNavisworks
	default:
		return Config{}, false
	}

	// Version digits begin at offset 48 (E2: OdString(buf+0x30) -> Od_strtoint).
	rest := string(hdr[SigCmpLen:HeaderSize])
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return Config{}, false
	}
	v := 0
	for _, c := range rest[:i] {
		v = v*10 + int(c-'0')
	}
	cfg.Version = v

	// Word-pair flags are not present in the 48-byte body in a decodable
	// per-field form; Precision/Build default to the observed "double
	// release" pair used by all three known signatures.
	cfg.Precision = PrecisionDouble
	cfg.Build = BuildRelease
	return cfg, true
}

// Ensure the comparison constants stay exactly SigCmpLen bytes; Load
// compares left(0x30)=48 bytes only (findings N2).
var _ = [1]struct{}{}[len(SigASCIILichunk)-SigCmpLen]
var _ = [1]struct{}{}[len(SigBinaryLichunk)-SigCmpLen]
var _ = [1]struct{}{}[len(SigBinaryNavisworksPrefix)-SigCmpLen]
