package devportal

import (
	"encoding/hex"
	"time"

	"github.com/caddyserver/buildworker"
)

// AccountInfo stores information about a user account.
type AccountInfo struct {
	ID       string
	Email    string
	Password []byte
	Salt     []byte
	APIKey   []byte

	RegistrationDate time.Time
	VerifiedDate     time.Time

	CaddyMaintainer bool
}

// APIKeyHex returns the hex-encoded API key
func (a AccountInfo) APIKeyHex() string {
	return hex.EncodeToString(a.APIKey)
}

// CaddyRelease indicates a version point (commit
// or tag) at which Caddy is available.
type CaddyRelease struct {
	Version    string // commit or tag (could be a branch, but unwise since that ref moves)
	Timestamp  time.Time
	ReleasedBy string // the ID of the account that did the release
}

// Plugin stores information about a plugin.
type Plugin struct {
	ID             string
	OwnerAccountID string
	Name           string
	Description    string
	Website        string
	ImportPath     string
	SourceRepo     string
	Subfolder      string // TODO: Not used now, because only one published plugin per repo...
	ReleaseBranch  string // TODO: For use with webhooks; not currently used...
	Type           PluginType
	Releases       []PluginRelease
}

// PluginRelease stores information about a successful plugin release.
type PluginRelease struct {
	Timestamp       time.Time
	Version         string
	CaddyVersion    string
	TestedPlatforms []buildworker.Platform
}

// CachedBuild refers to a build that has been cached
type CachedBuild struct {
	Config            buildworker.BuildRequest
	Timestamp         time.Time // when the cached item was initially requested/created
	CacheKey          string    // the unique key for this cache item
	Dir               string    // the directory where the files are kept
	ArchiveFilename   string    // name of the archive file
	SignatureFilename string    // name of the signature file
}
