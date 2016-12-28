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

	Name string

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

	// Name and type are inferred from static analysis
	Name string
	Type PluginType
	// TODO: add a "status" field so the author can have an idea what's going on

	// Metadata provided by account owner
	Description string
	Website     string // project homepage
	Support     string // direct link to get help or file issues
	Docs        string // direct link to docs
	Examples    []Example

	// Information necessary for builds and releases
	ImportPath    string // `go get` package path
	SourceRepo    string // `git clone` URL
	Subfolder     string // TODO: Not used now, because only one published plugin per repo...
	ReleaseBranch string // TODO: For use with webhooks; not currently used...

	Releases  []PluginRelease
	Published time.Time
	Updated   time.Time // TODO: does a release count as an update? I vote no...
}

// LatestRelease returns the latest release, if there is one;
// otherwise a nil pointer.
func (p Plugin) LatestRelease() *PluginRelease {
	if len(p.Releases) > 0 {
		return &p.Releases[len(p.Releases)-1]
	}
	return nil
}

// NewestReleases returns the n newest releases.
func (p Plugin) NewestReleases(n ...int) []PluginRelease {
	num := len(p.Releases)
	if len(n) == 1 {
		num = n[0]
	}
	rels := make([]PluginRelease, num)
	for i := 0; i < num; i++ {
		rels[i] = p.Releases[len(p.Releases)-1-i]
	}
	return rels
}

// Example is an example for how to use a plugin.
type Example struct {
	Title       string // a short, descriptive one-liner
	Code        string // the content of the example, displayed as code
	Explanation string // in sentence form
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
