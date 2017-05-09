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

	EmailNotifyInfo    bool
	EmailNotifySuccess bool
	EmailNotifyWarn    bool
	EmailNotifyError   bool

	PasswordReset ResetToken
}

// APIKeyHex returns the hex-encoded API key
func (a AccountInfo) APIKeyHex() string {
	return hex.EncodeToString(a.APIKey)
}

type ResetToken struct {
	Token   string
	Created time.Time
}

func (rt ResetToken) Expired() bool {
	return time.Since(rt.Created) > 24*time.Hour
}

// CaddyRelease indicates a version point (commit
// or tag) at which Caddy is available.
type CaddyRelease struct {
	Version    string // commit or tag (could be a branch, but unwise since that ref moves)
	Timestamp  time.Time
	ReleasedBy string // the ID of the account that did the release
}

// Counts keeps a basic record of download counts.
type Counts struct {
	Total        int
	ByOS         map[string]int
	ByArch       map[string]int
	ByVersion    map[string]int
	NumPlugins   map[int]int
	LastDownload time.Time
	ByPlugin     []nameAndCount
}
type nameAndCount struct {
	Name  string
	Count int
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
	ImportPath string // `go get` package path
	SourceRepo string // `git clone` URL
	// Subfolder     string // TODO: Not used
	ReleaseBranch string // TODO: For use with webhooks; not currently used...

	Releases  []PluginRelease
	Published time.Time
	Updated   time.Time // timestamp when information about the plugin was last updated

	Unpublished   bool `json:"-"` // whether the plugin is currently unpublished (i.e. hidden)
	DownloadCount int  // how many times this plugin has been included in a download
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
	Version         string
	CaddyVersion    string
	Timestamp       time.Time
	TestedPlatforms []buildworker.Platform
}

// CachedBuild refers to a build that has been cached
type CachedBuild struct {
	Config            buildworker.BuildRequest
	CacheKey          string    // the unique key for this cache item
	Timestamp         time.Time // when the cached item was initially requested/created
	Dir               string    // the directory where the files are kept
	ArchiveFilename   string    // name of the archive file
	SignatureFilename string    // name of the signature file
}

// Notification represents a notification for an account.
type Notification struct {
	ID           string
	AccountID    string
	Timestamp    time.Time
	Headline     string
	Body         string
	Acknowledged bool
	Level        NotifLevel
}

type NotifLevel int

const (
	NotifInfo NotifLevel = iota
	NotifSuccess
	NotifWarn
	NotifError
)

func NotifLevelText(level NotifLevel) string {
	switch level {
	case NotifInfo:
		return "info"
	case NotifSuccess:
		return "success"
	case NotifWarn:
		return "warning"
	case NotifError:
		return "error"
	}
	return "unknown"
}

type NotificationList []Notification

func (list NotificationList) UnreadCount() int {
	count := 0
	for _, n := range list {
		if !n.Acknowledged {
			count++
		}
	}
	return count
}
