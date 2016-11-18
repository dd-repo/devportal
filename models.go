package devportal

import "time"

// AccountInfo stores information about a user account.
type AccountInfo struct {
	ID       string
	Email    string
	Password []byte
	Salt     []byte

	RegistrationDate time.Time
	VerifiedDate     time.Time
}

// PluginInfo stores information about a plugin.
type PluginInfo struct {
	Name          string
	ImportPath    string
	SourceRepo    string
	ReleaseBranch string
	DocsRepo      string
	DocsBranch    string
	DocsManifest  string

	Status string

	Type PluginType
}
