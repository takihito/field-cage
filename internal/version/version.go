// Package version holds the field-cage release version.
package version

// Version is kept in sync with the most recent release tag by tagpr (see
// the versionFile setting in .tagpr). Release builds override the value
// baked into the binary via -ldflags "-X main.version=...".
const Version = "0.1.1"
