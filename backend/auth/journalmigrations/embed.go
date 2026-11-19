package journalmigrations

import "embed"

// Files contains the independent security journal migrations.
//
//go:embed *.sql
var Files embed.FS
