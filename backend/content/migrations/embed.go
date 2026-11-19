package migrations

import "embed"

// Files contains the migrations distributed with the service.
//
//go:embed *.sql
var Files embed.FS
