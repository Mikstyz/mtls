package migrations

import "embed"

// Files contains the migrations distributed with the media-processing service.
//
//go:embed *.sql
var Files embed.FS
