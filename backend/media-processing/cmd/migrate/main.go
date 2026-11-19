package main

import (
	"log"

	_ "github.com/lib/pq"
	"mtls/media-processing/migrations"
	"mtls/shared/migrate"
)

func main() {
	if err := migrate.RunCommand("media_processing", "media_assets", migrations.Files); err != nil {
		log.Fatal(err)
	}
}
