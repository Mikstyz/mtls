package main

import (
	"log"

	_ "github.com/lib/pq"
	"mtls/content/migrations"
	"mtls/shared/migrate"
)

func main() {
	if err := migrate.RunCommand("content", "content_posts", migrations.Files); err != nil {
		log.Fatal(err)
	}
}
