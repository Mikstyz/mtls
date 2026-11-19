package main

import (
	"log"

	_ "github.com/lib/pq"

	"mtls/auth/journalmigrations"
	"mtls/shared/migrate"
)

func main() {
	if err := migrate.RunCommand("security_journal", "security_journal_events", journalmigrations.Files); err != nil {
		log.Fatal(err)
	}
}
