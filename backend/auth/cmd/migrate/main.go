package main

import (
	"log"

	_ "github.com/lib/pq"
	"mtls/auth/migrations"
	"mtls/shared/migrate"
)

func main() {
	if err := migrate.RunCommand("auth", "credentials", migrations.Files); err != nil {
		log.Fatal(err)
	}
}
