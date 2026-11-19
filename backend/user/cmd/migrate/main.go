package main

import (
	"log"

	_ "github.com/lib/pq"
	"mtls/shared/migrate"
	"mtls/user/migrations"
)

func main() {
	if err := migrate.RunCommand("user", "users", migrations.Files); err != nil {
		log.Fatal(err)
	}
}
