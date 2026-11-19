module mtls/content

go 1.23

require mtls/shared v0.0.0

require (
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.3
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
)

replace mtls/shared => ../shared
