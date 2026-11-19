module mtls/user

go 1.26.0

require (
	github.com/KimMachineGun/automemlimit v1.0.0
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.3
	go.uber.org/automaxprocs v1.6.0
	mtls/shared v0.0.0
)

require (
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
)

replace mtls/shared => ../shared
