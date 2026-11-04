.PHONY: build test bench demo lab lab-down isolation

build:
	cd agent && go build -o fimagent ./cmd/fimagent

test:
	cd agent && go vet ./... && go test ./...

bench:
	cd agent && go test -run - -bench . ./internal/hasher/

demo:
	bash examples/demo/run_demo.sh

lab:
	docker compose -f docker/docker-compose.yml up -d --build

lab-down:
	docker compose -f docker/docker-compose.yml down

isolation:
	bash docs/isolation_check.sh
