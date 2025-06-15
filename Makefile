test:
	go test ./... -v 

run:
	go build
	./earnit

tidy:
	go mod tidy

dbup:
	docker-compose up 

dbshell:
	docker exec -it earnit_postgres psql -U postgres -d earnit

seeddb:
	 DATABASE_DSN_DEV=postgres://postgres:postgres@localhost:5432/earnit_dev?sslmode=disable APP_ENV=dev go run cmd/seed/main.go

resetdb:
	go run cmd/tools/reset_db.go 