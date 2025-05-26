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