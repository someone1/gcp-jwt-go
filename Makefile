check: get fmt vet lint test test-race

fmt:
	@for d in $(DIRS) ; do \
		if [ "`gofmt -s -l $$d/*.go | tee /dev/stderr`" ]; then \
			echo "^ improperly formatted go files" && echo && exit 1; \
		fi \
	done

lint:
	golangci-lint run

get:
	go get -v -d -t ./...

test:
	go test ./...

test-race:
	go test -race ./...

test-coverage:
	go test -race -v -coverprofile=coverage.out -covermode=atomic -coverpkg=$(shell go list ./... | grep -v '/vendor/' | paste -sd, -) ./...

test-appengine-coverage:
	APPENGINE_TEST=true go test -coverprofile=ae_coverage.out -covermode=count -coverpkg=$(shell go list ./... | grep -v '/vendor/' | paste -sd, -) ./...

vet:
	@if [ "`go vet ./... | tee /dev/stderr`" ]; then \
		echo "^ go vet errors!" && echo && exit 1; \
	fi

build:
	go build -ldflags="-w -s" .

build-dev:
	go build .
