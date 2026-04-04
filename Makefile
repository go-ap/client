GO ?= go
TEST := $(GO) test
TEST_FLAGS ?= -v
TEST_TARGET ?= ./...
GO111MODULE=on
PROJECT_NAME := $(shell basename $(PWD))

.PHONY: test coverage clean download

download: go.sum

go.sum: go.mod
	$(GO) mod tidy

test: go.sum clean
	@touch tests.json
	$(TEST) $(TEST_FLAGS) -cover $(TEST_TARGET) -json > tests.json
	go tool tparse -file tests.json
	@$(RM) ./tests.json

coverage: TEST_FLAGS += -covermode=count -coverprofile $(PROJECT_NAME).coverprofile
coverage: test

clean:
	$(RM) -v *.coverprofile

