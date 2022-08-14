.PHONY: build
build:
	go build -ldflags "-X 'main.Version=$(git describe --tags)' -X 'main.ReleaseDate=$(git log -1 --format=%ai $(git describe --tags) | cat)'"
