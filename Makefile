.PHONY: build
build:
	go build -ldflags "-X 'main.Version=$$(git describe --tags)' -X 'main.ReleaseDate=$$(git log -1 --format=%ai $$(git describe --tags) | cat)'"

.PHONY: build-platforms
build-platforms:
	export ACERT_VERSION=$$(git describe --tags) RELEASE_DATE=$$(git log -1 --format=%ai $$(git describe --tags) | cat) \
		&& printf "Building Acert version '%s' (%s)\n" "$${ACERT_VERSION}" "$${RELEASE_DATE}" \
		&& CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "acert-$${ACERT_VERSION}-linux-amd64" -ldflags "-X 'main.Version=$${ACERT_VERSION}' -X 'main.ReleaseDate=$${RELEASE_DATE}'" \
		&& CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o "acert-$${ACERT_VERSION}-linux-arm" -ldflags "-X 'main.Version=$${ACERT_VERSION}' -X 'main.ReleaseDate=$${RELEASE_DATE}'" \
		&& CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "acert-$${ACERT_VERSION}-linux-arm64" -ldflags "-X 'main.Version=$${ACERT_VERSION}' -X 'main.ReleaseDate=$${RELEASE_DATE}'" \
		&& CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o "acert-$${ACERT_VERSION}-darwin-amd64" -ldflags "-X 'main.Version=$${ACERT_VERSION}' -X 'main.ReleaseDate=$${RELEASE_DATE}'" \
		&& CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "acert-$${ACERT_VERSION}-darwin-arm64" -ldflags "-X 'main.Version=$${ACERT_VERSION}' -X 'main.ReleaseDate=$${RELEASE_DATE}'" \
		&& CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "acert-$${ACERT_VERSION}-windows-amd64.exe" -ldflags "-X 'main.Version=$${ACERT_VERSION}' -X 'main.ReleaseDate=$${RELEASE_DATE}'"

