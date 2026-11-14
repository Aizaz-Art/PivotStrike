PROXY := GOPROXY=direct GOSUMDB=off
LDFLAGS := -s -w

.PHONY: all clean server agent cross

all: server agent

server:
	$(PROXY) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-server ./cmd/pivot-server

agent:
	$(PROXY) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent ./cmd/pivot-agent

# Static, dependency-free binaries for every OS/arch an engagement is
# likely to hand you a shell on. CGO_ENABLED=0 matters: a cgo-linked agent
# binary dynamically depends on the target's libc and can fail to run on
# an exam box with a different glibc version — the single most common
# "it worked on my Kali but not on the target" bug report for tools like
# this.
cross:
	mkdir -p dist
	$(PROXY) GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_linux_amd64       ./cmd/pivot-agent
	$(PROXY) GOOS=linux   GOARCH=386   CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_linux_386         ./cmd/pivot-agent
	$(PROXY) GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_linux_arm64       ./cmd/pivot-agent
	$(PROXY) GOOS=linux   GOARCH=arm   CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_linux_arm        ./cmd/pivot-agent
	$(PROXY) GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_windows_amd64.exe ./cmd/pivot-agent
	$(PROXY) GOOS=windows GOARCH=386   CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_windows_386.exe   ./cmd/pivot-agent
	$(PROXY) GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_darwin_amd64      ./cmd/pivot-agent
	$(PROXY) GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-agent_darwin_arm64      ./cmd/pivot-agent
	$(PROXY) GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-server_linux_amd64      ./cmd/pivot-server
	$(PROXY) GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-server_windows_amd64.exe ./cmd/pivot-server
	$(PROXY) GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pivotstrike-server_darwin_arm64     ./cmd/pivot-server
	@echo "Built everything into dist/. Strip symbols already applied (-s -w);"
	@echo "upx-pack the agent binaries yourself if you need them smaller/more AV-evasive."

clean:
	rm -rf dist
