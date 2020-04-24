GO := go

.PHONY: fmt clean build install uninstall

build: | fmt
	$(GO) build

install: | build
	$(GO) get

uninstall:
	$(GO) clean -i

fmt:
	$(GO) fmt

clean:
	rm vfio-config
