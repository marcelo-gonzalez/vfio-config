GO := go

.PHONY: fmt clean

vfio-config: | fmt 
	$(GO) build

fmt:
	go fmt
clean:
	rm vfio-config
