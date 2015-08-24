.PHONY: clean

TOOLS = $(wildcard *.go)
BINARIES = $(patsubst %.go,%,$(TOOLS))

%: %.go
	go build $@.go

all: $(BINARIES)

clean:
	rm -f $(BINARIES)
