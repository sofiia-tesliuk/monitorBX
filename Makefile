CLANG = clang

EXECABLE = monitor-exec

BPFCODE = bpf_program


LIBRARY_PATH = -L/usr/lib64
BPFSO = -lbpf

LOADINCLUDE += -I/usr/include/bpf

.PHONY: clean $(CLANG) bpfload build

clean:
	rm -f *.o *.so $(EXECABLE)

build: ${BPFCODE.c}
	$(CLANG) -O2 -target bpf -c $(BPFCODE:=.c) $(CCINCLUDE) -o ${BPFCODE:=.o}

bpfload: build
	clang $(CFLAGS) -o $(EXECABLE) -lelf $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) \
        $(BPFLOADER) loader.c

$(EXECABLE): bpfload

.DEFAULT_GOAL := $(EXECABLE)