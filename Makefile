CLANG = clang

EXECABLE = monitorBX

BPFCODE = bpf_program

MACRO = -D BPF_TRACE_CUSTOM

LIBRARY_PATH = -L/usr/lib64
BPFSO = -lbpf

LOADINCLUDE += -I/usr/include/bpf

.PHONY: clean $(CLANG) bpfload build

clean:
	rm -f *.o *.so $(EXECABLE)

build: ${BPFCODE.c}
	$(CLANG) $(MACRO) -O2 -target bpf -c $(BPFCODE:=.c) $(CCINCLUDE) -o ${BPFCODE:=.o}

bpfload: build
	g++ -std=c++11 $(CFLAGS) $(MACRO) -o $(EXECABLE) -lelf $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) \
        $(BPFLOADER) loader.cpp -lm

$(EXECABLE): bpfload

.DEFAULT_GOAL := $(EXECABLE)