OUTPUT := $(abspath ./dist)
LIBBPF_SRC = ./libbpf/src
LIBBPF_OBJ := $(OUTPUT)/libbpf.a
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -O2 -Wall

CLANG := clang
BPFTOOL := bpftool

all: $(OUTPUT)/progs.bpf.o $(OUTPUT)/maps.bpf.o $(OUTPUT)/example

.PHONY: $(LIBBPF_OBJ)
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(OUTPUT)/libbpf DESTDIR=$(OUTPUT)             \
		INCLUDEDIR= LIBDIR= UAPIDIR=                          \
		install

$(OUTPUT)/progs.bpf.o: programs/progs.bpf.c $(LIBBPF_OBJ)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c programs/progs.bpf.c -o $@
	$(BPFTOOL) gen skeleton $@ > $(OUTPUT)/progs.skel.h

$(OUTPUT)/maps.bpf.o: programs/maps.bpf.c $(LIBBPF_OBJ)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c programs/maps.bpf.c -o $@
	$(BPFTOOL) gen skeleton $@ > $(OUTPUT)/maps.skel.h

$(OUTPUT)/example: $(OUTPUT)/progs.bpf.o
	$(CLANG) programs/userspace.c $(LIBBPF_OBJ) -lelf -lz $(INCLUDES) -o $@

clean:
	rm -rf $(OUTPUT)