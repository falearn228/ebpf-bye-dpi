CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
# Определяем архитектуру для макросов (x86, arm64 и т.д.)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Добавляем текущую директорию в INCLUDES, чтобы clang видел сгенерированный vmlinux.h
INCLUDES := -I. -I/usr/include -I/usr/include/x86_64-linux-gnu
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean skel vmlinux

all: vmlinux goodbyedpi.bpf.o

# Правило для генерации vmlinux.h из работающего ядра WSL2
vmlinux:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h || \
		(echo "Error: Could not generate vmlinux.h. Check if CONFIG_DEBUG_INFO_BTF is enabled." && exit 1); \
	fi

goodbyedpi.bpf.o: goodbyedpi.bpf.c vmlinux
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.o vmlinux.h goodbyedpi.skel.h

# Generate skeleton
skel: goodbyedpi.bpf.o
	$(BPFTOOL) gen skeleton $< > goodbyedpi.skel.h
