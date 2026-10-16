# SPDX-License-Identifier: GPL-2.0

CLANG ?= clang
BPFTOOL ?= /usr/local/sbin/bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
LIBBPF_INCLUDE ?= /usr/local/include
LIBBPF_LIBDIR ?= /usr/local/lib64
CFLAGS = -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c -g -Wall \
	 -I. -I$(LIBBPF_INCLUDE)
USERSPACE_CFLAGS = -O2 -fsanitize=address -g -Wall -I. -I$(LIBBPF_INCLUDE)
USERSPACE_LINKER_FLAGS = -L$(LIBBPF_LIBDIR) -lbpf

POLICIES = default stats contig bounded reserve coldskip evict budget \
	   pinned region pause
BPF_OBJ = $(POLICIES:%=compact_ext_%.bpf.o)
LOADERS = compact_ext_run.out compact_ext_default.out compact_ext_stats.out

TESTS = tests/wrong_type_attach.out tests/double_attach.out

LINUX_PATH = ../linux

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

VMLINUX_H = vmlinux.h

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

all: $(BPF_OBJ) $(LOADERS) $(TESTS)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@

.SECONDARY:
%.bpf.o: %.bpf.c $(VMLINUX_H) compact_ext_lib.bpf.h
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) $< -o $@

.SECONDARY:
%.skel.h: %.bpf.o $(VMLINUX_H)
	$(BPFTOOL) gen skeleton $< > $@

%.out: %.c %.skel.h
	$(CLANG) $(USERSPACE_CFLAGS) $< -o $@ $(USERSPACE_LINKER_FLAGS)

compact_ext_run.out: compact_ext_run.c
	$(CLANG) $(USERSPACE_CFLAGS) $< -o $@ $(USERSPACE_LINKER_FLAGS)

compact_ext_stats.bpf.o compact_ext_stats.out: compact_ext_stats.h

tests/double_attach.out: tests/double_attach.c compact_ext_default.skel.h
	$(CLANG) $(USERSPACE_CFLAGS) $< -o $@ $(USERSPACE_LINKER_FLAGS)

clean:
	rm -f *.o *.out *.skel.h $(VMLINUX_H) $(VMLINUX_H).tmp
	rm -f tests/*.o tests/*.out tests/*.skel.h

.PHONY: all clean
