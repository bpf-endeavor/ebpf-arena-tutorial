LLC ?= llc-19
CLANG ?= clang-19

build_dir = build
skel_dir = $(build_dir)/skel
bpf_src = pubtrafstat.bpf.c
# define headers as dependencies so the program is recompiled after changes
bpf_headers=$(shell find ./include/ -name '*.h')
out_obj = $(addprefix $(skel_dir)/, $(patsubst %.bpf.c, %.skel.h, $(bpf_src)))

# debuging variables ...
# $(info $(out_obj))
# $(info $(bpf_headers))

BPF_CFLAGS ?=
BPF_CFLAGS += -O2 -g
BPF_CFLAGS += -std=gnu17
BPF_CFLAGS += -Werror
BPF_CFLAGS += -Wno-unused-value
BPF_CFLAGS += -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-address-of-packed-member
BPF_CFLAGS += -I ./include/
BPF_CFLAGS += -D __KERNEL__ -D __BPF__
BPF_CFLAGS += -D __BPF_FEATURE_ADDR_SPACE_CAST



EXTRA_CFLAGS ?=

# Rules
.PHONY: all clean
all: $(build_dir) $(skel_dir) $(out_obj)

# create the build dir if not existing
$(build_dir):
	mkdir -p $@

$(skel_dir):
	mkdir -p $@

clean:
	rm -r $(build_dir)

$(build_dir)/%.ll: %.c
	$(CLANG) $(EXTRA_CFLAGS) $(BPF_CFLAGS) -emit-llvm -c $< -o $@

$(build_dir)/%.o: $(build_dir)/%.ll  $(bpf_headers)
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $<

# Name ``mogu'' is selected from the drink with chewy cubes in it that I
# had a few minutes ago
bpf_skeleton_name=mogu
$(skel_dir)/%.skel.h: $(build_dir)/%.bpf.o
	bpftool gen skeleton $< name $(bpf_skeleton_name) > $@

