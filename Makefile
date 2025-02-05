LLC ?= llc-19
CLANG ?= clang-19

build_dir = build
bpf_src = pubtrafstat.bpf.c
# define headers as dependencies so the program is recompiled after changes
bpf_headers=$(shell find ./include/ -name '*.h')
out_obj = $(addprefix $(build_dir)/, $(patsubst %.c, %.o, $(bpf_src)))

# debuging variables ...
$(info $(out_obj))
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
all: $(build_dir) $(out_obj)

# create the build dir if not existing
$(build_dir):
	mkdir -p $@

clean:
	rm -r $(build_dir)

$(build_dir)/%.o: %.c $(bpf_headers)
	$(CLANG) $(EXTRA_CFLAGS) $(BPF_CFLAGS) -emit-llvm -c $< -o $@.ll
	$(LLC) -mcpu=probe -march=bpf -filetype=obj -o $@ $@.ll
