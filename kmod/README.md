## Complications when compiling this kmod

* make sure kernel has BTF support (check if there is yes)

```bash
cat /boot/config-$(uname -r) | grep BTF
```

* make sure you have `pahole`

```bash
cd $HOME/
git clone https://github.com/acmel/dwarves.git
cd dwarves
mkdir build
cd build/
cmake ../
make -j
sudo make install
sudo ldconfig
```

* make sure vmlinux is available in `/usr/lib/modules` directory

```bash
sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(uname -r)/build/
```

* make sure the `resolve_btfids` tool is available
> If there is an error like `... resolve_btfids: not found`

```
sudo mkdir -p /usr/src/linux-headers-6.13.3-arena/tools/bpf/resolve_btfids/
cd $LINUX_KERNEL_SOURCE/tools/bpf/resolve_btfids/
make
sudo cp ./resolve_btfids /usr/src/linux-headers-6.13.3-arena/tools/bpf/resolve_btfids/resolve_btfids
```

