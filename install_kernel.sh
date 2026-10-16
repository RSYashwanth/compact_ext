#!/bin/bash
set -eu -o pipefail

echo "Installing dependencies..."
sudo -A apt-get update
sudo -A apt-get install -y build-essential bc bison flex rsync libelf-dev \
			libssl-dev libncurses-dev dwarves clang lld \
			llvm python3 python3-pip

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
LINUX_PATH="$BASE_DIR/linux"

cd "$LINUX_PATH"

make distclean

echo "Configuring kernel..."
make olddefconfig

{ yes '' || true;} | make localmodconfig

scripts/config --set-str LOCALVERSION "-compact-ext"
scripts/config --set-str SYSTEM_TRUSTED_KEYS ''
scripts/config --set-str SYSTEM_REVOCATION_KEYS ''
scripts/config --enable CONFIG_BPF_SYSCALL
scripts/config --enable CONFIG_BPF_JIT
scripts/config --enable CONFIG_DEBUG_INFO_BTF
scripts/config --enable CONFIG_COMPACTION
scripts/config --enable CONFIG_COMPACT_EXT

echo "Building and installing the kernel..."
echo "If prompted, hit enter to continue."
make -j$(nproc)
sudo -A make modules_install install

echo "Building and installing libbpf..."
make -C tools/lib/bpf -j
sudo -A make -C tools/lib/bpf install

if [[ ! -e /etc/ld.so.conf.d/libbpf.conf ]]; then
	echo "/usr/local/lib64" | sudo -A tee /etc/ld.so.conf.d/libbpf.conf > /dev/null
	sudo -A ldconfig
	echo "Added /usr/local/lib64 to /etc/ld.so.conf.d/libbpf.conf"
else
	echo "/usr/local/lib64 already exists in /etc/ld.so.conf.d/libbpf.conf"
fi

echo "Building and installing bpftool..."
make -C tools/bpf/bpftool -j
sudo -A make -C tools/bpf/bpftool install

echo "compact_ext kernel installed successfully."
echo "To boot into it, update your bootloader to select the 6.6.8-compact-ext+ kernel."
