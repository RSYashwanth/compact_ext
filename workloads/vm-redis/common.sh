set -euo pipefail

: "${NODE:?NODE is not set (run this through run_benchmark.py)}"
: "${DATA_DIR:?DATA_DIR is not set (run this through run_benchmark.py)}"

VM_MB=${VM_MB:-4096}
VM_CPUS=${VM_CPUS:-4}
VM_SSH_PORT=${VM_SSH_PORT:-2223}
IMAGE_URL=${IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}

SMALL_FILES=${SMALL_FILES:-1500000}
SMALL_FILE_BYTES=${SMALL_FILE_BYTES:-1500}
node_mb=$(awk '/MemTotal/ {print int($4 / 1024)}' "/sys/devices/system/node/node$NODE/meminfo")
BIG_FILE_MB=${BIG_FILE_MB:-$((node_mb * 16 / 10))}

KEYS=${KEYS:-24000000}
LOAD_REQUESTS=${LOAD_REQUESTS:-30000000}
VALUE_BYTES=${VALUE_BYTES:-64}
LOAD_PIPELINE=${LOAD_PIPELINE:-64}
READ_REQUESTS=${READ_REQUESTS:-20000000}
READ_PIPELINE=${READ_PIPELINE:-32}
READ_RUNS=${READ_RUNS:-3}
BENCH_CLIENTS=${BENCH_CLIENTS:-8}
BENCH_THREADS=${BENCH_THREADS:-2}

BASE_IMG=$DATA_DIR/base.img
DISK=$DATA_DIR/guest.qcow2
SEED=$DATA_DIR/seed.img
KEY=$DATA_DIR/id_ed25519
PIDFILE=$DATA_DIR/qemu.pid
FILES_DIR=$DATA_DIR/files
BIG_FILE=$DATA_DIR/big.dat

die() { echo "vm-redis: $*" >&2; exit 1; }
log() { echo "vm-redis: $*" >&2; }

vssh() {
	ssh -n -i "$KEY" -p "$VM_SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 \
	    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	    -o LogLevel=ERROR ubuntu@127.0.0.1 "$@"
}

qemu_pid() {
	local pid
	[[ -r $PIDFILE ]] || return 1
	pid=$(<"$PIDFILE")
	[[ $(cat "/proc/$pid/comm" 2>/dev/null) == qemu-vm-redis ]] || return 1
	echo "$pid"
}

boot() {
	local mem_mb=$1 seed=${2:-}

	qemu_pid >/dev/null && die "the guest is already running"
	rm -f "$PIDFILE"
	numactl --membind="$NODE" --cpunodebind="$NODE" \
	qemu-system-x86_64 \
		-name vm-redis,process=qemu-vm-redis \
		-machine q35,accel=kvm,mem-merge=off -cpu host \
		-smp "$VM_CPUS" -m "${mem_mb}M" \
		-drive "file=$DISK,if=virtio,format=qcow2" \
		${seed:+-drive "file=$seed,if=virtio,format=raw,readonly=on"} \
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$VM_SSH_PORT-:22" \
		-device virtio-net-pci,netdev=n0 \
		-display none -serial "file:$DATA_DIR/serial.log" \
		-pidfile "$PIDFILE" -daemonize
	local deadline=$((SECONDS + 600))
	while ((SECONDS < deadline)); do
		vssh true 2>/dev/null && return 0
		qemu_pid >/dev/null || die "QEMU exited during boot; see $DATA_DIR/serial.log"
		sleep 0.5
	done
	die "no ssh from the guest after 600 s; see $DATA_DIR/serial.log"
}

shutdown_guest() {
	local pid

	pid=$(qemu_pid) || return 0
	vssh 'sudo poweroff' 2>/dev/null || true
	for _ in $(seq 1 60); do
		kill -0 "$pid" 2>/dev/null || return 0
		sleep 1
	done
	kill -KILL "$pid" 2>/dev/null || true
}
