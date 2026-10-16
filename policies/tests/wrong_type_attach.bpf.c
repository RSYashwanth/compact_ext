// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("struct_ops/wrong_ssthresh")
__u32 BPF_PROG(wrong_ssthresh, struct sock *sk)
{
	return 2;
}

SEC("struct_ops/wrong_cong_avoid")
void BPF_PROG(wrong_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
}

SEC("struct_ops/wrong_undo_cwnd")
__u32 BPF_PROG(wrong_undo_cwnd, struct sock *sk)
{
	return 2;
}

SEC(".struct_ops.link")
struct tcp_congestion_ops wrong_type_ops = {
	.ssthresh = (void *)wrong_ssthresh,
	.cong_avoid = (void *)wrong_cong_avoid,
	.undo_cwnd = (void *)wrong_undo_cwnd,
	.name = "cext_wrong_type",
};
