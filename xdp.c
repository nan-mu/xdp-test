// SPDX-License-Identifier: GPL-2.0
/*
 * 该程序将测试xdp的XDP_CTC返回值是否能正常使用。
 * 测试机部署该程序，另一主机ping测试机的IP地址。
 * 若ping正常工作且该设备收到ping包，则说明XDP_CTC返回值正常。
*/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#define XDP_CTC 5

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} prog_array SEC(".maps");

// parent XDP 程序：识别 ICMP ping，命中则调用 tail call
SEC("xdp")
int parent(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u16 h_proto;
    __u64 off;
    __u32 key = 0; // prog_array[0] 作为 child 程序

    // 检查以太网头
    off = sizeof(*eth);
    if (data + off > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;
    if (h_proto == __constant_htons(ETH_P_IP)) {
        iph = data + off;
        if ((void*)iph + sizeof(*iph) > data_end)
            return XDP_PASS;
        // 识别 ICMP 协议（ping）
        if (iph->protocol == IPPROTO_ICMP) {
            // 命中 ping，调用自定义 tail call helper
            return bpf_redirect_map(&prog_array, key, 0);
        }
    }
    return XDP_PASS;
}


// child XDP 程序：调换 L2 头部地址并 XDP_TX
SEC("xdp")
int child(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u8 tmp[ETH_ALEN];

    if (data + sizeof(*eth) > data_end)
        return XDP_ABORTED;

    // 交换源 MAC 和目的 MAC
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);

    // 修改为ip包防止被过早丢弃
    eth->h_proto = __constant_htons(ETH_P_IP);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
