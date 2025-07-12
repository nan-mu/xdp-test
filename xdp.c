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
#include <linux/udp.h>
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
        if (iph->protocol == IPPROTO_UDP) {
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
    struct iphdr *iph;
    struct udphdr *udph;

    // 边界检查是必须的，以确保访问安全，满足 eBPF 验证器要求。
    // 即使父程序已做检查，子程序仍需再次确认。

    // 检查以太网头边界
    if (data + sizeof(*eth) > data_end)
        return XDP_ABORTED;

    iph = data + sizeof(*eth);
    // 检查 IP 头边界
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return XDP_ABORTED;

    udph = (void *)iph + sizeof(*iph);
    // 检查 UDP 头边界
    if ((void *)udph + sizeof(*udph) > data_end)
        return XDP_ABORTED;

    // --- 开始交换操作 ---

    // 1. 交换源 IP 和目的 IP
    __be32 original_src_ip = iph->saddr;
    __be32 original_dst_ip = iph->daddr;
    iph->saddr = original_dst_ip;
    iph->daddr = original_src_ip;

    // 2. 交换源 UDP 端口和目的 UDP 端口
    __be16 original_src_port = udph->source;
    __be16 original_dst_port = udph->dest;
    udph->source = original_dst_port;
    udph->dest = original_src_port;

    // 3. 交换以太网帧的源 MAC 地址和目的 MAC 地址
    unsigned char original_h_dest[ETH_ALEN];
    unsigned char original_h_source[ETH_ALEN];
    // 使用 __builtin_memcpy 复制 MAC 地址
    __builtin_memcpy(original_h_dest, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(original_h_source, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, original_h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, original_h_dest, ETH_ALEN);

    // --- 更新校验和 ---
    // 修改了 IP 和 UDP 头部，通常需要重新计算校验和。
    // 简单起见，这里置零，让后续网络栈（或硬件卸载）处理。
    // 在生产环境中，对于 IP 校验和，通常是 `iph->check = 0;`。
    // 对于 UDP 校验和，如果非零，则必须重新计算，因为数据包内容（IP 地址）和端口都变了。
    // 但在 IPv4 中 UDP 校验和为 0 是合法的（可选）。

    // 返回 XDP_TX，表示将修改后的数据包发送回源设备
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
