#ifndef FLOW_TABLE_TYPES_H
#define FLOW_TABLE_TYPES_H

#include <string>
#include <vector>
#include <map>

/**
 * @brief DNS 报文头部结构
 */
struct DNSHeader {
    uint16_t transaction_id;     // 会话标识
    uint16_t flags;             // 标志位
    uint16_t questions;         // 问题数
    uint16_t answer_rrs;        // 回答资源记录数
    uint16_t authority_rrs;     // 权威名称服务器数
    uint16_t additional_rrs;    // 附加资源记录数
};

/**
 * @brief DNS 查询问题结构
 */
struct DNSQuestion {
    std::string domain_name;    // 查询的域名
    uint16_t type;             // 查询类型(A、AAAA等)
    uint16_t class_;           // 查询类(通常为IN)
};

/**
 * @brief DNS 资源记录结构
 */
struct DNSResourceRecord {
    std::string name;          // 域名
    uint16_t type;            // 记录类型
    uint16_t class_;          // 类
    uint32_t ttl;             // 生存时间
    uint16_t rdlength;        // 资源数据长度
    std::string rdata;        // 资源数据
};

/**
 * @brief DNS 消息结构
 */
struct Message {
    DNSHeader header;                              // DNS 报文头部
    std::vector<DNSQuestion> questions;            // 查询问题区域
    std::vector<DNSResourceRecord> answers;        // 回答区域
    std::vector<DNSResourceRecord> authorities;    // 权威名称服务器区域
    std::vector<DNSResourceRecord> additionals;    // 附加信息区域
};

/**
 * @brief DNS 查询类型枚举
 */
enum class DNSType : uint16_t {
    A = 1,          // IPv4 地址
    NS = 2,         // 权威名称服务器
    CNAME = 5,      // 规范名
    SOA = 6,        // 起始授权机构
    PTR = 12,       // 指针记录
    MX = 15,        // 邮件交换记录
    TXT = 16,       // 文本记录
    AAAA = 28,      // IPv6 地址
    SRV = 33,       // 服务记录
    ANY = 255       // 任意类型
};

/**
 * @brief DNS 查询类枚举
 */
enum class DNSClass : uint16_t {
    IN = 1,         // Internet
    CS = 2,         // CSNET(已过时)
    CH = 3,         // CHAOS
    HS = 4,         // Hesiod
    ANY = 255       // 任意类
};

/**
 * @brief DNS 响应码枚举
 */
enum class DNSResponseCode : uint16_t {
    NOERROR = 0,    // 无错误
    FORMERR = 1,    // 格式错误
    SERVFAIL = 2,   // 服务器失败
    NXDOMAIN = 3,   // 不存在的域名
    NOTIMP = 4,     // 未实现
    REFUSED = 5     // 拒绝查询
};

/**
 * @brief 四元组结构体，表示网络流的唯一标识
 */
struct FourTuple {
    // 源端
    unsigned char srcIPvN;            // 源IP版本 4/6
    union {
        unsigned int srcIPv4;         // 源IPv4地址
        unsigned char srcIPv6[16];    // 源IPv6地址
    };
    int sourcePort;                   // 源端口
    
    // 目标端
    unsigned char dstIPvN;            // 目标IP版本 4/6
    union {
        unsigned int dstIPv4;         // 目标IPv4地址
        unsigned char dstIPv6[16];    // 目标IPv6地址
    };
    int destPort;                     // 目标端口

    /**
     * @brief 判断两个四元组是否相等
     */
    bool operator==(const FourTuple& other) const {
        // 如果IP版本不同，直接返回不相等
        if (srcIPvN != other.srcIPvN || dstIPvN != other.dstIPvN) {
            return false;
        }
        
        // 检查端口
        if (sourcePort != other.sourcePort || destPort != other.destPort) {
            return false;
        }
        
        // 检查IP地址
        if (srcIPvN == 4) {
            // IPv4比较
            if (srcIPv4 != other.srcIPv4 || dstIPv4 != other.dstIPv4) {
                return false;
            }
        } else if (srcIPvN == 6) {
            // IPv6比较
            for (int i = 0; i < 16; i++) {
                if (srcIPv6[i] != other.srcIPv6[i] || dstIPv6[i] != other.dstIPv6[i]) {
                    return false;
                }
            }
        }
        
        return true;
    }
};

#endif // FLOW_TABLE_TYPES_H