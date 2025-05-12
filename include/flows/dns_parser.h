#ifndef DNS_PARSER_DNS_PARSER_H
#define DNS_PARSER_DNS_PARSER_H

#include <string>
#include <vector>
#include "../tools/types.h"

namespace dns_parser {

class DNSParser {
public:
    /**
     * @brief 解析 DNS 查询包
     * @param data 原始数据
     * @param message 解析后的消息结构
     * @return 是否解析成功
     */
    static bool parseQuery(const std::string& data, Message& message);

    /**
     * @brief 解析 DNS 响应包
     * @param data 原始数据
     * @param message 解析后的消息结构
     * @return 是否解析成功
     */
    static bool parseResponse(const std::string& data, Message& message);
    
    /**
     * @brief 输出 DNS 消息的详细信息
     * @param message DNS 消息结构
     * @param isQuery 是否是查询包
     */
    static void printMessageDetails(const Message& message, bool isQuery);
    
    /**
     * @brief 输出 DNS 头部信息
     * @param header DNS 头部结构
     */
    static void printHeader(const DNSHeader& header);
    
    /**
     * @brief 输出 DNS 查询问题信息
     * @param questions DNS 查询问题列表
     */
    static void printQuestions(const std::vector<DNSQuestion>& questions);
    
    /**
     * @brief 输出 DNS 资源记录信息
     * @param records DNS 资源记录列表
     * @param recordType 记录类型名称（如“应答”、“权威”、“附加”）
     */
    static void printResourceRecords(const std::vector<DNSResourceRecord>& records, const std::string& recordType);

private:
    /**
     * @brief 解析 DNS 头部
     * @param data 原始数据
     * @param offset 当前偏移量
     * @param header DNS 头部结构
     * @return 是否解析成功
     */
    static bool parseHeader(const std::string& data, size_t& offset, DNSHeader& header);

    /**
     * @brief 解析域名
     * @param data 原始数据
     * @param offset 当前偏移量
     * @return 解析出的域名
     */
    static std::string parseDomainName(const std::string& data, size_t& offset);

    /**
     * @brief 解析资源记录
     * @param data 原始数据
     * @param offset 当前偏移量
     * @param rr 资源记录结构
     * @return 是否解析成功
     */
    static bool parseResourceRecord(const std::string& data, size_t& offset, DNSResourceRecord& rr);
};

} // namespace dns_parser

#endif // DNS_PARSER_DNS_PARSER_H
