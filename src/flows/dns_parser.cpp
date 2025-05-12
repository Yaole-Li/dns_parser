#include "../../include/flows/dns_parser.h"
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

namespace dns_parser {

bool DNSParser::parseQuery(const std::string& data, Message& message) {
    size_t offset = 0;
    
    // 解析 DNS 头部
    if (!parseHeader(data, offset, message.header)) {
        return false;
    }

    // 解析查询问题
    for (uint16_t i = 0; i < message.header.questions; ++i) {
        DNSQuestion question;
        
        // 解析域名
        question.domain_name = parseDomainName(data, offset);
        
        // 解析查询类型和类
        if (offset + 4 > data.size()) {
            return false;
        }
        question.type = ntohs(*reinterpret_cast<const uint16_t*>(data.data() + offset));
        offset += 2;
        question.class_ = ntohs(*reinterpret_cast<const uint16_t*>(data.data() + offset));
        offset += 2;

        message.questions.push_back(question);
    }

    return true;
}

bool DNSParser::parseResponse(const std::string& data, Message& message) {
    size_t offset = 0;
    
    // 解析 DNS 头部
    if (!parseHeader(data, offset, message.header)) {
        return false;
    }

    // 解析查询问题
    for (uint16_t i = 0; i < message.header.questions; ++i) {
        DNSQuestion question;
        question.domain_name = parseDomainName(data, offset);
        
        if (offset + 4 > data.size()) {
            return false;
        }
        question.type = ntohs(*reinterpret_cast<const uint16_t*>(data.data() + offset));
        offset += 2;
        question.class_ = ntohs(*reinterpret_cast<const uint16_t*>(data.data() + offset));
        offset += 2;

        message.questions.push_back(question);
    }

    // 解析应答记录
    for (uint16_t i = 0; i < message.header.answer_rrs; ++i) {
        DNSResourceRecord rr;
        if (!parseResourceRecord(data, offset, rr)) {
            return false;
        }
        message.answers.push_back(rr);
    }

    // 解析权威记录
    for (uint16_t i = 0; i < message.header.authority_rrs; ++i) {
        DNSResourceRecord rr;
        if (!parseResourceRecord(data, offset, rr)) {
            return false;
        }
        message.authorities.push_back(rr);
    }

    // 解析附加记录
    for (uint16_t i = 0; i < message.header.additional_rrs; ++i) {
        DNSResourceRecord rr;
        if (!parseResourceRecord(data, offset, rr)) {
            return false;
        }
        message.additionals.push_back(rr);
    }

    return true;
}

bool DNSParser::parseHeader(const std::string& data, size_t& offset, DNSHeader& header) {
    if (data.size() < 12) {  // DNS 头部固定 12 字节
        return false;
    }

    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
    header.transaction_id = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    header.flags = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    header.questions = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    header.answer_rrs = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    header.authority_rrs = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    header.additional_rrs = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;

    return true;
}

std::string DNSParser::parseDomainName(const std::string& data, size_t& offset) {
    std::string domain;
    
    while (offset < data.size()) {
        uint8_t len = static_cast<uint8_t>(data[offset++]);
        
        // 检查是否是压缩指针
        if ((len & 0xC0) == 0xC0) {  // 最高两位为 11
            if (offset >= data.size()) {
                return domain;
            }
            uint16_t pointer = ((len & 0x3F) << 8) | static_cast<uint8_t>(data[offset++]);
            size_t saved_offset = offset;
            offset = pointer;
            domain += parseDomainName(data, offset);
            offset = saved_offset;
            return domain;
        }
        
        if (len == 0) {
            break;
        }
        
        if (offset + len > data.size()) {
            return domain;
        }
        
        if (!domain.empty()) {
            domain += ".";
        }
        
        domain += data.substr(offset, len);
        offset += len;
    }
    
    return domain;
}

bool DNSParser::parseResourceRecord(const std::string& data, size_t& offset, DNSResourceRecord& rr) {
    // 解析域名
    rr.name = parseDomainName(data, offset);
    
    // 检查剩余字节是否足够
    if (offset + 10 > data.size()) {
        return false;
    }
    
    // 解析类型、类、TTL 和数据长度
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
    rr.type = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    rr.class_ = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    rr.ttl = ntohl(*reinterpret_cast<const uint32_t*>(ptr + offset));
    offset += 4;
    rr.rdlength = ntohs(*reinterpret_cast<const uint16_t*>(ptr + offset));
    offset += 2;
    
    // 检查数据长度是否合法
    if (offset + rr.rdlength > data.size()) {
        return false;
    }
    
    // 解析资源数据
    rr.rdata = data.substr(offset, rr.rdlength);
    offset += rr.rdlength;
    
    return true;
}

void DNSParser::printMessageDetails(const Message& message, bool isQuery) {
    std::cout << "\n===== DNS " << (isQuery ? "查询" : "响应") << " =====" << std::endl;
    
    // 输出头部信息
    printHeader(message.header);
    
    // 输出查询问题
    printQuestions(message.questions);
    
    // 如果是响应包，输出资源记录
    if (!isQuery) {
        printResourceRecords(message.answers, "应答");
        printResourceRecords(message.authorities, "权威");
        printResourceRecords(message.additionals, "附加");
    }
}

void DNSParser::printHeader(const DNSHeader& header) {
    std::cout << "\n[DNS 头部]" << std::endl;
    std::cout << "事务 ID: 0x" << std::hex << std::setw(4) << std::setfill('0') << header.transaction_id << std::dec << std::endl;
    
    // 解析标志位
    uint16_t flags = header.flags;
    bool isResponse = (flags & 0x8000) != 0;
    uint8_t opcode = (flags >> 11) & 0x0F;
    bool isAuthoritative = (flags & 0x0400) != 0;
    bool isTruncated = (flags & 0x0200) != 0;
    bool recursionDesired = (flags & 0x0100) != 0;
    bool recursionAvailable = (flags & 0x0080) != 0;
    uint8_t responseCode = flags & 0x000F;
    
    std::cout << "标志位: 0x" << std::hex << std::setw(4) << std::setfill('0') << flags << std::dec << std::endl;
    std::cout << "  - 查询/响应: " << (isResponse ? "响应" : "查询") << std::endl;
    std::cout << "  - 操作码: " << static_cast<int>(opcode) << std::endl;
    std::cout << "  - 权威应答: " << (isAuthoritative ? "是" : "否") << std::endl;
    std::cout << "  - 截断: " << (isTruncated ? "是" : "否") << std::endl;
    std::cout << "  - 期望递归: " << (recursionDesired ? "是" : "否") << std::endl;
    std::cout << "  - 递归可用: " << (recursionAvailable ? "是" : "否") << std::endl;
    std::cout << "  - 响应码: " << static_cast<int>(responseCode) << std::endl;
    
    std::cout << "问题数: " << header.questions << std::endl;
    std::cout << "应答记录数: " << header.answer_rrs << std::endl;
    std::cout << "权威记录数: " << header.authority_rrs << std::endl;
    std::cout << "附加记录数: " << header.additional_rrs << std::endl;
}

void DNSParser::printQuestions(const std::vector<DNSQuestion>& questions) {
    if (questions.empty()) {
        return;
    }
    
    std::cout << "\n[DNS 查询问题]" << std::endl;
    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& question = questions[i];
        std::cout << "问题 #" << (i + 1) << std::endl;
        std::cout << "域名: " << question.domain_name << std::endl;
        
        // 输出查询类型
        std::cout << "类型: ";
        switch (question.type) {
            case 1: std::cout << "A (1) - IPv4 地址"; break;
            case 2: std::cout << "NS (2) - 权威名称服务器"; break;
            case 5: std::cout << "CNAME (5) - 规范名称"; break;
            case 6: std::cout << "SOA (6) - 权威区域起始"; break;
            case 12: std::cout << "PTR (12) - 指针记录"; break;
            case 15: std::cout << "MX (15) - 邮件交换"; break;
            case 16: std::cout << "TXT (16) - 文本记录"; break;
            case 28: std::cout << "AAAA (28) - IPv6 地址"; break;
            case 33: std::cout << "SRV (33) - 服务定位"; break;
            case 35: std::cout << "NAPTR (35) - 名称权威指针"; break;
            case 255: std::cout << "ANY (255) - 任意类型"; break;
            default: std::cout << question.type << " - 未知类型";
        }
        std::cout << std::endl;
        
        // 输出查询类别
        std::cout << "类别: ";
        switch (question.class_) {
            case 1: std::cout << "IN (1) - 互联网"; break;
            case 3: std::cout << "CH (3) - Chaos"; break;
            case 4: std::cout << "HS (4) - Hesiod"; break;
            default: std::cout << question.class_ << " - 未知类别";
        }
        std::cout << std::endl;
    }
}

void DNSParser::printResourceRecords(const std::vector<DNSResourceRecord>& records, const std::string& recordType) {
    if (records.empty()) {
        return;
    }
    
    std::cout << "\n[DNS " << recordType << "记录]" << std::endl;
    std::cout << "记录数: " << records.size() << std::endl;
    
    for (size_t i = 0; i < records.size(); ++i) {
        const auto& record = records[i];
        std::cout << "\n记录 #" << (i + 1) << std::endl;
        std::cout << "名称: " << record.name << std::endl;
        
        // 输出记录类型
        std::cout << "类型: ";
        switch (record.type) {
            case 1: std::cout << "A (1) - IPv4 地址"; break;
            case 2: std::cout << "NS (2) - 权威名称服务器"; break;
            case 5: std::cout << "CNAME (5) - 规范名称"; break;
            case 6: std::cout << "SOA (6) - 权威区域起始"; break;
            case 12: std::cout << "PTR (12) - 指针记录"; break;
            case 15: std::cout << "MX (15) - 邮件交换"; break;
            case 16: std::cout << "TXT (16) - 文本记录"; break;
            case 28: std::cout << "AAAA (28) - IPv6 地址"; break;
            case 33: std::cout << "SRV (33) - 服务定位"; break;
            case 35: std::cout << "NAPTR (35) - 名称权威指针"; break;
            default: std::cout << record.type << " - 未知类型";
        }
        std::cout << std::endl;
        
        // 输出记录类别
        std::cout << "类别: ";
        switch (record.class_) {
            case 1: std::cout << "IN (1) - 互联网"; break;
            case 3: std::cout << "CH (3) - Chaos"; break;
            case 4: std::cout << "HS (4) - Hesiod"; break;
            default: std::cout << record.class_ << " - 未知类别";
        }
        std::cout << std::endl;
        
        std::cout << "TTL: " << record.ttl << " 秒" << std::endl;
        std::cout << "数据长度: " << record.rdlength << " 字节" << std::endl;
        
        // 根据记录类型解析数据
        if (record.type == 1 && record.rdlength == 4) {  // A 记录
            const unsigned char* ip = reinterpret_cast<const unsigned char*>(record.rdata.data());
            std::cout << "IP 地址: " << static_cast<int>(ip[0]) << "." 
                      << static_cast<int>(ip[1]) << "."
                      << static_cast<int>(ip[2]) << "."
                      << static_cast<int>(ip[3]) << std::endl;
        } else if (record.type == 28 && record.rdlength == 16) {  // AAAA 记录
            const unsigned char* ip = reinterpret_cast<const unsigned char*>(record.rdata.data());
            std::cout << "IPv6 地址: ";
            for (int j = 0; j < 16; j += 2) {
                if (j > 0) std::cout << ":";
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<int>(ip[j]) << std::setw(2) 
                          << static_cast<int>(ip[j+1]);
            }
            std::cout << std::dec << std::endl;
        } else if (record.type == 5) {  // CNAME 记录
            std::cout << "规范名称: " << record.rdata << std::endl;
        } else if (record.type == 2) {  // NS 记录
            std::cout << "名称服务器: " << record.rdata << std::endl;
        } else if (record.type == 15) {  // MX 记录
            if (record.rdlength >= 2) {
                uint16_t preference = ntohs(*reinterpret_cast<const uint16_t*>(record.rdata.data()));
                std::string exchange = record.rdata.substr(2);
                std::cout << "优先级: " << preference << std::endl;
                std::cout << "邮件服务器: " << exchange << std::endl;
            }
        } else if (record.type == 16) {  // TXT 记录
            std::cout << "文本: " << record.rdata << std::endl;
        } else {
            // 其他类型记录，以十六进制显示
            std::cout << "数据: ";
            for (size_t j = 0; j < record.rdata.size(); ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<int>(static_cast<unsigned char>(record.rdata[j])) << " ";
            }
            std::cout << std::dec << std::endl;
        }
    }
}

} // namespace dns_parser
