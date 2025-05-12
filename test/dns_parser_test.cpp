#include <gtest/gtest.h>
#include "../include/flows/dns_parser.h"
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

// 添加 main 函数
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

using namespace dns_parser;

// 辅助函数：将十六进制字符串转换为二进制数据
std::string hexToBytes(const std::string& hex) {
    std::string bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// 辅助函数：打印二进制数据为十六进制格式
void printHex(const std::string& data) {
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(c) << " ";
    }
    std::cout << std::dec << std::endl;
}

// 测试完整 DNS 查询包解析
TEST(DNSParserTest, ParseFullQueryPacket) {
    // 使用文档中的完整查询包示例
    std::string queryHex = 
        "AAAA"          // Transaction ID
        "0100"          // Flags
        "0001"          // Questions
        "0000"          // Answer RRs
        "0000"          // Authority RRs
        "0000"          // Additional RRs
        "03777777"      // 3 "www"
        "076578616D706C65" // 7 "example"
        "03636F6D"      // 3 "com"
        "00"            // 0 (root)
        "0001"          // Type A
        "0001";         // Class IN
    
    std::string queryData = hexToBytes(queryHex);
    Message message;
    
    ASSERT_TRUE(DNSParser::parseQuery(queryData, message));
    
    std::cout << "\n===== 解析 DNS 查询包 =====" << std::endl;
    std::cout << "Transaction ID: 0x" << std::hex << message.header.transaction_id << std::dec << std::endl;
    std::cout << "Flags: 0x" << std::hex << message.header.flags << std::dec << std::endl;
    std::cout << "Questions: " << message.header.questions << std::endl;
    std::cout << "Answer RRs: " << message.header.answer_rrs << std::endl;
    std::cout << "Authority RRs: " << message.header.authority_rrs << std::endl;
    std::cout << "Additional RRs: " << message.header.additional_rrs << std::endl;
    
    // 验证头部
    EXPECT_EQ(message.header.transaction_id, 0xAAAA);
    EXPECT_EQ(message.header.flags, 0x0100);
    EXPECT_EQ(message.header.questions, 1);
    EXPECT_EQ(message.header.answer_rrs, 0);
    EXPECT_EQ(message.header.authority_rrs, 0);
    EXPECT_EQ(message.header.additional_rrs, 0);
    
    // 验证查询部分
    ASSERT_EQ(message.questions.size(), 1);
    std::cout << "\n查询域名: " << message.questions[0].domain_name << std::endl;
    std::cout << "查询类型: " << message.questions[0].type << std::endl;
    std::cout << "查询类别: " << message.questions[0].class_ << std::endl;
    
    EXPECT_EQ(message.questions[0].domain_name, "www.example.com");
    EXPECT_EQ(message.questions[0].type, 1);  // A 记录
    EXPECT_EQ(message.questions[0].class_, 1); // IN 类
}

// 测试完整 DNS 响应包解析
TEST(DNSParserTest, ParseFullResponsePacket) {
    // 使用文档中的完整响应包示例
    std::string responseHex = 
        "AAAA"          // Transaction ID
        "8180"          // Flags
        "0001"          // Questions
        "0001"          // Answer RRs
        "0000"          // Authority RRs
        "0000"          // Additional RRs
        "03777777"      // 3 "www"
        "076578616D706C65" // 7 "example"
        "03636F6D"      // 3 "com"
        "00"            // 0 (root)
        "0001"          // Type A
        "0001"          // Class IN
        "C00C"          // Pointer to domain name
        "0001"          // Type A
        "0001"          // Class IN
        "0000003C"      // TTL (60)
        "0004"          // Data length
        "5DB8D822";     // IP address (93.184.216.34)
    
    std::string responseData = hexToBytes(responseHex);
    Message message;
    
    ASSERT_TRUE(DNSParser::parseResponse(responseData, message));
    
    std::cout << "\n===== 解析 DNS 响应包 =====" << std::endl;
    std::cout << "Transaction ID: 0x" << std::hex << message.header.transaction_id << std::dec << std::endl;
    std::cout << "Flags: 0x" << std::hex << message.header.flags << std::dec << std::endl;
    std::cout << "Questions: " << message.header.questions << std::endl;
    std::cout << "Answer RRs: " << message.header.answer_rrs << std::endl;
    std::cout << "Authority RRs: " << message.header.authority_rrs << std::endl;
    std::cout << "Additional RRs: " << message.header.additional_rrs << std::endl;
    
    // 验证头部
    EXPECT_EQ(message.header.transaction_id, 0xAAAA);
    EXPECT_EQ(message.header.flags, 0x8180);
    EXPECT_EQ(message.header.questions, 1);
    EXPECT_EQ(message.header.answer_rrs, 1);
    EXPECT_EQ(message.header.authority_rrs, 0);
    EXPECT_EQ(message.header.additional_rrs, 0);
    
    // 验证查询部分
    ASSERT_EQ(message.questions.size(), 1);
    std::cout << "\n查询域名: " << message.questions[0].domain_name << std::endl;
    std::cout << "查询类型: " << message.questions[0].type << std::endl;
    std::cout << "查询类别: " << message.questions[0].class_ << std::endl;
    
    EXPECT_EQ(message.questions[0].domain_name, "www.example.com");
    EXPECT_EQ(message.questions[0].type, 1);  // A 记录
    EXPECT_EQ(message.questions[0].class_, 1); // IN 类
    
    // 验证应答部分
    ASSERT_EQ(message.answers.size(), 1);
    std::cout << "\n应答域名: " << message.answers[0].name << std::endl;
    std::cout << "记录类型: " << message.answers[0].type << std::endl;
    std::cout << "记录类别: " << message.answers[0].class_ << std::endl;
    std::cout << "TTL: " << message.answers[0].ttl << " 秒" << std::endl;
    std::cout << "数据长度: " << message.answers[0].rdlength << " 字节" << std::endl;
    
    EXPECT_EQ(message.answers[0].name, "www.example.com");
    EXPECT_EQ(message.answers[0].type, 1);    // A 记录
    EXPECT_EQ(message.answers[0].class_, 1);  // IN 类
    EXPECT_EQ(message.answers[0].ttl, 60);    // 60秒
    EXPECT_EQ(message.answers[0].rdlength, 4);
    
    // 验证并打印 IP 地址
    const unsigned char* ip = reinterpret_cast<const unsigned char*>(message.answers[0].rdata.data());
    std::cout << "IP 地址: " << static_cast<int>(ip[0]) << "." 
              << static_cast<int>(ip[1]) << "."
              << static_cast<int>(ip[2]) << "."
              << static_cast<int>(ip[3]) << std::endl;
    
    EXPECT_EQ(static_cast<int>(ip[0]), 93);
    EXPECT_EQ(static_cast<int>(ip[1]), 184);
    EXPECT_EQ(static_cast<int>(ip[2]), 216);
    EXPECT_EQ(static_cast<int>(ip[3]), 34);
}

// 测试完整数据包解析和输出
TEST(DNSParserTest, ParseAndPrintFullPacket) {
    // 定义一个完整的 DNS 查询和响应对
    std::string queryHex = 
        "AAAA0100000100000000"
        "03777777076578616D706C6503636F6D0000010001";
    
    std::string responseHex = 
        "AAAA8180000100010000"
        "000003777777076578616D706C6503636F6D0000010001"
        "C00C0001000100000"
        "03C00045DB8D822";
    
    // 打印原始数据包
    std::cout << "\n===== 原始数据包 =====" << std::endl;
    std::cout << "DNS 查询包: " << std::endl;
    printHex(hexToBytes(queryHex));
    std::cout << "DNS 响应包: " << std::endl;
    printHex(hexToBytes(responseHex));
    
    // 解析查询包
    Message queryMessage;
    ASSERT_TRUE(DNSParser::parseQuery(hexToBytes(queryHex), queryMessage));
    
    // 解析响应包
    Message responseMessage;
    ASSERT_TRUE(DNSParser::parseResponse(hexToBytes(responseHex), responseMessage));
    
    // 打印完整解析结果
    std::cout << "\n===== DNS 完整数据包解析结果 =====" << std::endl;
    
    // 打印查询信息
    std::cout << "\n[DNS 查询]" << std::endl;
    std::cout << "Transaction ID: 0x" << std::hex << queryMessage.header.transaction_id << std::dec << std::endl;
    std::cout << "Flags: 0x" << std::hex << queryMessage.header.flags << std::dec << std::endl;
    std::cout << "查询域名: " << queryMessage.questions[0].domain_name << std::endl;
    std::cout << "查询类型: " << queryMessage.questions[0].type << std::endl;
    std::cout << "查询类别: " << queryMessage.questions[0].class_ << std::endl;
    
    // 打印响应信息
    std::cout << "\n[DNS 响应]" << std::endl;
    std::cout << "Transaction ID: 0x" << std::hex << responseMessage.header.transaction_id << std::dec << std::endl;
    std::cout << "Flags: 0x" << std::hex << responseMessage.header.flags << std::dec << std::endl;
    std::cout << "查询域名: " << responseMessage.questions[0].domain_name << std::endl;
    
    if (!responseMessage.answers.empty()) {
        const unsigned char* ip = reinterpret_cast<const unsigned char*>(responseMessage.answers[0].rdata.data());
        std::cout << "\n解析结果:" << std::endl;
        std::cout << responseMessage.questions[0].domain_name << " IN A " 
                  << static_cast<int>(ip[0]) << "." 
                  << static_cast<int>(ip[1]) << "."
                  << static_cast<int>(ip[2]) << "."
                  << static_cast<int>(ip[3]) << std::endl;
        std::cout << "TTL: " << responseMessage.answers[0].ttl << " 秒" << std::endl;
    }
}
