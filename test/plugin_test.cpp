/**
 * @file plugin_test.cpp
 * @brief 测试DNS解析插件的完整流程
 * 
 * 该文件模拟插件的完整流程，包括初始化、处理DNS查询和响应包、清理资源等步骤
 */

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include "../include/plugin/plugin.h"
#include "../include/flows/dns_parser.h"
#include "../include/tools/types.h"

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

// 创建模拟的DNS查询TASK
TASK* createDNSQueryTask() {
    // DNS查询包示例（查询www.example.com的A记录）
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
    
    // 创建TASK结构
    TASK* task = new TASK();
    memset(task, 0, sizeof(TASK));
    
    // 设置通告指令
    task->Inform = 0x12;  // 数据传输
    
    // 设置源端（客户端）
    task->Source.Role = 'C';  // 客户端
    task->Source.IPvN = 4;    // IPv4
    task->Source.IPv4 = inet_addr("192.168.1.100");
    task->Source.Port = 12345;
    
    // 设置宿端（服务器）
    task->Target.Role = 'S';  // 服务器
    task->Target.IPvN = 4;    // IPv4
    task->Target.IPv4 = inet_addr("8.8.8.8");
    task->Target.Port = 53;   // DNS端口
    
    // 设置数据
    task->Length = queryData.size();
    task->Buffer = new unsigned char[task->Length];
    memcpy(task->Buffer, queryData.c_str(), task->Length);
    
    return task;
}

// 创建模拟的DNS响应TASK
TASK* createDNSResponseTask() {
    // DNS响应包示例（www.example.com的A记录响应）
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
    
    // 创建TASK结构
    TASK* task = new TASK();
    memset(task, 0, sizeof(TASK));
    
    // 设置通告指令
    task->Inform = 0x12;  // 数据传输
    
    // 设置源端（服务器）
    task->Source.Role = 'S';  // 服务器
    task->Source.IPvN = 4;    // IPv4
    task->Source.IPv4 = inet_addr("8.8.8.8");
    task->Source.Port = 53;   // DNS端口
    
    // 设置宿端（客户端）
    task->Target.Role = 'C';  // 客户端
    task->Target.IPvN = 4;    // IPv4
    task->Target.IPv4 = inet_addr("192.168.1.100");
    task->Target.Port = 12345;
    
    // 设置数据
    task->Length = responseData.size();
    task->Buffer = new unsigned char[task->Length];
    memcpy(task->Buffer, responseData.c_str(), task->Length);
    
    return task;
}

// 释放TASK资源
void freeTask(TASK* task) {
    if (task) {
        if (task->Buffer) {
            delete[] task->Buffer;
        }
        delete task;
    }
}

int main() {
    std::cout << "===== DNS解析插件测试程序 =====" << std::endl;
    
    // 1. 插件初始化
    std::cout << "\n----- 步骤1: 插件初始化 -----" << std::endl;
    int createResult = Create(1, 0, nullptr);
    if (createResult != 0) {
        std::cerr << "插件初始化失败，错误码: " << createResult << std::endl;
        return 1;
    }
    
    // 2. 线程初始化
    std::cout << "\n----- 步骤2: 线程初始化 -----" << std::endl;
    int singleResult = Single(1, nullptr);
    if (singleResult != 0) {
        std::cerr << "线程初始化失败，错误码: " << singleResult << std::endl;
        Remove();  // 清理资源
        return 1;
    }
    
    // 3. 处理DNS查询包
    std::cout << "\n----- 步骤3: 处理DNS查询包 -----" << std::endl;
    TASK* queryTask = createDNSQueryTask();
    TASK* queryExport = nullptr;
    
    int queryResult = Filter(queryTask, &queryExport);
    if (queryResult != 0) {
        std::cerr << "处理DNS查询包失败，错误码: " << queryResult << std::endl;
    }
    
    // 4. 处理DNS响应包
    std::cout << "\n----- 步骤4: 处理DNS响应包 -----" << std::endl;
    TASK* responseTask = createDNSResponseTask();
    TASK* responseExport = nullptr;
    
    int responseResult = Filter(responseTask, &responseExport);
    if (responseResult != 0) {
        std::cerr << "处理DNS响应包失败，错误码: " << responseResult << std::endl;
    }
    
    // 5. 清理资源
    std::cout << "\n----- 步骤5: 清理资源 -----" << std::endl;
    Remove();
    
    // 释放TASK资源
    freeTask(queryTask);
    freeTask(responseTask);
    
    std::cout << "\n===== DNS解析插件测试完成 =====" << std::endl;
    return 0;
}
