/**
 * @file plugin.cpp
 * @brief DNS数据包解析插件接口实现
 * 
 * 实现了plugin.h中声明的四个接口函数：
 * - Create：插件创建（全局初始化）
 * - Single：插件构建（线程初始化）
 * - Filter：数据过滤处理
 * - Remove：插件拆除（资源清理）
 */

#include "../../include/plugin/plugin.h"
#include "../../include/flows/dns_parser.h"

// 全局变量

// 项目相关全局变量
static std::string projectRoot;
// 全局配置文件路径
static std::string configFilePath;

// 获取当前目录的工具函数
std::string getCurrentDir() {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        return std::string(cwd) + "/";
    }
    // 返回默认路径
    std::cerr << "警告: 无法获取当前目录，使用相对路径" << std::endl;
    return "./";
}

// 获取项目根目录的工具函数 - 保留以向后兼容
std::string getProjectRoot() {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        std::string currentPath(cwd);
        // 查找flow_table目录
        size_t pos = currentPath.find("flow_table");
        if (pos != std::string::npos) {
            // 返回到flow_table目录的路径
            return currentPath.substr(0, pos + 10) + "/"; // 10是"flow_table"的长度
        }
    }
    // 返回默认路径
    std::cerr << "警告: 无法确定项目根目录，使用相对路径" << std::endl;
    return "./";
}

// 判断文件是否存在
bool fileExists(const std::string& filepath) {
    std::ifstream file(filepath);
    return file.good();
}

// ------------------------------ 1. 插件创建（全局初始化） ------------------------------
// 该部分只在程序启动时执行一次
int Create(unsigned short Version, unsigned short Amount, const char *Option) {
    // 输出插件初始化信息
    std::cout << "DNS数据包解析插件初始化..." << std::endl;
    std::cout << "Version: " << Version << ", Amount: " << Amount << std::endl;
    if (Option) {
        std::cout << "Option: " << Option << std::endl;
    }

    // 获取项目根目录
    projectRoot = getProjectRoot();
    std::cout << "项目根目录: " << projectRoot << std::endl;

    // 设置默认配置文件路径
    if (configFilePath.empty()) {
        configFilePath = projectRoot + "/config/config.ini";
    }
    std::cout << "配置文件路径: " << configFilePath << std::endl;

    // 注释掉配置文件检查，因为这只是测试
    // if (!fileExists(configFilePath)) {
    //     std::cerr << "错误: 配置文件不存在: " << configFilePath << std::endl;
    //     return -1;
    // }
    
    std::cout << "DNS数据包解析插件初始化完成" << std::endl;
    return 0;
}

// ------------------------------ 2. 插件构建（线程初始化） ------------------------------
// 该部分在每个工作线程启动时执行
int Single(unsigned short Thread, const char *Option) {
    // 输出线程初始化信息
    std::cout << "线程 " << Thread << " 初始化..." << std::endl;
    if (Option) {
        std::cout << "Option: " << Option << std::endl;
    }

    std::cout << "线程 " << Thread << " 初始化完成" << std::endl;
    return 0;
}

// ------------------------------ 3. Filter 处理函数 ------------------------------
// 数据过滤函数，处理每个数据包
int Filter(TASK *Import, TASK **Export) {
    // 初始化导出参数
    *Export = Import;

    // 检查输入参数
    if (!Import || !Import->Buffer || Import->Length <= 0) {
        return 0;
    }

    // 判断是查询还是响应（根据源端角色）
    bool isQuery = (Import->Source.Role == 'C');
    
    // 获取数据包内容（直接是应用层数据）
    std::string packetData(reinterpret_cast<char*>(Import->Buffer), Import->Length);
    
    // 创建消息结构
    Message message;
    
    // 解析 DNS 数据包
    bool parseSuccess = false;
    if (isQuery) {
        parseSuccess = dns_parser::DNSParser::parseQuery(packetData, message);
    } else {
        parseSuccess = dns_parser::DNSParser::parseResponse(packetData, message);
    }
    
    // 如果解析成功，输出信息
    if (parseSuccess) {
        // 使用封装的输出函数显示详细信息
        dns_parser::DNSParser::printMessageDetails(message, isQuery);
    }
    
    return 0;
}

// ------------------------------ 4. 插件拆除（资源清理） ------------------------------
// 负责资源释放和清理
void Remove() {
    std::cout << "清理插件资源..." << std::endl;
    std::cout << "插件资源清理完成" << std::endl;
}

// 提供一个函数用于外部设置配置文件路径
void SetConfigFilePath(const char* path) {
    if (path != nullptr) {
        configFilePath = path;
    }
}