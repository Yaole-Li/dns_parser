cmake_minimum_required(VERSION 3.14)
project(dns_parser)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译选项
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fPIC")
endif()

# 强制使用PIC编译所有的对象
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 设置包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 注释掉不存在的配置解析器库
# add_library(config_parser
#     src/config/config_parser.cpp
# )

# 添加 DNS 解析器库
add_library(dns_parser
    src/flows/dns_parser.cpp
)

# 添加插件库
add_library(dns_plugin SHARED
    src/plugin/plugin.cpp
)

# 链接插件库
target_link_libraries(dns_plugin
    dns_parser
    # config_parser  # 注释掉不存在的依赖
)

# 添加测试可执行文件
add_executable(test_dns_parser
    test/dns_parser_test.cpp
)

# 链接测试可执行文件
target_link_libraries(test_dns_parser
    dns_parser
    gtest
    gtest_main
    pthread
)

# 添加插件测试可执行文件
add_executable(plugin_test
    test/plugin_test.cpp
)

# 链接插件测试可执行文件
target_link_libraries(plugin_test
    dns_parser
    dns_plugin
)