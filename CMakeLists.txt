cmake_minimum_required(VERSION 3.5)
project(T2AM_Project VERSION 0.1 DESCRIPTION "ProtoType MQTT Server")

# C++17 표준을 사용하도록 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Google Protocol Buffers 찾기
find_package(Protobuf REQUIRED)

# Paho MQTT C++ 라이브러리 찾기
find_package(PahoMqttCpp REQUIRED)

# 시스템의 기본 include 경로 추가
include_directories(/usr/include)
include_directories(${CMAKE_SOURCE_DIR}/includes)

# proto 디렉토리에 있는 .proto 파일을 처리하기 위해 추가
add_subdirectory(proto)

# server.cpp 파일을 포함한 소스 파일 컴파일
add_executable(server main.cpp src/mqtt_server.cpp src/INIReader.cpp src/ini.c src/header_checker.cpp)

# Proto 파일에서 생성된 소스 파일과 Paho MQTT 라이브러리를 server 실행 파일에 링크
target_link_libraries(server PRIVATE ${Protobuf_LIBRARIES} vehicle_registration_proto PahoMqttCpp::paho-mqttpp3)

# include 디렉토리 추가 (protobuf 생성 파일 포함)
target_include_directories(server PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
