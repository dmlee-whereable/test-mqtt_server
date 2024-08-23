# 현재 디렉토리와 하위 디렉토리에 있는 모든 .proto 파일 찾기
file(GLOB PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)

# edition 폴더 내의 .proto 파일 찾기
file(GLOB EXCLUDED_PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/edition/*.proto)

# edition 폴더 내의 파일을 PROTO_FILES 목록에서 제거
list(REMOVE_ITEM PROTO_FILES ${EXCLUDED_PROTO_FILES})

# Proto 파일을 C++ 코드로 컴파일
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# 생성된 소스 파일을 라이브러리로 추가
add_library(vehicle_registration_proto ${PROTO_SRCS} ${PROTO_HDRS})

# Protobuf 라이브러리 링크
target_link_libraries(vehicle_registration_proto ${Protobuf_LIBRARIES})

# 포함 디렉토리 지정
target_include_directories(vehicle_registration_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
