#include "mqtt_server.h"
#include <iostream>
#include <chrono>
#include <thread>

int main() {
    const std::string SERVER_ADDRESS{"ssl://43.203.128.43:8883"};
    const std::string CLIENT_ID{"MMS_Server"};

    mqtt_server server(SERVER_ADDRESS, CLIENT_ID);
    server.connect_with_retry(5, 1); // 5회 시도, 1초 간격

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Prevent high CPU usage
    }
    return 0;
}
