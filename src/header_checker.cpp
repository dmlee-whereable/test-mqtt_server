#include "header_checker.h"
#include <iostream>

HeaderChecker::HeaderChecker(const std::unordered_map<int, std::string>& valid_message_classes, int max_sender_class)
    : valid_message_classes_(valid_message_classes), max_sender_class_(max_sender_class) {}

bool HeaderChecker::checkHeader(const whereable::t2am::Header& header, int expected_message_class) {
    int message_class = header.class_info() >> 16;
    int sender_class = header.class_info() & 0xFFFF;

    auto it = valid_message_classes_.find(message_class);
    if (it == valid_message_classes_.end()) {
        std::cerr << "Error: Unrecognized message class " << message_class << " (Unknown Message)" << std::endl;
        return false;
    }

    if (message_class != expected_message_class) {
        std::cerr << "Error: Invalid message class " << message_class << ", expected " << expected_message_class << std::endl;
        return false;
    }

    if (message_class == 1001) {
        if (sender_class != 0xFFFF) {
            std::cerr << "Error: For message class 1001, sender class must be 0xFFFF, but got " << std::hex << sender_class << std::dec << std::endl;
            return false;
        }
    }

    return true;
}
