#ifndef HEADER_CHECKER_H
#define HEADER_CHECKER_H

#include "VehicleRegistration.pb.h"
#include <string>
#include <unordered_map>

class HeaderChecker {
public:
    HeaderChecker(const std::unordered_map<int, std::string>& valid_message_classes, int max_sender_class);
    bool checkHeader(const whereable::t2am::Header& header, int expected_message_class);

private:
    std::unordered_map<int, std::string> valid_message_classes_;
    int max_sender_class_;
};

#endif
