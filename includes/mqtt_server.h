#ifndef MQTT_SERVER_H
#define MQTT_SERVER_H

#include "mqtt/client.h"
#include "VehicleRegistration.pb.h"  // Header 클래스가 정의된 헤더 파일 포함
#include "INIReader.h"

#include <unordered_map>
#include <string>
#include <iomanip>
#include <sstream>

class mqtt_server : public virtual mqtt::callback, public virtual mqtt::iaction_listener {
    mqtt::async_client cli_;
    INIReader reader_;
    std::string username_;
    std::string password_;
    std::string version_;
    std::vector<bool> vehicle_registration_status_;

    void on_failure(const mqtt::token& tok) override;
    void on_success(const mqtt::token& tok) override;
    void connected(const std::string& cause) override;
    void connection_lost(const std::string& cause) override;
    void message_arrived(mqtt::const_message_ptr msg) override;

    void print_header_info(const whereable::t2am::Header& header);
    void process_message_by_class(int message_class, const whereable::t2am::Header& header);

    void load_configuration();

    std::string generate_vehicle_id();
    whereable::t2am::Header create_header(int message_class);

public:
    mqtt_server(const std::string& address, const std::string& client_id);
    void start();
    void connect_with_retry(int max_retries, int retry_delay);
};

#endif // MQTT_SERVER_H
