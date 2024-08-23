#include "mqtt_server.h"
#include "header_checker.h"
#include <VehicleRegistration.pb.h>

const std::string VEHICLE_REGIST_TOPIC{"t2am/register"};
const std::string VEHICLE_REGIST_RESPONSE_TOPIC{"t2am/register/response"};
const std::string CA_CERTS_PATH{"/etc/mosquitto/certs/ca.crt"};

std::unordered_map<int, std::string> valid_message_classes = {
    {1001, "VehicleRegistration"},
    {1002, "VehicleRegistrationResponse"},
    {1003, "ControlConnectionCheck"},
    {1004, "ControlConnectionCheckAck"},
    {1005, "WakeUp"},
    {1006, "WakeUpAck"},
    {2001, "Monitoring_Information"},
    {2002, "Charging_Information"},
    {2003, "Driving"},
    {3001, "TripStart"},
    {3002, "TripEnd"},
    {4001, "ErrorReport"},
    {4002, "Event"}
};

HeaderChecker header_checker(valid_message_classes, 0xFFFF);

mqtt_server::mqtt_server(const std::string& address, const std::string& client_id)
    : cli_(address, client_id), reader_("../config.ini"),  vehicle_registration_status_(1000, false) {
    cli_.set_callback(*this);

    // 설정 파일에서 사용자 이름, 비밀번호, 버전 정보를 로드합니다.
    load_configuration();
}

void mqtt_server::load_configuration() {
    if (reader_.ParseError() < 0) {
        std::cerr << "Error: Can't load configuration file." << std::endl;
        return;
    }

    username_ = reader_.Get("credentials", "username", "");
    password_ = reader_.Get("credentials", "password", "");
    version_ = reader_.Get("settings", "version", "");

    if (username_.empty() || password_.empty()) {
        std::cerr << "Error: Invalid credentials in configuration file." << std::endl;
    }

    if (version_.empty()) {
        std::cerr << "Error: Version information not found in configuration file." << std::endl;
        version_ = "240729001"; // 기본값 설정
    }
}

void mqtt_server::on_failure(const mqtt::token& tok) {
    std::cout << "Operation failed: " << tok.get_message_id() << std::endl;
}

void mqtt_server::on_success(const mqtt::token& tok) {
    std::cout << "Operation succeeded: " << tok.get_message_id() << std::endl;
}

void mqtt_server::connected(const std::string& cause) {
    std::cout << "Connected: " << cause << std::endl;
    try {
        cli_.subscribe(VEHICLE_REGIST_TOPIC, 1, nullptr, *this);
        std::cout << "Subscribe request sent: " << VEHICLE_REGIST_TOPIC << std::endl;
    } catch (const mqtt::exception& exc) {
        std::cerr << "Failed to subscribe: " << exc.what() << std::endl;
    }
}

void mqtt_server::connection_lost(const std::string& cause) {
    std::cerr << "Connection lost: " << cause << std::endl;
}

#include <stdexcept>

std::string convert_timestamp_to_string(int64_t timestamp) {
    // 나노초 단위의 타임스탬프를 초 단위로 변환
    std::time_t seconds = timestamp / 1'000'000'000;
    long nanoseconds = timestamp % 1'000'000'000;

    // time_t를 tm 구조체로 변환
    std::tm* tm_ptr = std::gmtime(&seconds);
    
    if (tm_ptr == nullptr) {
        throw std::runtime_error("Failed to convert timestamp to time structure");
    }

    // 변환된 tm 구조체를 사람이 읽을 수 있는 문자열로 변환
    std::ostringstream oss;
    oss << std::put_time(tm_ptr, "%Y-%m-%d %H:%M:%S") << "." << std::setw(9) << std::setfill('0') << nanoseconds;
    
    if (oss.fail()) {
        throw std::runtime_error("Failed to format time using std::put_time");
    }
    
    return oss.str();
}

// 헤더 정보를 출력하는 함수
void mqtt_server::print_header_info(const whereable::t2am::Header& header) {
    std::cout << "--Header\n";
    std::cout << "Version: " << header.version() << "\n";

    int message_class = header.class_info() >> 16;
    int sender_class = header.class_info() & 0xFFFF;

    // 메시지 클래스 출력
    std::string message_class_str = "UNKNOWN MESSAGE";
    auto it = valid_message_classes.find(message_class);
    if (it != valid_message_classes.end()) {
        message_class_str = it->second;
    }
    std::cout << "Message_Class: " << message_class << " (" << message_class_str << ")\n";

    // 발신자 클래스 출력
    std::cout << "Sender: " << std::hex << std::setw(4) << std::setfill('0') << sender_class << std::dec << "\n";

    // 타임스탬프를 사람이 읽을 수 있는 형식으로 변환하여 출력
    try {
        std::string timestamp_str = convert_timestamp_to_string(header.timestamp());
        std::cout << "Time: " << timestamp_str << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Failed to convert timestamp: " << e.what() << std::endl;
    }
}

std::string mqtt_server::generate_vehicle_id() {
    for (int i = 0; i < vehicle_registration_status_.size(); ++i) {
        if (!vehicle_registration_status_[i]) {
            vehicle_registration_status_[i] = true; // 차량 등록 상태를 true로 설정
            std::ostringstream oss;
            oss << "t2am-airride-" << std::setw(3) << std::setfill('0') << (i + 1);
            return oss.str();
        }
    }
    throw std::runtime_error("No available vehicle IDs.");
}

whereable::t2am::Header mqtt_server::create_header(int message_class) {
    whereable::t2am::Header header;
    header.set_version(std::stoul(version_));
    header.set_class_info((message_class << 16) | 0x0001); // message_class와 sender_class 설정
    header.set_timestamp(std::chrono::system_clock::now().time_since_epoch().count());
    return header;
}

// 메시지 클래스에 따라 처리하는 함수
void mqtt_server::process_message_by_class(int message_class, const whereable::t2am::Header& header) {
    switch (message_class) {
        case 1001: {  // VehicleRegistration
            if (!header_checker.checkHeader(header, 1001)) {
                std::cerr << "Header check failed. Ignoring message." << std::endl;
                return;
            }

            whereable::t2am::VehicleRegistrationResponse response;
            response.mutable_header()->CopyFrom(create_header(1002));
            response.set_vehicle_id(generate_vehicle_id());

            std::string payload;
            response.SerializeToString(&payload);
            // 구독
            mqtt::message_ptr pubmsg = mqtt::make_message(VEHICLE_REGIST_RESPONSE_TOPIC, payload, 1, false); // QoS 1, retain false
            cli_.publish(pubmsg);
            break;
        }
        case 1003: {  // ControlConnectionCheck
            std::cout << "Processing ControlConnectionCheck...\n";
            break;
        }
        case 1005: {  // WakeUp
            std::cout << "Processing WakeUp...\n";
            break;
        }
        default: {
            std::cerr << "Error: Unrecognized message class " << message_class << " (" << "UNKOWN_MESSAGE" << ")\n";
            return;
        }
    }
}

// 메시지 수신 처리 함수
void mqtt_server::message_arrived(mqtt::const_message_ptr msg) {
    std::cout << "Received Message\n";
    try {
        whereable::t2am::VehicleRegistration vehicle_registration;
        if (!vehicle_registration.ParseFromString(msg->to_string())) {
            std::cerr << "Failed to parse the incoming message.\n";
            return;
        }

        const whereable::t2am::Header& header = vehicle_registration.header();

        print_header_info(header);

        int message_class = header.class_info() >> 16;
        process_message_by_class(message_class, header);

    } catch (const std::exception& e) {
        std::cerr << "Failed to process message: " << e.what() << std::endl;
    }
}

void mqtt_server::start() {
    mqtt::ssl_options sslopts;
    sslopts.set_trust_store(CA_CERTS_PATH);
    sslopts.set_verify(true);
    sslopts.set_ssl_version(MQTT_SSL_VERSION_TLS_1_2);

    mqtt::connect_options conn_opts;
    conn_opts.set_keep_alive_interval(20);
    conn_opts.set_clean_session(true);
    conn_opts.set_automatic_reconnect(true);
    conn_opts.set_ssl(sslopts);
    conn_opts.set_user_name(username_);
    conn_opts.set_password(password_);

    try {
        cli_.connect(conn_opts, nullptr, *this);
    } catch (const mqtt::exception& exc) {
        std::cerr << "Connection failed: " << exc.what() << std::endl;
    }
}

void mqtt_server::connect_with_retry(int max_retries, int retry_delay) {
    int attempts = 0;
    while (attempts < max_retries) {
        try {
            start();
            std::this_thread::sleep_for(std::chrono::seconds(2));
            return;
        } catch (const mqtt::exception& exc) {
            std::cerr << "Connection attempt " << (attempts + 1) << " failed: " << exc.what() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(retry_delay));
        attempts++;
    }
    std::cerr << "Failed to connect to MQTT broker after " << max_retries << " attempts." << std::endl;
}
