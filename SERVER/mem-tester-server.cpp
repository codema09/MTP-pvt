#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <vector>
#include <sstream>
#include <random>
#include <chrono>
#include <atomic>
#include <mutex>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstdlib>
#include <iomanip>

// --- Server Configuration ---
const std::string HOST = "localhost";
const int PORT = 8443;
const std::string CERT_FILE = "cert.pem";
const std::string KEY_FILE = "key.pem";
const bool ENABLE_RANDOM_DELAY = true;
const int MIN_DELAY = 1;  // seconds
const int MAX_DELAY = 10; // seconds

// Syscall numbers for x86_64 Linux
const long SYS_BRK = 12;
const long SYS_GETTID = 186;

// Thread counter
std::atomic<int> active_threads(0);
std::mutex cout_mutex;

// --- Helper Functions ---

/**
 * Get the actual kernel Thread ID (TID) that eBPF sees
 */
pid_t get_kernel_tid() {
    return syscall(SYS_GETTID);
}

/**
 * Perform brk syscall operations for memory testing
 */
void do_brk() {
    // 1. Get the current program break
    void* current_break = (void*)syscall(SYS_BRK, 0);
    
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Initial program break: 0x" << std::hex << (uintptr_t)current_break << std::dec << std::endl;
    }

    // 2. Increase the program break (allocate memory)
    const size_t page_size = 4096;
    void* new_break_address = (void*)((uintptr_t)current_break + page_size);
    
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Attempting to set new program break to: 0x" << std::hex << (uintptr_t)new_break_address << std::dec << std::endl;
    }

    void* result_addr = (void*)syscall(SYS_BRK, new_break_address);

    if (result_addr == new_break_address) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Successfully increased program break." << std::endl;
    } else {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Failed to increase program break. Return value: 0x" << std::hex << (uintptr_t)result_addr << std::dec << std::endl;
    }

    // 3. Reset the program break (deallocate memory)
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Resetting program break to initial address: 0x" << std::hex << (uintptr_t)current_break << std::dec << std::endl;
    }
    
    syscall(SYS_BRK, current_break);
    
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Program break reset." << std::endl;
    }
}

/**
 * Extract request ID from query parameters
 */
std::string extract_request_id(const std::string& path) {
    size_t query_pos = path.find('?');
    if (query_pos == std::string::npos) {
        return "unknown";
    }

    std::string query = path.substr(query_pos + 1);
    std::istringstream iss(query);
    std::string param;

    while (std::getline(iss, param, '&')) {
        if (param.substr(0, 3) == "id=") {
            return param.substr(3);
        }
    }

    return "unknown";
}

/**
 * Parse HTTP request to extract method and path
 */
bool parse_http_request(const std::string& request, std::string& method, std::string& path) {
    std::istringstream iss(request);
    if (!(iss >> method >> path)) {
        return false;
    }
    return true;
}

/**
 * Log request details with thread information
 */
void log_request(const std::string& method, const std::string& path, int response_code, 
                 const std::string& client_ip, int client_port) {
    pid_t pid = getpid();
    pid_t tid = get_kernel_tid();

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "[REQUEST] " << method << " " << path << " | RESPONSE: " << response_code << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "  Process ID (PID):         " << pid << std::endl;
    std::cout << "  Kernel Thread ID (TID):   " << tid << " <-- THIS SHOULD MATCH THE SNIFFER" << std::endl;
    std::cout << "  Client Address:           " << client_ip << ":" << client_port << std::endl;
    std::cout << "  Active Threads in Server: " << active_threads.load() << std::endl;
    std::cout << std::string(70, '=') << "\n" << std::endl;
}

/**
 * Handle a GET request with memory allocation and optional delay
 */
void handle_get_request(SSL* ssl, const std::string& path, const std::string& client_ip, int client_port) {
    std::string request_id = extract_request_id(path);

    // Allocate memory in multiple stages (just like Python version)
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocating 50 MB string..." << std::endl;
    }
    std::string mem_hog_50(50 * 1024 * 1024, 'A');
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocated 50 MB. Length: " << mem_hog_50.size() << std::endl;
    }

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocating 20 MB string..." << std::endl;
    }
    std::string mem_hog_20(20 * 1024 * 1024, 'A');
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocated 20 MB. Length: " << mem_hog_20.size() << std::endl;
    }

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocating 30 MB string..." << std::endl;
    }
    std::string mem_hog_30(30 * 1024 * 1024, 'A');
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocated 30 MB. Length: " << mem_hog_30.size() << std::endl;
    }

    // Random delay if enabled
    if (ENABLE_RANDOM_DELAY) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(MIN_DELAY, MAX_DELAY);
        double delay = dis(gen);

        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "  [DELAY] Sleeping for " << std::fixed << std::setprecision(2) 
                      << delay << "s (Request ID: " << request_id << ")" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(delay * 1000)));
        
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "  [RESUME] Processing request ID: " << request_id << std::endl;
        }
    }

    // Allocate 200 MB
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocating 200 MB string..." << std::endl;
    }
    std::string mem_hog_200(200 * 1024 * 1024, 'A');
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  [MEMORY] Allocated 200 MB. Length: " << mem_hog_200.size() << std::endl;
    }

    // Perform brk syscall test
    do_brk();

    // Build HTTP response
    std::ostringstream response_body;
    response_body << "<h1>Request " << request_id << " processed</h1>\n";
    response_body << "<p>PID: " << getpid() << ", TID: " << get_kernel_tid() << "</p>\n";
    response_body << "<p>Client: " << client_ip << ":" << client_port << "</p>\n";
    response_body << "<p>Memory Allocated: 100 MB</p>\n";

    std::ostringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: text/html\r\n";
    response << "Content-Length: " << response_body.str().length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << response_body.str();

    std::string response_str = response.str();
    SSL_write(ssl, response_str.c_str(), response_str.length());

    // Log the request
    log_request("GET", path, 200, client_ip, client_port);
}

/**
 * Handle a client connection in a separate thread
 */
void handle_client(SSL* ssl, int client_socket, const std::string& client_ip, int client_port) {
    active_threads++;

    char buffer[4096] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes > 0) {
        buffer[bytes] = '\0';
        std::string request(buffer);
        
        std::string method, path;
        if (parse_http_request(request, method, path)) {
            if (method == "GET") {
                handle_get_request(ssl, path, client_ip, client_port);
            } else {
                // Send 405 Method Not Allowed
                std::string response = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
                SSL_write(ssl, response.c_str(), response.length());
            }
        } else {
            // Send 400 Bad Request
            std::string response = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
            SSL_write(ssl, response.c_str(), response.length());
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);

    active_threads--;
}

/**
 * Initialize OpenSSL
 */
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

/**
 * Cleanup OpenSSL
 */
void cleanup_openssl() {
    EVP_cleanup();
}

/**
 * Create SSL context
 */
SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/**
 * Configure SSL context with certificate and key
 */
void configure_ssl_context(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/**
 * Check if certificate and key files exist
 */
bool check_certificates() {
    return (access(CERT_FILE.c_str(), F_OK) == 0) && (access(KEY_FILE.c_str(), F_OK) == 0);
}

/**
 * Main server function
 */
int main() {
    // Check for certificates
    if (!check_certificates()) {
        std::cout << std::string(60, '=') << std::endl;
        std::cout << " ERROR: Certificate (cert.pem) or Key (key.pem) not found." << std::endl;
        std::cout << " Please run this command first:" << std::endl;
        std::cout << " openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj \"/CN=localhost\"" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        return 1;
    }

    // Initialize OpenSSL
    init_openssl();
    SSL_CTX* ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Unable to create socket");
        return 1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        return 1;
    }

    // Bind socket
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        return 1;
    }

    // Listen
    if (listen(server_socket, 10) < 0) {
        perror("Unable to listen");
        return 1;
    }

    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "🔒 DEFINITIVE HTTPS SERVER STARTED" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "  Server PID:               " << getpid() << std::endl;
    std::cout << "  Listening on:             https://" << HOST << ":" << PORT << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Ready to be traced by 'server-sniffer.py'. Waiting for connections..." << std::endl;
    std::cout << std::string(70, '=') << "\n" << std::endl;

    // Accept connections
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
            perror("Unable to accept");
            continue;
        }

        // Get client IP and port
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        // Create SSL connection
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        // Handle client in a new thread
        std::thread client_thread(handle_client, ssl, client_socket, std::string(client_ip), client_port);
        client_thread.detach();
    }

    close(server_socket);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
