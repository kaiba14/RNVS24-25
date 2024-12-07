#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define MAX_STORAGE 100
#define MAX_DYNAMIC_ENTRIES 100

struct dynamic_content {
    char path[256];
    char *content;
} dynamic_files[MAX_DYNAMIC_ENTRIES];
int dynamic_count = 0;

// Storage for dynamic content
typedef struct {
    char *key;
    char *value;
} KeyValue;

KeyValue storage[MAX_STORAGE];
int storage_count = 0;

// Static content
struct static_content {
    const char *path;
    const char *content;
} static_files[] = {
    {"/static/foo", "Foo"},
    {"/static/bar", "Bar"},
    {"/static/baz", "Baz"},
    {NULL, NULL}
};

void send_response(int client_fd, int status, const char *status_text, const char *body) {
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Length: %ld\r\n"
             "\r\n"
             "%s",
             status, status_text, body ? strlen(body) : 0, body ? body : "");
    send(client_fd, response, strlen(response), 0);
}

char* get_dynamic_content(const char *path) {
    for (int i = 0; i < storage_count; i++) {
        if (strcmp(storage[i].key, path) == 0) {
            return storage[i].value;
        }
    }
    return NULL;
}

void store_dynamic_content(const char *path, const char *content) {
    for (int i = 0; i < storage_count; i++) {
        if (strcmp(storage[i].key, path) == 0) {
            free(storage[i].value);
            storage[i].value = strdup(content);
            return;
        }
    }
    
    if (storage_count < MAX_STORAGE) {
        storage[storage_count].key = strdup(path);
        storage[storage_count].value = strdup(content);
        storage_count++;
    }
}

void delete_dynamic_content(const char *path) {
    for (int i = 0; i < storage_count; i++) {
        if (strcmp(storage[i].key, path) == 0) {
            free(storage[i].key);
            free(storage[i].value);
            storage[storage_count-1].key = storage[i].key;
            storage[storage_count-1].value = storage[i].value;
            storage_count--;
            return;
        }
    }
}

int handle_request(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    char method[16], path[256], version[16];
    int total_bytes = 0, bytes_read;
    
    // Read until we get \r\n\r\n
    while ((bytes_read = read(client_fd, buffer + total_bytes, 
           BUFFER_SIZE - total_bytes - 1)) > 0) {
        total_bytes += bytes_read;
        if (strstr(buffer, "\r\n\r\n")) break;
    }
    
    if (bytes_read < 0) return -1;
    buffer[total_bytes] = '\0';

    // Parse request line
    if (sscanf(buffer, "%s %s %s", method, path, version) != 3) {
        send_response(client_fd, 400, "Bad Request", NULL);
        return 0;
    }

    // Handle HEAD method
    if (strcmp(method, "HEAD") == 0) {
        send_response(client_fd, 501, "Not Implemented", NULL);
        return 0;
    }

    // Handle static content
    if (strncmp(path, "/static/", 8) == 0) {
        for (int i = 0; static_files[i].path != NULL; i++) {
            if (strcmp(path, static_files[i].path) == 0) {
                send_response(client_fd, 200, "OK", static_files[i].content);
                return 0;
            }
        }
        send_response(client_fd, 404, "Not Found", NULL);
        return 0;
    }

    // Handle dynamic content
    if (strncmp(path, "/dynamic/", 9) == 0) {
        if (strcmp(method, "GET") == 0) {
            // Find content in dynamic storage
            for (int i = 0; i < dynamic_count; i++) {
                if (strcmp(path, dynamic_files[i].path) == 0) {
                    send_response(client_fd, 200, "OK", dynamic_files[i].content);
                    return 0;
                }
            }
            send_response(client_fd, 404, "Not Found", NULL);
            return 0;
        }
        else if (strcmp(method, "PUT") == 0) {
            char *body = strstr(buffer, "\r\n\r\n");
            if (!body) {
                send_response(client_fd, 400, "Bad Request", NULL);
                return 0;
            }
            body += 4; // Skip \r\n\r\n

            // Store in dynamic content
            strncpy(dynamic_files[dynamic_count].path, path, 
                   sizeof(dynamic_files[dynamic_count].path) - 1);
            dynamic_files[dynamic_count].path[sizeof(dynamic_files[dynamic_count].path) - 1] = '\0';
            dynamic_files[dynamic_count].content = strdup(body);
            dynamic_count++;

            send_response(client_fd, 201, "Created", NULL);
            return 0;
        }
        else if (strcmp(method, "DELETE") == 0) {
            // Find and remove content
            for (int i = 0; i < dynamic_count; i++) {
                if (strcmp(path, dynamic_files[i].path) == 0) {
                    free(dynamic_files[i].content);
                    // Move last entry to current position
                    if (i < dynamic_count - 1) {
                        dynamic_files[i] = dynamic_files[dynamic_count - 1];
                    }
                    dynamic_count--;
                    send_response(client_fd, 204, "No Content", NULL);
                    return 0;
                }
            }
            send_response(client_fd, 404, "Not Found", NULL);
            return 0;
        }
    }

    // Default response for invalid requests
    if (!strstr(buffer, "HTTP/1.")) {
        send_response(client_fd, 400, "Bad Request", NULL);
    } else {
        send_response(client_fd, 404, "Not Found", NULL);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <address> <port>\n", argv[0]);
        exit(1);
    }

    int server_fd;
    struct sockaddr_in address;
    int yes = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
        perror("setsockopt failed");
        exit(1);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(atoi(argv[2]));

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(1);
    }

    // Main server loop
    while (1) {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, 
            &client_len)) < 0) {
            perror("accept failed");
            continue;
        }

        // Handle multiple requests on same connection
        while (handle_request(client_fd) == 0) {
            // Continue handling requests until error
        }
        
        close(client_fd);
    }

    return 0;
}