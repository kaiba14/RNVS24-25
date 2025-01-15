#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100
#define UDP_BUFFER 11

struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}};


struct node {
    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    uint16_t id;
};


struct is_responsible {
    struct node resp;
    uint16_t pred_id;
};

struct is_responsible dht_lookup_list[10] = {0};
int dht_index = 0;


struct dht {
    struct node self;
    struct node pred;
    struct node succ;
};

static struct dht dht_info;

struct sockaddr_in addr;
struct sockaddr_in succ_addr;
struct sockaddr_in pred_addr;

bool is_responsible(uint16_t resource_hash, uint16_t self_id, uint16_t pred_id) {
    if (pred_id < self_id) {
        // Normaler Fall
        return (resource_hash > pred_id && resource_hash <= self_id);
    } else {
        // Wrap-Around Fall
        return (resource_hash > pred_id || resource_hash <= self_id);
    }
}

void add_to_dht_lookup_list(struct node resp, uint16_t pred_id) {
    dht_lookup_list[dht_index].resp = resp;
    dht_lookup_list[dht_index].pred_id = pred_id;

    dht_index = (dht_index + 1) % 10;
}


struct node *is_hash_found(uint16_t hash) {
    for (int i = 0; i < dht_index; i++) {

        if (is_responsible(hash, dht_lookup_list[i].resp.id, dht_lookup_list[i].pred_id)) {
            return &dht_lookup_list[i].resp;
        }
    }
    return NULL;
}
void remove_from_dht_lookup_list(uint16_t hash) {

    for (int i = 0; i < dht_index; i++) {
        if (is_responsible(hash, dht_lookup_list[i].resp.id, dht_lookup_list[i].pred_id)) {
            for (int j = i; j < dht_index - 1; j++) {
                dht_lookup_list[j] = dht_lookup_list[j + 1];
            }
            dht_lookup_list[dht_index - 1].resp.id = 0;
            memset(dht_lookup_list[dht_index - 1].resp.ip, 0, INET_ADDRSTRLEN);
            dht_lookup_list[dht_index - 1].resp.port = 0;
            dht_lookup_list[dht_index - 1].pred_id = 0;
            dht_index--;
            return;
        }
    }
}

void handle_reply_message(const uint8_t *buffer) {
    // 1. Nachricht parsen
    uint16_t pred_id = (buffer[1] << 8) | buffer[2];
    uint16_t resp_id = (buffer[3] << 8) | buffer[4]; // Verantwortlicher Node-ID aus Byte 3-4 (Network Byte Order)

    struct in_addr resp_ip;
    resp_ip.s_addr = *(uint32_t *)&buffer[5]; // IP-Adresse des Verantwortlichen (Byte 5-8)

    uint16_t resp_port = (buffer[9] << 8) | buffer[10]; // Port des Verantwortlichen aus Byte 9-10 (Network Byte Order)

    // 2. Erstelle die verantwortliche Node
    struct node responsible_node = {
        .id = resp_id,
        .port = resp_port,
    };
    inet_ntop(AF_INET, &resp_ip, responsible_node.ip, INET_ADDRSTRLEN);

    // 3. Füge den Eintrag in die dht_lookup_list hinzu
    add_to_dht_lookup_list(responsible_node, pred_id);

    // 4. Debug-Ausgabe
    fprintf(stderr, "Reply processed: Responsible Node -> ID=%u, IP=%s, Port=%u; Pred ID=%u\n",
            responsible_node.id, responsible_node.ip, responsible_node.port, pred_id);
}


struct dht init_dht(int argc, char **argv) {
    struct dht info;
    memset(&info, 0, sizeof(info)); // Initialisiere das Struct mit Nullen

    // Self-Node
    strncpy(info.self.ip, argv[1], INET_ADDRSTRLEN - 1);
    info.self.port = (uint16_t)atoi(argv[2]);
    info.self.id = (argc > 3) ? (uint16_t)atoi(argv[3]) : 0;

    // Vorgänger (Predecessor)
    const char *pred_id = getenv("PRED_ID");
    const char *pred_ip = getenv("PRED_IP");
    const char *pred_port = getenv("PRED_PORT");
    if (pred_id && pred_ip && pred_port) {
        strncpy(info.pred.ip, pred_ip, INET_ADDRSTRLEN - 1);
        info.pred.port = (uint16_t)atoi(pred_port);
        info.pred.id = (uint16_t)atoi(pred_id);
    } else {
        // Keine Vorgänger-Informationen verfügbar
        strncpy(info.pred.ip, "0.0.0.0", INET_ADDRSTRLEN - 1);
        info.pred.port = 0;
        info.pred.id = 0;
    }

    // Nachfolger (Successor)
    const char *succ_id = getenv("SUCC_ID");
    const char *succ_ip = getenv("SUCC_IP");
    const char *succ_port = getenv("SUCC_PORT");
    if (succ_id && succ_ip && succ_port) {
        strncpy(info.succ.ip, succ_ip, INET_ADDRSTRLEN - 1);
        info.succ.port = (uint16_t)atoi(succ_port);
        info.succ.id = (uint16_t)atoi(succ_id);
    } else {
        // Keine Nachfolger-Informationen verfügbar
        strncpy(info.succ.ip, "0.0.0.0", INET_ADDRSTRLEN - 1);
        info.succ.port = 0;
        info.succ.id = 0;
    }

    return info;
}



void send_redirect(int conn, const char *uri, const char *resp_ip, uint16_t resp_port) {
    char response[HTTP_MAX_SIZE];
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 303 See Other\r\n"
                       "Location: http://%s:%u%s\r\n"
                       "Content-Length: 0\r\n\r\n",
                       resp_ip, resp_port, uri);

    send(conn, response, len, 0);
}

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request
 * information.
 */
void send_reply(int conn, struct request *request) {

    // Create a buffer to hold the HTTP reply
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;

    fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n",
            request->method, request->uri, request->payload_length);

    if (strcmp(request->method, "GET") == 0) {
        // Find the resource with the given URI in the 'resources' array.
        size_t resource_length;
        const char *resource =
            get(request->uri, resources, MAX_RESOURCES, &resource_length);

        if (resource) {
            size_t payload_offset =
                sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                        resource_length);
            memcpy(reply + payload_offset, resource, resource_length);
            offset = payload_offset + resource_length;
        } else {
            reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            offset = strlen(reply);
        }
    } else if (strcmp(request->method, "PUT") == 0) {
        // Try to set the requested resource with the given payload in the
        // 'resources' array.
        if (set(request->uri, request->payload, request->payload_length,
                resources, MAX_RESOURCES)) {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        } else {
            reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        }
        offset = strlen(reply);
    } else if (strcmp(request->method, "DELETE") == 0) {
        // Try to delete the requested resource from the 'resources' array
        if (delete (request->uri, resources, MAX_RESOURCES)) {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        } else {
            reply = "HTTP/1.1 404 Not Found\r\n\r\n";
        }
        offset = strlen(reply);
    } else {
        reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
        offset = strlen(reply);
    }

    // Send the reply back to the client
    if (send(conn, reply, offset, 0) == -1) {
        perror("send");
        close(conn);
    }
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the
 * return value indicates the number of bytes processed. If the packet is
 * malformed or an error occurs during processing, the return value is -1.
 *
 */
ssize_t process_packet(int conn, char *buffer, size_t n, int udp_socket) {
    struct request request = {
        .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1};
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0) {

        uint16_t path_hash = pseudo_hash((unsigned char *)request.uri, strlen(request.uri));

        struct node *responsible_node = is_hash_found(path_hash);
        if (responsible_node) {
            // Sende Redirect an die gefundene Node
            send_redirect(conn, request.uri, responsible_node->ip, responsible_node->port);


            remove_from_dht_lookup_list(path_hash);

            return bytes_processed;
        }


        if (is_responsible(path_hash, dht_info.self.id, dht_info.pred.id)) {

            send_reply(conn, &request);
        } else if (dht_info.succ.id == dht_info.pred.id) {

            send_redirect(conn, request.uri, dht_info.succ.ip, dht_info.succ.port);
        } else {

            const char *service_unavailable =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 1\r\n"
                "Content-Length: 0\r\n\r\n";
            send(conn, service_unavailable, strlen(service_unavailable), 0);
            
            // Sende Lookup-Nachricht an den Nachfolger
            unsigned char lookup_msg[UDP_BUFFER];
            memset(lookup_msg, 0, sizeof(lookup_msg));


            lookup_msg[0] = 0;

            uint16_t hash_nbo = htons(path_hash);
            memcpy(&lookup_msg[1], &hash_nbo, sizeof(hash_nbo));


            uint16_t id_nbo = htons(dht_info.self.id);
            memcpy(&lookup_msg[3], &id_nbo, sizeof(id_nbo));


            struct in_addr ip_addr;
            inet_pton(AF_INET, dht_info.self.ip, &ip_addr);
            memcpy(&lookup_msg[5], &ip_addr, sizeof(ip_addr));


            uint16_t port_nbo = htons(dht_info.self.port);
            memcpy(&lookup_msg[9], &port_nbo, sizeof(port_nbo));

            ssize_t sent = sendto(udp_socket, lookup_msg, sizeof(lookup_msg), 0,
                                  (struct sockaddr *)&succ_addr, sizeof(succ_addr));
            if (sent == -1) {
                perror("sendto");

            }
        }   
        // Check the "Connection" header in the request to determine if the
        // connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close")) {
            return -1;
        }
    } else if (bytes_processed == -1) {
        // If the request is malformed or an error occurs during processing,
        // send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}


/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network
 * address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from
 * the host and port.
 */
struct sockaddr_in derive_sockaddr(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible
    // addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}


void handle_lookup_message(const uint8_t *buffer, int udp_socket) {
    // 1. Nachricht parsen
    uint16_t hash_id = (buffer[1] << 8) | buffer[2]; // Hash-ID aus Byte 1-2 (Network Byte Order)

    struct in_addr sender_ip;
    sender_ip.s_addr = *(uint32_t *)&buffer[5]; // IP-Adresse des Senders (Byte 5-8, bereits in Network Byte Order)

    uint16_t sender_port = (buffer[9] << 8) | buffer[10]; // Port des Senders aus Byte 9-10 (Network Byte Order)

    // Initialisiere die Adresse des Senders
    char sender_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_ip, sender_ip_str, sizeof(sender_ip_str));
    // Konvertiere den Port in einen String
    char sender_port_str[6]; // Platz für maximal 5 Ziffern + '\0'
    snprintf(sender_port_str, sizeof(sender_port_str), "%u", sender_port);

    // Erstelle die sockaddr_in-Struktur des Senders
    struct sockaddr_in sender_addr = derive_sockaddr(sender_ip_str, sender_port_str);

    // 2. Prüfen der Zuständigkeit
    if (is_responsible(hash_id, dht_info.self.id, dht_info.pred.id)) {
        // Aktuelle Node ist zuständig -> Reply senden
        uint8_t reply_msg[UDP_BUFFER] = {0};

        reply_msg[0] = 1; // Typ: Reply
        uint16_t pred_id_nbo = htons(dht_info.pred.id); // ID des Vorgängers
        memcpy(&reply_msg[1], &pred_id_nbo, sizeof(pred_id_nbo));

        uint16_t self_id_nbo = htons(dht_info.self.id);
        memcpy(&reply_msg[3], &self_id_nbo, sizeof(self_id_nbo));

        struct in_addr self_ip;
        inet_pton(AF_INET, dht_info.self.ip, &self_ip);
        memcpy(&reply_msg[5], &self_ip, sizeof(self_ip));

        uint16_t self_port_nbo = htons(dht_info.self.port);
        memcpy(&reply_msg[9], &self_port_nbo, sizeof(self_port_nbo));

        // Sende die Reply-Nachricht an den Sender
        if (sendto(udp_socket, reply_msg, sizeof(reply_msg), 0,
                   (struct sockaddr *)&sender_addr, sizeof(sender_addr)) == -1) {
            perror("sendto (Reply - self responsible)");
        }
    } else if (is_responsible(hash_id, dht_info.succ.id, dht_info.self.id)) {
        // Nachfolger ist zuständig -> Reply mit Nachfolgerinformationen senden
        uint8_t reply_msg[UDP_BUFFER] = {0};

        reply_msg[0] = 1; // Typ: Reply
        uint16_t self_id_nbo = htons(dht_info.self.id); // ID der aktuellen Node
        memcpy(&reply_msg[1], &self_id_nbo, sizeof(self_id_nbo));

        uint16_t succ_id_nbo = htons(dht_info.succ.id);
        memcpy(&reply_msg[3], &succ_id_nbo, sizeof(succ_id_nbo));

        struct in_addr succ_ip;
        inet_pton(AF_INET, dht_info.succ.ip, &succ_ip);
        memcpy(&reply_msg[5], &succ_ip, sizeof(succ_ip));

        uint16_t succ_port_nbo = htons(dht_info.succ.port);
        memcpy(&reply_msg[9], &succ_port_nbo, sizeof(succ_port_nbo));

        // Sende die Reply-Nachricht an den Sender
        if (sendto(udp_socket, reply_msg, sizeof(reply_msg), 0,
                   (struct sockaddr *)&sender_addr, sizeof(sender_addr)) == -1) {
            perror("sendto (Reply - successor responsible)");
        }
    } else {
        // Weder die aktuelle Node noch der Nachfolger ist zuständig -> Weiterleiten
        if (sendto(udp_socket, buffer, UDP_BUFFER, 0,
                   (struct sockaddr *)&succ_addr, sizeof(succ_addr)) == -1) {
            perror("sendto (Forward lookup)");
        }
    }
}



/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
void connection_setup(struct connection_state *state, int sock) {
    // Set the socket descriptor for the new connection in the connection_state
    // structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded
 * bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the
 * discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep) {
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard); // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the
 * connection state.
 * @return Returns true if the connection and data processing were successful,
 * false otherwise. If an error occurs while receiving data from the socket, the
 * function exits the program.
 */
bool handle_connection(struct connection_state *state, int udp_socket) {
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read =
        recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1) {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    } else if (bytes_read == 0) {
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while ((bytes_processed = process_packet(state->sock, window_start,
                                             window_end - window_start, udp_socket)) > 0) {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1) {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer,
                                window_end - window_start);
    return true;
}



/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of
 * the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
int setup_tcp_socket(struct sockaddr_in addr) {
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but
    // before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Set the SO_REUSEADDR socket option to allow reuse of local addresses
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
        -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending
    // connection
    if (listen(sock, backlog)) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}


/**
 * Erstellt und bindet einen UDP-Socket an die gegebene Adresse.
 *
 * @param addr Der sockaddr_in-Struktur, die die Adresse und den Port enthält.
 * @return Der File-Deskriptor des erstellten UDP-Sockets.
 */
int setup_udp_socket(struct sockaddr_in addr) {
    // Erstelle einen UDP-Socket
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == -1) {
        perror("socket(UDP)");
        exit(EXIT_FAILURE);
    }

    // Setze SO_REUSEADDR, um die Wiederverwendung der Adresse zu erlauben
    int enable = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
        perror("setsockopt(UDP)");
        close(udp_socket);
        exit(EXIT_FAILURE);
    }

    // Binde den UDP-Socket an die gegebene Adresse und den Port
    if (bind(udp_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind(UDP)");
        close(udp_socket);
        exit(EXIT_FAILURE);
    }

    return udp_socket; // Rückgabe des gültigen UDP-Socket-Deskriptors
}

/**
 *  The program expects 3; otherwise, it returns EXIT_FAILURE.
 *
 *  Call as:
 *
 *  ./build/webserver self.ip self.port
 */
int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <IP> <Port> [NodeID]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Initialize DHT info
    dht_info = init_dht(argc, argv);

    // Debug output for DHT info
    printf("Self Node: IP=%s, Port=%u, ID=%u\n",
           dht_info.self.ip, dht_info.self.port, dht_info.self.id);
    printf("Predecessor: IP=%s, Port=%u, ID=%u\n",
           dht_info.pred.ip, dht_info.pred.port, dht_info.pred.id);
    printf("Successor: IP=%s, Port=%u, ID=%u\n",
           dht_info.succ.ip, dht_info.succ.port, dht_info.succ.id);

    addr = derive_sockaddr(dht_info.self.ip, argv[2]);

    char succ_port_str[6];
    snprintf(succ_port_str, sizeof(succ_port_str), "%u", dht_info.succ.port);
    succ_addr = derive_sockaddr(dht_info.succ.ip, succ_port_str);

    char pred_port_str[6];
    snprintf(pred_port_str, sizeof(pred_port_str), "%u", dht_info.pred.port);
    pred_addr = derive_sockaddr(dht_info.pred.ip, pred_port_str);

    int tcp_socket = setup_tcp_socket(addr);
    int udp_socket = setup_udp_socket(addr);

    // Array for monitoring sockets with poll
    struct pollfd sockets[3] = {
        {.fd = tcp_socket, .events = POLLIN},
        {.fd = -1, .events = 0},
        {.fd = udp_socket, .events = POLLIN}
    };

    // Connection state for TCP connections
    struct connection_state state = {0};

    while (true) {
        // Wait for events on sockets
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i++) {
            if (!(sockets[i].revents & POLLIN)) continue;

            int s = sockets[i].fd;

            // Handle TCP listener socket
            if (s == tcp_socket) {
                int connection = accept(tcp_socket, NULL, NULL);
                if (connection == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("accept");
                    close(tcp_socket);
                    exit(EXIT_FAILURE);
                } else {
                    connection_setup(&state, connection);

                    sockets[0].events = 0;
                    sockets[1].fd = connection;
                    sockets[1].events = POLLIN;
                }
            }
            // Handle UDP socket
            else if (s == udp_socket) {
                uint8_t buffer[UDP_BUFFER];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);

                ssize_t bytes_received = recvfrom(udp_socket, buffer, sizeof(buffer), 0,
                                                (struct sockaddr *)&client_addr, &client_len);
                if (bytes_received > 0) {
                    fprintf(stderr, "Received UDP packet from %s:%d\n",
                            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

                    // Prüfe den ersten Byte der Nachricht (Message-Type)
                    uint8_t message_type = buffer[0];
                    if (message_type == 0) {
                        // Handle Lookup-Message
                        handle_lookup_message(buffer, udp_socket);
                    } else if (message_type == 1) {
                        handle_reply_message(buffer);
                    } else {
                        fprintf(stderr, "Unknown message type: %u\n", message_type);
                    }
                } else if (bytes_received == -1) {
                    perror("recvfrom");
                }
            }
            // Handle active TCP connection
            else if (s == state.sock) {
                bool cont = handle_connection(&state, udp_socket);
                if (!cont) {
                    close(state.sock);

                    // Re-enable TCP listener in poll array
                    sockets[0].events = POLLIN;
                    sockets[1].fd = -1;
                    sockets[1].events = 0;
                }
            }
        }
    }

    return EXIT_SUCCESS;
}