#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h> 
#include <stdbool.h>
#include "ds_utils.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file.txt> <worker port 1> <worker port 2> ... <worker port n>\n", argv[0]);
        return 1;
    }

    int worker_count = argc - 2;

    // ZeroMQ-Context initialisieren
    void *context = zmq_ctx_new();
    void *worker_sockets[worker_count];
    zmq_pollitem_t poll_worker[worker_count];

    for (int i = 0; i < worker_count; i++) {
        worker_sockets[i] = zmq_socket(context, ZMQ_REQ);
        char endpoint[256];
        snprintf(endpoint, sizeof(endpoint), "tcp://127.0.0.1:%s", argv[i + 2]);

        if (zmq_connect(worker_sockets[i], endpoint) != 0) {
            fprintf(stderr, "Fehler: Konnte nicht mit %s verbinden\n", endpoint);
            zmq_close(worker_sockets[i]);
            // Need to clean up previously created sockets too
            for (int j = 0; j < i; j++) {
                zmq_close(worker_sockets[j]);
            }
            zmq_ctx_destroy(context);
            return 1;
        }

        poll_worker[i].socket = worker_sockets[i];
        poll_worker[i].events = ZMQ_POLLIN;
        poll_worker[i].revents = 0;
        poll_worker[i].fd = -1;
    }

    // Datei einlesen
    const char *filename = argv[1];
    char *file_content = read_file_to_string(filename);
    if (!file_content){
        return 1;
    } 
    // Text in Chunks aufteilen
    LinkedList* worker_list[worker_count];
    LinkedList* chunk_list = NULL;
    cut_chunks(&chunk_list, file_content);
    free(file_content);

    for (int i = 0; i < worker_count; i++) {
        worker_list[i] = NULL;
    }
    distribute_chunks_to_workers(worker_list, &chunk_list, worker_count);

    // Initialisiere Listen für die Map- und Reduce-Phase
    LinkedList *mapped_list = NULL;
    LinkedList *reduced_list = NULL;

    bool map_phase = true;
    bool processing = true;

    while (processing) {
        int active_workers = worker_count;

        // Sende die erste Runde Chunks an alle Worker
        for (int i = 0; i < worker_count; i++) {
            if (worker_list[i] != NULL) {
                char buffer[PAYLOAD_SIZE] = {0};
                dequeue(&worker_list[i], buffer);
                char msg[MESSAGE_SIZE] = {0};

                memcpy(msg, map_phase ? "map" : "red", 3);
                strncpy(msg + 3, buffer, PAYLOAD_SIZE);
                zmq_send(worker_sockets[i], msg, strlen(msg) + 1, 0);
            } else {
                active_workers--;
            }
        }

        // Warte auf Antworten von Workern
        while (active_workers > 0) {
            zmq_poll(poll_worker, worker_count, -1);

            for (int i = 0; i < worker_count; i++) {
                if (poll_worker[i].revents & ZMQ_POLLIN) {
                    char response[MESSAGE_SIZE] = {0};
                    zmq_recv(worker_sockets[i], response, sizeof(response), 0);

                    if (map_phase) {
                        enqueue(&mapped_list, response);
                    } else {
                        enqueue(&reduced_list, response);
                    }

                    // Falls der Worker noch weitere Chunks hat, sende den nächsten
                    if (worker_list[i] != NULL) {
                        char buffer[PAYLOAD_SIZE] = {0};
                        dequeue(&worker_list[i], buffer);
                        char msg[MESSAGE_SIZE] = {0};

                        memcpy(msg, map_phase ? "map" : "red", 3);
                        strncpy(msg + 3, buffer, PAYLOAD_SIZE);
                        zmq_send(worker_sockets[i], msg, strlen(msg) + 1, 0);
                    } else {
                        active_workers--;
                    }
                }
            }
        }

        // Wechsel von Map zu Reduce oder Beenden
        if (map_phase) {
            // Verteile Mapped List auf Worker
            distribute_chunks_to_workers(worker_list, &mapped_list, worker_count);
            map_phase = false;
        } else {
            processing = false;
        }
    }
    // Beende alle Worker mit "rip"
    for (int i = 0; i < worker_count; i++) {
        zmq_send(worker_sockets[i], "rip\0", 4, 0);
        char response[256];
        zmq_recv(worker_sockets[i], response, sizeof(response), 0);
    }

    for (int i = 0; i < worker_count; i++) {
        if (worker_list[i] != NULL) {  // Sicherstellen, dass die Liste existiert
            free_list(worker_list[i]);
            worker_list[i] = NULL;  // Setze den Zeiger nach dem Freigeben auf NULL
        }
    }


    HashMap word_map;
    memset(word_map.table, 0, sizeof(word_map.table));

    extract_words_to_hashmap(reduced_list, &word_map);

    sort_and_print_hashmap(&word_map);
    fflush(stdout);  // Ensure output is flushed

    free_list(chunk_list);
    chunk_list = NULL;


    free_list(mapped_list);
    mapped_list = NULL;

    free_list(reduced_list);
    reduced_list = NULL;

    free_hashmap(&word_map);
        // Cleanup
    for (int i = 0; i < worker_count; i++) {
        zmq_close(worker_sockets[i]);
    }
    zmq_ctx_shutdown(context);
    zmq_ctx_destroy(context);

    return 0;
}
