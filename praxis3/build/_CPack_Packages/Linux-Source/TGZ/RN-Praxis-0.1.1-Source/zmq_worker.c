#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <zmq.h>
#include <string.h>
#include <unistd.h>
#include "ds_utils.h"


#define MAX_MSG_LEN 1500


typedef struct {
    char *port;
    void *context;
} worker_data;
char* worker_red(char *msg) {

    // Speicher für den neuen reduzierten String reservieren
    char *reduced_msg = malloc(PAYLOAD_SIZE);
    if (!reduced_msg) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        return NULL;
    }

    int i = 0, j = 0, sum = 0;
    int in_number = 0;  // Flag, das anzeigt, ob wir gerade in einer Zahlenreihe sind

    while (msg[i] != '\0') {
        if (isdigit((unsigned char)msg[i])) {
            sum += (msg[i] - '0');  // Ziffer zu `sum` addieren
            in_number = 1;
        } else {
            if (in_number) {  // Falls wir vorher Zahlen hatten, summierte Zahl einfügen
                j += sprintf(reduced_msg + j, "%d", sum);
                sum = 0;
                in_number = 0;
            }

            if (j < PAYLOAD_SIZE - 1) {  // Falls Platz im Buffer ist, Zeichen kopieren
                reduced_msg[j++] = msg[i];
            }
        }
        i++;
    }

    // Falls das Wort mit einer Zahl endet, diese Zahl noch einfügen
    if (in_number) {
        j += sprintf(reduced_msg + j, "%d", sum);
    }

    reduced_msg[j] = '\0';  // Nullterminierung setzen
    return reduced_msg;  // Reduzierten String zurückgeben
}



char* worker_map(char *msg) {
    int j = 0;
    size_t len = strlen(msg);

    // Speicher für den neuen String reservieren
    char *processed_msg = malloc(len + 1);
    if (!processed_msg) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        return NULL;
    }

    // Zeichen filtern und in `processed_msg` speichern
    for (size_t i = 0; i < len; i++) {
        if (isalpha((unsigned char)msg[i])) {
            processed_msg[j++] = tolower((unsigned char)msg[i]);
        } else if (j > 0 && processed_msg[j - 1] != ' ') {
            processed_msg[j++] = ' ';
        }
    }

    // Falls das letzte Zeichen ein Leerzeichen ist, entfernen
    if (j > 0 && processed_msg[j - 1] == ' ') {
        j--;
    }

    processed_msg[j] = '\0';  // Nullterminierung setzen

    // Hashmap initialisieren
    HashMap hash_table;
    memset(hash_table.table, 0, sizeof(hash_table.table));  
    LinkedList* word_list = NULL;

    char *save_ptr;
    for (char *token = strtok_r(processed_msg, " ", &save_ptr);
        token != NULL;
        token = strtok_r(NULL, " ", &save_ptr))
    {
        insert_word(&hash_table, token, &word_list);
    }

    // Speicher für die Ausgabe reservieren
    char *output = malloc(PAYLOAD_SIZE);
    if (!output) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        free(processed_msg);
        return NULL;
    }
    

    // Wörter in der Reihenfolge ihrer Erkennung zusammensetzen
    int index = 0;
    LinkedList *current = word_list;
    while (current != NULL) {
        unsigned int hash_index = hash_function(current->msg);
        HashMapEntry *entry = hash_table.table[hash_index];

        // Suche das korrekte Wort in der HashMap
        while (entry != NULL && strcmp(entry->word, current->msg) != 0) {
            entry = entry->next;
        }

        if (entry) {
            index += snprintf(output + index, PAYLOAD_SIZE - index, "%s", entry->word);
            for (int i = 0; i < entry->count; i++) {
                if (index < PAYLOAD_SIZE - 1) {
                    output[index++] = '1';
                }
            }
        }

        current = current->next;
    }

    output[index] = '\0';  // Nullterminierung setzen

    // Speicher freigeben
    free(processed_msg);
    free_list(word_list);
    free_hashmap(&hash_table);

    return output;
}






void *handle_worker(void *arg) {
    worker_data *data = (worker_data *)arg;
    char endpoint[256];

    snprintf(endpoint, sizeof(endpoint), "tcp://127.0.0.1:%s", data->port);
    void *socket = zmq_socket(data->context, ZMQ_REP);

    if (zmq_bind(socket, endpoint) != 0) {
        fprintf(stderr, "Fehler: Konnte Worker nicht an %s binden\n", endpoint);
        zmq_close(socket);
        free(data);
        return NULL;
    }

    printf("Worker läuft auf %s\n", endpoint);
    while (1) {
        char buffer[MAX_MSG_LEN];  // Puffer für eingehende Nachrichten
        zmq_recv(socket, buffer, sizeof(buffer), 0);
        
        if (strncmp(buffer, "map", 3) == 0) {
            char* response = worker_map(buffer + 3);
            zmq_send(socket, response, strlen(response) + 1, 0);
            free(response);  // Speicher nach Nutzung freigeben!

        } else if (strncmp(buffer, "red", 3) == 0) {
            char* response = worker_red(buffer + 3);
            zmq_send(socket, response, strlen(response) + 1, 0);
            free(response);  // Speicher nach Nutzung freigeben!

        } else if (strcmp(buffer, "rip") == 0) {
            char* response = "rip";
            zmq_send(socket, response, strlen(response) + 1 , 0);
            break;
        }
    }

    zmq_close(socket);
    free(data);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 0;
    }

    int num_workers = argc - 1;
    pthread_t threads[num_workers];
    void *context = zmq_ctx_new();

    for (int i = 0; i < num_workers; i++) {
        worker_data *data = malloc(sizeof(worker_data));
        data->port = argv[i + 1];
        data->context = context;

        pthread_create(&threads[i], NULL, handle_worker, data);
    }

    for (int i = 0; i < num_workers; i++) {
        pthread_join(threads[i], NULL);
    }

    zmq_ctx_destroy(context);
    return 0;
}
