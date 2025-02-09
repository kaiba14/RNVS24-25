#include "ds_utils.h"



void enqueue(LinkedList** head, const char* chunk) {
    // Speicher für das neue Element reservieren
    LinkedList* node = malloc(sizeof(LinkedList));
    if (!node) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        return;
    }

    // Nachricht kopieren (inklusive Nullterminierung)
    memset(node->msg, 0, strlen(chunk) + 1);
    strncpy(node->msg, chunk, strlen(chunk) + 1);
    node->msg[strlen(chunk)] = '\0';
    node->next = NULL; // Neues Element zeigt auf nichts

    // Falls die Queue leer ist, wird das neue Element zum Head
    if (!(*head)) {
        *head = node;
        return;
    }
    // Zum letzten Element springen und das neue anhängen
    LinkedList* current = *head;
    while (current->next) {
        current = current->next;
    }
    current->next = node;

}


void dequeue(LinkedList** head, char* buffer) {
    if (*head == NULL) {
        buffer[0] = '\0';  // Falls die Queue leer ist, geben wir einen leeren String zurück
        return;
    }

    LinkedList* temp = *head;
    strncpy(buffer, temp->msg, strlen(temp->msg) + 1);  // Kopiert inkl. Nullterminierung
    *head = (*head)->next;  // Das nächste Element wird zum neuen Head
    free(temp);  // Speicher freigeben
}


// Gibt eine ganze LinkedList frei.
void free_list(LinkedList* head) {
    while (head != NULL) {
        LinkedList* temp = head;
        head = head->next;
        free(temp);
    }
}


void print_list(LinkedList* head) {
    LinkedList* current = head;
    int index = 0;

    while (current != NULL) {
        size_t length = strlen(current->msg);

        // Prüfe, ob Nachricht kleiner als PAYLOAD_SIZE ist
        if (length >= PAYLOAD_SIZE) {
            fprintf(stderr,"FEHLER: Nachricht %d überschreitet PAYLOAD_SIZE (%zu Bytes)\n", index, length);
            return;
        }

        // Prüfe, ob die Nachricht nullterminiert ist
        if (current->msg[length] != '\0') {
            fprintf(stderr,"FEHLER: Nachricht %d ist nicht korrekt nullterminiert!\n", index);
            return;
        }

        // Alles okay, Nachricht ausgeben
        fprintf(stderr,"Nachricht %d: %s\n", index, current->msg);
        current = current->next;
        index++;
    }

    fprintf(stderr,"Alle Nachrichten wurden erfolgreich ausgegeben.\n");
}


char* read_file_to_string(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Fehler: Datei konnte nicht geöffnet werden!\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);

    char* buffer = malloc(filesize + 1);
    if (!buffer) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, filesize, file);
    buffer[filesize] = '\0';  // Nullterminierung sicherstellen
    fclose(file);
    return buffer;
}

void distribute_chunks_to_workers(LinkedList* worker_list[], LinkedList** chunk_list, int worker_count) {
    LinkedList* worker_tail[worker_count];  // Speichert das letzte Element jeder Worker-Liste
    for (int i = 0; i < worker_count; i++) {
        worker_list[i] = NULL;
        worker_tail[i] = NULL;
    }

    while (*chunk_list != NULL) {
        for (int i = 0; i < worker_count && *chunk_list != NULL; i++) {
            LinkedList* node = *chunk_list;
            *chunk_list = node->next;
            node->next = NULL;

            if (worker_list[i] == NULL) {
                // Falls die Worker-Liste leer ist, wird der erste Chunk gesetzt
                worker_list[i] = node;
                worker_tail[i] = node;
            } else {
                // Falls die Liste nicht leer ist, ans Ende anhängen
                worker_tail[i]->next = node;
                worker_tail[i] = node;  // Hier wird `worker_tail[i]` aktualisiert


            }
        }
    }
}


void cut_chunks(LinkedList** queue, const char* file_string) {
    int index = 0;
    int length = strlen(file_string);
    int max_chunk_size = PAYLOAD_SIZE - 1;  // Platz für Nullterminierung

    while (index < length) {
        // Falls der verbleibende Text kleiner als die maximale Chunk-Größe ist
        int chunk_size = (index + max_chunk_size < length) ? max_chunk_size : (length - index);
        
        // Prüfen, ob wir am Ende eines Wortes oder mitten in einem Wort sind
        if (chunk_size == max_chunk_size && isalpha(file_string[index + chunk_size])) {
            // Rückwärts gehen, bis wir ein Nicht-Buchstaben-Zeichen finden
            while (chunk_size > 0 && isalpha(file_string[index + chunk_size])) {
                chunk_size--;
            }
        }
        // Chunk in einen Buffer kopieren
        char buffer[PAYLOAD_SIZE];
        strncpy(buffer, file_string + index, chunk_size);
        buffer[chunk_size] = '\0';  // Nullterminierung hinzufügen

        // Chunk in die Queue speichern
        enqueue(queue, buffer);

        // Index verschieben
        index += chunk_size;

        // Falls das nächste Zeichen ein Leerzeichen oder Trennzeichen ist, überspringen
        while (index < length && !isalpha(file_string[index])) {
            index++;
        }
    }
}

unsigned int hash_function(const char *word) {
    unsigned int hash = 0;
    while (*word) 
        hash = (hash * 31 + *word++) % HASH_SIZE;
    return hash;
}


void insert_word(HashMap *hashmap, const char *word, LinkedList** word_list) {
    unsigned int index = hash_function(word);
    
    HashMapEntry* current = hashmap->table[index];
    while (current) {
        if (strcmp(current->word, word) == 0) {
            current->count++;
            return;
        }
        current = current->next;
    }

    HashMapEntry* new_entry = malloc(sizeof(HashMapEntry));
    if (!new_entry) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        return;
    }
    strcpy(new_entry->word, word);
    new_entry->count = 1;
    new_entry->next = hashmap->table[index];
    hashmap->table[index] = new_entry;

    enqueue(word_list, word);

}


void free_hashmap(HashMap *hashmap) {
    for (int i = 0; i < HASH_SIZE; i++) {
        HashMapEntry *entry = hashmap->table[i];
        while (entry != NULL) {
            HashMapEntry *temp = entry;
            entry = entry->next;
            free(temp);  // 🔥 Speicher explizit freigeben!
        }
        hashmap->table[i] = NULL;  // Sicherheitsmaßnahme
    }
}
void extract_words_to_hashmap(LinkedList* final_list, HashMap* hashmap) {
    while (final_list != NULL) {
        char* text = final_list->msg;
        char word[MAX_WORD_SIZE];
        char number[32];  // Buffer for number string
        int word_index = 0;
        int num_index = 0;

        for (int i = 0; text[i] != '\0'; i++) {
            if (isalpha(text[i])) {  
                // Collect letters
                word[word_index++] = text[i];
            } else if (isdigit(text[i])) {  
                // First digit found - finish word
                word[word_index] = '\0';
                
                // Collect all consecutive digits
                while (isdigit(text[i])) {
                    number[num_index++] = text[i++];
                }
                i--; // Adjust index since for-loop will increment
                
                // Convert digit string to number
                number[num_index] = '\0';
                int count = atoi(number);

                // Insert word+count into hashmap
                insert_word_count(hashmap, word, count);

                // Reset for next word
                word_index = 0;
                num_index = 0;
            }
        }

        final_list = final_list->next;
    }
}

int extract_entries(HashMap* hashmap, HashMapEntry** entries) {
    int count = 0;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        HashMapEntry* current = hashmap->table[i];
        while (current) {
            if (count >= HASH_SIZE) {  // Schutz vor Speicherüberlauf
                fprintf(stderr, "Fehler: Zu viele Einträge für Array (%d)\n", count);
                return count;
            }
            entries[count++] = current;
            current = current->next;
        }
    }
    
    return count;
}
int compare_entries(const void *a, const void *b) {
    HashMapEntry *entryA = *(HashMapEntry **)a;
    HashMapEntry *entryB = *(HashMapEntry **)b;

    // Nach Häufigkeit absteigend sortieren
    if (entryB->count != entryA->count) {
        return entryB->count - entryA->count;
    }
    
    // Falls gleiche Häufigkeit, alphabetisch sortieren
    return strcmp(entryA->word, entryB->word);
}

void insert_word_count(HashMap* hashmap, const char* word, int count) {
    if (!word || strlen(word) == 0) {  // Sicherstellen, dass kein leeres Wort eingefügt wird
        fprintf(stderr, "Fehler: Leeres Wort wird nicht eingefügt!\n");
        return;
    }

    unsigned int index = hash_function(word);
    
    HashMapEntry* current = hashmap->table[index];

    while (current) {
        if (strcmp(current->word, word) == 0) {  // Falls das Wort bereits existiert
            current->count += count;
            return;
        }
        current = current->next;
    }

    // Falls das Wort neu ist, erstelle neuen Eintrag
    HashMapEntry* new_entry = malloc(sizeof(HashMapEntry));
    if (!new_entry) {
        fprintf(stderr, "Fehler: Speicherzuweisung fehlgeschlagen!\n");
        return;
    }

    strncpy(new_entry->word, word, MAX_WORD_SIZE - 1);  // Sicherstellen, dass das Wort nicht zu groß ist
    new_entry->word[MAX_WORD_SIZE - 1] = '\0';  // Nullterminierung garantieren
    new_entry->count = count;
    new_entry->next = hashmap->table[index];  // Verkettete Liste für Hash-Kollisionen
    hashmap->table[index] = new_entry;
}
void sort_and_print_hashmap(HashMap* hashmap) {
    HashMapEntry* entries[HASH_SIZE];  // Array zur Speicherung aller Hashmap-Wörter
    memset(entries, 0, sizeof(entries));  // Speicher vorher auf 0 setzen
    int total_entries = extract_entries(hashmap, entries);

    if (total_entries == 0) {
        printf("Keine Wörter zum Sortieren vorhanden.\n");
        return;
    }

    // Sortiere das Array basierend auf Häufigkeit und Alphabet
    qsort(entries, total_entries, sizeof(HashMapEntry*), compare_entries);

    // CSV-Format Ausgabe
    printf("word,frequency\n");
    for (int i = 0; i < total_entries; i++) {
        if (entries[i] == NULL) {  // Schutz vor NULL-Zugriff
            fprintf(stderr, "Fehler: NULL-Eintrag in sortierter Liste gefunden!\n");
            continue;
        }
        printf("%s,%d\n", entries[i]->word, entries[i]->count);
    }
}
