#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MESSAGE_SIZE 1500
#define PAYLOAD_SIZE 1497
#define MAX_WORD_SIZE 30
#define HASH_SIZE 23456


typedef struct LinkedList {
    char msg[PAYLOAD_SIZE];  // Speichert den Chunk (Nachricht)
    struct LinkedList* next;     // Zeiger auf das nächste Element
} LinkedList;



typedef struct HashMapEntry {
    char word[MAX_WORD_SIZE];  
    int count;  
    struct HashMapEntry *next;
} HashMapEntry;

typedef struct {
    HashMapEntry *table[HASH_SIZE];
} HashMap;

typedef struct WordOrder {
    char word[MAX_WORD_SIZE];
    struct WordOrder *next;
} WordOrder;




void dequeue(LinkedList** queue, char* buffer);

void enqueue(LinkedList** queue, const char* buffer);

void free_list(LinkedList* head);

void print_list(LinkedList* head);

char* read_file_to_string(const char* filename);

void distribute_chunks_to_workers(LinkedList* worker_list[], LinkedList** chunk_list, int worker_count);

void cut_chunks(LinkedList** queue, const char* file_string);

void insert_word(HashMap *hashmap, const char *word, LinkedList** word_list);

unsigned int hash_function(const char *word);

void free_hashmap(HashMap *hashmap);
void extract_words_to_hashmap(LinkedList* reduced_list, HashMap* hashmap);
void insert_word_count(HashMap* hashmap, const char* word, int count);
void sort_and_print_hashmap(HashMap* hashmap);
int compare_entries(const void *a, const void *b);
int extract_entries(HashMap* hashmap, HashMapEntry** entries);
