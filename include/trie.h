#include "skel.h"

#ifndef trie_h
#define trie_h

typedef struct trie
{
    struct trie *sons[2];

    struct route_table_entry *entry;
    int isEnd;
}TrieNode, *TrieNodePointer;

typedef void (*FreeFunction)(void **);

TrieNodePointer InitialiseTrieNode();
void DeleteTrie(TrieNodePointer *trieNode, int type, FreeFunction freeFunc);
int InsertNode(TrieNodePointer trieNode, struct route_table_entry *entry); // (0/1) success
struct route_table_entry* SearchTrie(TrieNodePointer node, struct in_addr addr);


int IsEmpty(TrieNodePointer node);
TrieNodePointer Remove(TrieNodePointer *node, char *key, int depth, FreeFunction freeFunc);

#endif