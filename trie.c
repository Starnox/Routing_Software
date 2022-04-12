#include "trie.h"

TrieNodePointer InitialiseTrieNode()
{
    // alloc memory
    TrieNodePointer newNode = (TrieNodePointer) malloc(sizeof(TrieNode));

    // verification
    if(newNode == NULL)
    {
        printf("Alocare esuata");
        return NULL;
    }

    // initialisation
    newNode->isEnd = 0;
    newNode->entry = NULL;
    int i;
    for(i = 0; i < 2; ++i)
        newNode->sons[i] = NULL;

    return newNode;
}

int InsertNode(TrieNodePointer trieNode, struct route_table_entry *entry)
{
    // verification
    if(trieNode == NULL)
        return 0;

    TrieNodePointer pointerCrawl = trieNode;

    uint32_t addr = entry->prefix;
    uint32_t mask = entry->mask;
    addr = htonl(addr);
    mask = htonl(mask);
    int i;

    for(i = 31; i >= 0 && (((1LL << i)) & mask) >> i == 1 ; i--)
    {
        // get the index
        long long currIndex = (1 << i) & addr;
        currIndex >>= (i);
        //printf("%u %u\n",currIndex, i);
        if(pointerCrawl == NULL)
            return 0; // failure
        
  
            // if the child doesn't exist we create it
        if(pointerCrawl->sons[currIndex] == NULL)
            pointerCrawl->sons[currIndex] = InitialiseTrieNode();
        //printf("here");
        // we advance the crawler
        pointerCrawl = pointerCrawl->sons[currIndex];
    }


    // set the data in the final node
    pointerCrawl->isEnd = 1;
    pointerCrawl->entry = entry;
    return 1;
}

// search the trie and if the item exist than return its info
struct route_table_entry* SearchTrie(TrieNodePointer node, struct in_addr addr)
{
    if(node == NULL)
        return NULL;
    TrieNodePointer pointerCrawl = node;
    uint32_t naddr = htonl(addr.s_addr);
    struct route_table_entry *lastEntry = NULL;

    int i;

    for(i = 31; i >= 0; i--)
    {
        if(pointerCrawl->entry != NULL){
            lastEntry = pointerCrawl->entry;
        }

        if(pointerCrawl == NULL)
            return lastEntry;
        // get the index
        long long currIndex = (1 << i) & naddr;
        currIndex >>= (i);
        //printf("%u\n",currIndex);

        if(pointerCrawl->sons[currIndex] == NULL){
            return lastEntry;
        }
        
        pointerCrawl = pointerCrawl->sons[currIndex];
    }
    printf("here");
    // return the info in the end pointer
    if(pointerCrawl != NULL && pointerCrawl->isEnd)
        return pointerCrawl->entry;
    return NULL;
}


// check if the node has any sons
int IsEmpty(TrieNodePointer node)
{
    int i;
    for(i = 0; i < 2; ++i)
    {
        if(node->sons[i] != NULL)
            return 0;
    }
    return 1;
}
