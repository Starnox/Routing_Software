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

/*
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


TrieNodePointer Remove(TrieNodePointer *node, char *key, int depth, FreeFunction freeFunc)
{
    if(*node == NULL)
        return NULL;

    // if it is the last character of the key
    if(depth == strlen(key))
    {
        // if the node is not the prefix to any other key
        if(IsEmpty(*node))
        {
            DeleteTrie(node, 1, freeFunc);
            *node = NULL;
        }

        // if it is the end of a key
        if(*node != NULL && (*node)->isEnd)
        {
            // if we want to free the information
            if(freeFunc != NULL)
            {
                freeFunc(&((*node)->endPointer));
            }
            // the node is no more the end of a key
            (*node)->isEnd = 0;
        }
        return *node;
    }
    int index = GetIndexInAlphabet(key[depth]);

    (*node)->sons[index] = Remove(&(*node)->sons[index], key, depth + 1, freeFunc);

    // if the node does not have any child and is not end of another word
    if(IsEmpty(*node) && (*node)->isEnd == 0)
    {
        DeleteTrie(node, 1, freeFunc);
        *node = NULL;
    }
    return *node;
}


void DeleteTrie(TrieNodePointer *trieNode, int type, FreeFunction freeFunc)
{
    if(*trieNode == NULL)
        return;

    int i;

    if((*trieNode)->isEnd)// if it is end of word
    {
        // if it is of type T2
        if(type == 2)
        {
            // then delete the type 1 trie associated with it
            DeleteTrie((TrieNodePointer *) &((*trieNode)->endPointer), 1, freeFunc);
        }
        else
        {
            if(freeFunc != NULL) // if we want to free the info
                freeFunc(&((*trieNode)->endPointer));
        }

    }

    for(i = 0; i< 2; ++i)
    {
        // if the node exists
        if((*trieNode)->sons[i])
        {
            // go deeper in the trie with dfs approach
            DeleteTrie(&((*trieNode)->sons[i]), type, freeFunc);
        }
    }

    free(*trieNode);
    *trieNode = NULL;
}
*/