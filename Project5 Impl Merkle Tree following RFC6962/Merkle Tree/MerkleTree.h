#pragma once
#include <iostream>
#include <stdlib.h>
#include <string>
#include <list>
#include <sstream>
#include <iomanip>
#include <vector>
#include <math.h>
#include <openssl/evp.h>
using namespace std;

typedef struct Node
{
    std::string data;
    std::string hashvalue;
    int ID;
    struct Node* left;
    struct Node* right;
    struct Node* parent;
} Node;
class MerkleTree {
private:
    Node* root;
    int blockNo, levels;
    const int HASHSIZE = 2 * EVP_MD_size(EVP_sha256());
public:
    MerkleTree();

    string SM3(const std::string& strIn);
    bool generatr_tree(const string* datas, int size);
    bool insert(string data);
    string ProveBlock(int n);
    Node* create_node(const string& data, const string& hashvalue, int ID);
    Node* merge_nodes(Node* left_child, Node* right_child);
    string GetRootHash();
    Node* getRoot() { return this->root; }

};



