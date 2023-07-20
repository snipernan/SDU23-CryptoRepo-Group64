#include"MerkleTree.h"

MerkleTree::MerkleTree()
{
    levels = 0;
    blockNo = -1;
}

string MerkleTree::SM3(const std::string& strIn)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(ctx, strIn.c_str(), strIn.size());
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

Node* MerkleTree::create_node(const string& data, const string& hashvalue, int ID)
{
    Node* node = new Node;
    node->data = data;
    node->hashvalue = hashvalue;
    node->ID = ID;
    node->left = node->right = node->parent = nullptr;
    return node;
}

Node* MerkleTree::merge_nodes(Node* left_child, Node* right_child)
{
    Node* parent_node = create_node(left_child->data, SM3(left_child->hashvalue + right_child->hashvalue), -1);
    parent_node->left = left_child;
    parent_node->right = right_child;
    left_child->parent = right_child->parent = parent_node;
    return parent_node;
}

bool MerkleTree::generatr_tree(const string* datas, int size)
{
    vector<Node*> leaf_nodes, parent_nodes;
    Node* left_child = nullptr, * right_child = nullptr;
    // 创建叶子节点
    for (int index = 0; index < size; index++)

    {
        Node* leaf_node = create_node(datas[index], SM3(datas[index]), ++blockNo);
        leaf_nodes.push_back(leaf_node);
    }

    // 计算树的层数
    do
    {
        levels++;
    } while (pow(2, levels) <= blockNo);

    // 依次合并节点，直到只剩下根节点
    do
    {
        // 将上一轮合并的父节点放入 parent_nodes 中
        auto iter_parent = parent_nodes.begin();
        auto done_parent = parent_nodes.end();
        while (iter_parent != done_parent)
        {
            leaf_nodes.push_back(*iter_parent++);
        }
        parent_nodes.clear();

        // 依次取出两个叶子节点合并成一个父节点
        auto iter_leaf = leaf_nodes.begin();
        auto done_leaf = leaf_nodes.end();
        left_child = right_child = nullptr;
        while (iter_leaf != done_leaf)
        {
            if (!left_child)
                left_child = *iter_leaf++;
            else
            {
                right_child = *iter_leaf++;
                Node* parent_node = merge_nodes(left_child, right_child);
                parent_nodes.push_back(parent_node);
                left_child = right_child = nullptr;
            }
        }

        // 如果叶子节点个数是奇数，最后一个节点只有左孩子，右孩子为空节点
        if (left_child)
        {
            right_child = create_node("", "", -1);
            Node* parent_node = merge_nodes(left_child, right_child);
            parent_nodes.push_back(parent_node);
            left_child = right_child = nullptr;
        }

        leaf_nodes.clear();
    } while (parent_nodes.size() > 1);

    root = parent_nodes[0];
    return true;
}


bool MerkleTree::insert(string data) {
    if (data.empty()) {
        cout << "Error: Empty block!" << endl;
        return false;
    }
    blockNo++;

    // 创建新节点         
    Node* new_node = create_node(data, SM3(data), blockNo);

    if (!root) {
        // 树为空,新节点为根节点
        root = new_node;
    }
    else {
        Node* parent = root;

        // 找到合适的父节点
        while (parent->left || parent->right) {
            if (parent->left && parent->right) {
                // 选择较短的一侧
                parent = blockNo % 2 ? parent->right : parent->left;
            }
            else if (!parent->left) {
                parent->left = new_node;
                new_node->parent = parent;
                break;
            }
            else {
                parent->right = new_node;
                new_node->parent = parent;
                break;
            }
        }

        // 父节点为根节点时,创建新的根节点                 
        if (parent == root) {
            root = create_node("", "", -1);
            root->left = parent;
            root->right = new_node;
        }

        Node* current = new_node;
        while (current) {
            if (current->left && current->right) {
                current->hashvalue = SM3(current->left->hashvalue + current->right->hashvalue);
            }
            else {
                // 叶子节点的哈希值为数据的哈希值
                current->hashvalue = SM3(current->data);
            }
            current = current->parent;
        }

        // 更新根节点的哈希值
        root->hashvalue = SM3(root->left->hashvalue + root->right->hashvalue);


    }
    return true;
}

string MerkleTree::GetRootHash()
{
    return root ? root->hashvalue : "";
}

string MerkleTree::ProveBlock(int n)
{
    string proof = "";

    if (n > blockNo)
    {
        proof = "Error: Block number out of range!";
        return proof;
    }

    Node* node = root;
    int mask = 1 << (levels - 1);

    // 遍历证明路径，将每个节点的哈希值和相对位置存储在证明字符串中
    while (mask > 0)
    {
        if (n & mask)
        {
            if (node->right)
            {
                proof += "L: " + node->left->hashvalue + "\n";
                node = node->right;
            }
            else
            {
                proof = "Error: Block not found!";
                return proof;
            }
        }
        else
        {
            if (node->left)
            {
                proof += "R: " + node->right->hashvalue + "\n";
                node = node->left;
            }
            else
            {
                proof = "Error: Block not found!";
                return proof;
            }
        }
        mask >>= 1;
    }

    return proof;
}
int main() {
    MerkleTree tree;

    string datas[20] = { "84", "75", "41", "74", "42", "0", "16", "83", "63", "94", "80", "15", "90", "47", "39", "61", "21", "62", "99", "38" };
    if (tree.generatr_tree(datas, 20)) {
        cout << "Successfully constructed Merkle tree with initial 20 blocks" << endl;
    }

    if (tree.insert("sdu-ljm")) {
        cout << "Successfully inserted new block" << endl;
    }
    cout << "Current root hash after insertion: " << tree.GetRootHash() << endl;

    string proof = tree.ProveBlock(4);
    if (!proof.empty()) {
        cout << "Proof of inclusion for block 4:" << endl;
        cout << proof;
    }

    cout << endl << "Current root hash remains unchanged after inclusion proof:" << endl;
    cout << tree.GetRootHash() << endl;
}