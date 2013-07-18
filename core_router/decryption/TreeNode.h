// same as TreeNode519.h

#include <string>
using namespace std;

typedef int TreeItemType;

class TreeNode             // node in the tree
{
private:
  TreeNode() {};
  TreeNode(const TreeItemType& nodeItem,
	   TreeNode *left = NULL,
	   TreeNode *right = NULL):
    item(nodeItem),leftChildPtr(left),
    rightChildPtr(right) {}
  TreeItemType item;        // data portion
  TreeNode *leftChildPtr;   // pointer to left child
  TreeNode *rightChildPtr;  // pointer to right child
  friend class anon_tree;   // Anonymization Class
};  // end TreeNode class
