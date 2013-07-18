// ********************************************************
// Header file anon_tree.h for the ADT binary tree.
// ********************************************************
#include "TreeException.h"
#include "TreeNode.h" // contains definitions for TreeNode
                      // and TreeItemType
#include <bitset>

typedef void (*FunctionType)(TreeItemType& anItem);

class anon_tree
{
public:
  // constructors and destructor:
  anon_tree();
  anon_tree(const TreeItemType& rootItem);
  anon_tree(const TreeItemType& rootItem,
	     anon_tree& leftTree,
	     anon_tree& rightTree);
  anon_tree(const anon_tree& tree);
  virtual ~anon_tree();

  // binary tree operations:
  virtual bool isEmpty() const;

  virtual TreeItemType getRootData() const
    throw(TreeException);
  virtual void setRootData(const TreeItemType& newItem);

  virtual void attachLeft(const TreeItemType& newItem)
    throw(TreeException);
  virtual void attachRight(const TreeItemType& newItem)
    throw(TreeException);

  virtual void attachLeftSubtree(anon_tree& leftTree)
    throw(TreeException);
  virtual void attachRightSubtree(anon_tree& rightTree)
    throw(TreeException);

  virtual void detachLeftSubtree(anon_tree& leftTree)
    throw(TreeException);
  virtual void detachRightSubtree(anon_tree& rightTree)
    throw(TreeException);

  virtual anon_tree getLeftSubtree() const;
  virtual anon_tree getRightSubtree() const;

  virtual void preorderTraverse(FunctionType visit);
  virtual void inorderTraverse(FunctionType visit);
  virtual void postorderTraverse(FunctionType visit);
  virtual bitset<1> lookup_l1_Tree(bitset<1> key);
  virtual bitset<2> lookup_l1_Tree(bitset<2> key);
  virtual bitset<3> lookup_l1_Tree(bitset<3> key);
  virtual bitset<4> lookup_l1_Tree(bitset<4> key);
  virtual bitset<5> lookup_l1_Tree(bitset<5> key);
  virtual bitset<6> lookup_l1_Tree(bitset<6> key);
  virtual bitset<7> lookup_l1_Tree(bitset<7> key);
  virtual bitset<8> lookup_l1_Tree(bitset<8> key);
  virtual bitset<9> lookup_l1_Tree(bitset<9> key);
  virtual bitset<10> lookup_l1_Tree(bitset<10> key);
  virtual bitset<11> lookup_l1_Tree(bitset<11> key);
  virtual bitset<12> lookup_l1_Tree(bitset<12> key);
  virtual bitset<13> lookup_l1_Tree(bitset<13> key);
  virtual bitset<14> lookup_l1_Tree(bitset<14> key);
  virtual bitset<15> lookup_l1_Tree(bitset<15> key);
  virtual bitset<16> lookup_l1_Tree(bitset<16> key);
  virtual bitset<17> lookup_l1_Tree(bitset<17> key);
  virtual bitset<1> lookup_l2_Tree(bitset<1> key);
  virtual bitset<2> lookup_l2_Tree(bitset<2> key);
  virtual bitset<3> lookup_l2_Tree(bitset<3> key);
  virtual bitset<4> lookup_l2_Tree(bitset<4> key);
  virtual bitset<5> lookup_l2_Tree(bitset<5> key);
  virtual bitset<6> lookup_l2_Tree(bitset<6> key);
  virtual bitset<7> lookup_l2_Tree(bitset<7> key);
  virtual bitset<8> lookup_l2_Tree(bitset<8> key);

  // overloaded operator:
  virtual anon_tree& operator=(const anon_tree& rhs);

protected:
  anon_tree(TreeNode *nodePtr);  // constructor

  void copyTree(TreeNode *treePtr,
		TreeNode *& newTreePtr) const;
  // Copies the tree rooted at treePtr into a tree rooted
  // at newTreePtr. Throws TreeException if a copy of the
  // tree cannot be allocated.

  void destroyTree(TreeNode *& treePtr);
  // Deallocates memory for a tree.
  // The next two functions retrieve and set the value
  // of the private data member root.

  TreeNode *rootPtr() const;
  void setRootPtr(TreeNode *newRoot);

  // The next two functions retrieve and set the values
  // of the left and right child pointers of a tree node.
  void getChildPtrs(TreeNode *nodePtr,
		    TreeNode *& leftChildPtr,
		    TreeNode *& rightChildPtr) const;
  void setChildPtrs(TreeNode *nodePtr,
		    TreeNode *leftChildPtr,
		    TreeNode *rightChildPtr);

  void preorder(TreeNode *treePtr, FunctionType visit);
  void inorder(TreeNode *treePtr, FunctionType visit);
  void postorder(TreeNode *treePtr, FunctionType visit);
  bitset<1> lookup_l1(TreeNode *treePtr,bitset<1> key);
  bitset<2> lookup_l1(TreeNode *treePtr,bitset<2> key);
  bitset<3> lookup_l1(TreeNode *treePtr,bitset<3> key);
  bitset<4> lookup_l1(TreeNode *treePtr,bitset<4> key);
  bitset<5> lookup_l1(TreeNode *treePtr,bitset<5> key);
  bitset<6> lookup_l1(TreeNode *treePtr,bitset<6> key);
  bitset<7> lookup_l1(TreeNode *treePtr,bitset<7> key);
  bitset<8> lookup_l1(TreeNode *treePtr,bitset<8> key);
  bitset<9> lookup_l1(TreeNode *treePtr,bitset<9> key);
  bitset<10> lookup_l1(TreeNode *treePtr,bitset<10> key);
  bitset<11> lookup_l1(TreeNode *treePtr,bitset<11> key);
  bitset<12> lookup_l1(TreeNode *treePtr,bitset<12> key);
  bitset<13> lookup_l1(TreeNode *treePtr,bitset<13> key);
  bitset<14> lookup_l1(TreeNode *treePtr,bitset<14> key);
  bitset<15> lookup_l1(TreeNode *treePtr,bitset<15> key);
  bitset<16> lookup_l1(TreeNode *treePtr,bitset<16> key);
  bitset<17> lookup_l1(TreeNode *treePtr,bitset<17> key);
  bitset<1> lookup_l2(TreeNode *treePtr,bitset<1> key);
  bitset<2> lookup_l2(TreeNode *treePtr,bitset<2> key);
  bitset<3> lookup_l2(TreeNode *treePtr,bitset<3> key);
  bitset<4> lookup_l2(TreeNode *treePtr,bitset<4> key);
  bitset<5> lookup_l2(TreeNode *treePtr,bitset<5> key);
  bitset<6> lookup_l2(TreeNode *treePtr,bitset<6> key);
  bitset<7> lookup_l2(TreeNode *treePtr,bitset<7> key);
  bitset<8> lookup_l2(TreeNode *treePtr,bitset<8> key);

private:
  TreeNode *root;  // pointer to root of tree
};  // end class
// End of header file.

