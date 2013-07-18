#include "BinaryTree.h"  // binary tree operations
#include <iostream>
using namespace std;

void display(TreeItemType& anItem) {
  cout << anItem << endl;
}

int main() {
  BinaryTree tree1, tree2, left; // empty trees
  BinaryTree tree3(70);    // tree with only a root 70

  // build the tree in Figure 10-10
  tree1.setRootData(40);
  tree1.attachLeft(30);
  tree1.attachRight(50);

  tree2.setRootData(20);
  tree2.attachLeft(10);
  tree2.attachRightSubtree(tree1);

  // tree in Fig 10-10
  BinaryTree binTree(60, tree2, tree3);

  cout << "Inorder Traversal - tree" << endl;
  binTree.inorderTraverse(display);
  cout << endl << "Inorder Traversal - left subtree" << endl;
  binTree.getLeftSubtree().inorderTraverse(display);
  binTree.detachLeftSubtree(left);
  cout << endl << "Inorder Traversal - detached left subtree" << endl;
  left.inorderTraverse(display);
  cout << endl << "Inorder Traversal - tree" << endl;
  binTree.inorderTraverse(display);
  return 0;
}  // end main
