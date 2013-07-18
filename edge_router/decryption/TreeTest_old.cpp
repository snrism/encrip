#include "BinaryTree.h"  // binary tree operations
#include <iostream>
#include <time.h>
#include <stdlib.h>
//#include <math.h>

using namespace std;
//const int TREE_SIZE = pow(2,24);


//Print the Tree in console
void display(TreeItemType& anItem) {
  cout << anItem << endl;
}

BinaryTree getTree()
{
	int n=0;
	BinaryTree tree;
	tree.setRootData((rand()%2));
	if(n<2)
	{
	  tree.attachLeftSubtree(getTree());
	  tree.attachRightSubtree(getTree());
		
	}
  	n++;
	return tree;
}

BinaryTree getLeftTree()
{
	BinaryTree tree;
	// build the tree in Figure 10-10
	tree.setRootData((rand()%2));
	  tree.attachLeft((rand()%2));
	  tree.attachRight((rand()%2));
	return tree;
}

int main() {

 // BinaryTree tree1, tree2, left; // empty trees
  BinaryTree leftTree,rightTree;    // tree with only a root 70
  srand(time(NULL));
  leftTree = getTree();
  rightTree = getTree();

  BinaryTree binTree((rand()%2),leftTree,rightTree);

 /* cout << "Inorder Traversal - tree" << endl;
  binTree.inorderTraverse(display);
  cout << endl << "Inorder Traversal - left subtree" << endl;
  binTree.getLeftSubtree().inorderTraverse(display);
  cout << endl << "Inorder Traversal - right subtree" << endl;
  binTree.getRightSubtree().inorderTraverse(display);
*/
 

  return 0;
}  // end main
