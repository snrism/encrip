/*
 *  anon_tree.cpp
 *  Anonymzation Tree Data Structure 
 *
 *  Created by SRIRAM NATARAJAN on 11/13/11.
 *  Copyright 2011 __UMass_Amherst__. All rights reserved.
 *
 */
#include "anon_tree.h"      // header file
#include <cstddef>  // definition of NULL
#include <cassert>  // for assert()
#include <bitset>
#include <iostream>

anon_tree::anon_tree() : root(NULL)
{
}  // end default constructor

anon_tree::anon_tree(const TreeItemType& rootItem)
{
  root = new TreeNode(rootItem, NULL, NULL);
}  // end constructor

anon_tree::anon_tree(const TreeItemType& rootItem,
		       anon_tree& leftTree,
		       anon_tree& rightTree)
{
  root = new TreeNode(rootItem, NULL, NULL);
  
  attachLeftSubtree(leftTree);
  attachRightSubtree(rightTree);
}  // end constructor

anon_tree::anon_tree(const anon_tree& tree)
{
  copyTree(tree.root, root);
}  // end copy constructor

anon_tree::anon_tree(TreeNode *nodePtr):
  root(nodePtr)
{
}  // end protected constructor

anon_tree::~anon_tree()
{
  destroyTree(root);
}  // end destructor

bool anon_tree::isEmpty() const
{
  return (root == NULL);
}  // end isEmpty

TreeItemType anon_tree::getRootData() const
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  return root->item;
}  // end getRootData

void anon_tree::setRootData(const TreeItemType& newItem)
{
  if (!isEmpty())
    root->item = newItem;
  else {
    root = new TreeNode(newItem, NULL, NULL);
  }  // end if
}  // end setRootData

void anon_tree::attachLeft(const TreeItemType& newItem)
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  else if (root->leftChildPtr != NULL)
    throw TreeException("TreeException: Cannot overwrite left subtree");
  else  { // Assertion: nonempty tree; no left child
    root->leftChildPtr = new TreeNode(newItem, NULL, NULL);
  }  // end if
}  // end attachLeft

void anon_tree::attachRight(const TreeItemType& newItem)
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  else if (root->rightChildPtr != NULL)
    throw TreeException("TreeException: Cannot overwrite right subtree");
  else { // Assertion: nonempty tree; no right child
    root->rightChildPtr = new TreeNode(newItem, NULL, NULL);
  }  // end if
}  // end attachRight

void anon_tree::attachLeftSubtree(anon_tree& leftTree)
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  else if (root->leftChildPtr != NULL)
    throw TreeException("TreeException: Cannot overwrite left subtree");
  else { // Assertion: nonempty tree; no left child
    root->leftChildPtr = leftTree.root;
    leftTree.root = NULL;
  }
}  // end attachLeftSubtree

void anon_tree::attachRightSubtree(anon_tree& rightTree)
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  else if (root->rightChildPtr != NULL)
    throw TreeException("TreeException: Cannot overwrite right subtree");
  else { // Assertion: nonempty tree; no right child
    root->rightChildPtr = rightTree.root;
    rightTree.root = NULL;
  }  // end if
}  // end attachRightSubtree

void anon_tree::detachLeftSubtree(anon_tree& leftTree)
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  else {
    leftTree = anon_tree(root->leftChildPtr);
    root->leftChildPtr = NULL;
  }  // end if
}  // end detachLeftSubtree

void anon_tree::detachRightSubtree(anon_tree& rightTree)
  throw(TreeException)
{
  if (isEmpty())
    throw TreeException("TreeException: Empty tree");
  else {
    rightTree = anon_tree(root->rightChildPtr);
    root->rightChildPtr = NULL;
  }  // end if
}  // end detachRightSubtree

anon_tree anon_tree::getLeftSubtree() const
{
  TreeNode *subTreePtr;
  
  if (isEmpty())
    return anon_tree();
  else {
    copyTree(root->leftChildPtr, subTreePtr);
    return anon_tree(subTreePtr);
  }  // end if
}  // end getLeftSubtree

anon_tree anon_tree::getRightSubtree() const
{
  TreeNode *subTreePtr;
  
  if (isEmpty())
    return anon_tree();
  else { 
    copyTree(root->rightChildPtr, subTreePtr);
    return anon_tree(subTreePtr);
  }  // end if
}  // end getRightSubtree

void anon_tree::preorderTraverse(FunctionType visit)
{
  preorder(root, visit);
}  // end preorderTraverse

void anon_tree::inorderTraverse(FunctionType visit)
{
  inorder(root, visit);
}  // end inorderTraverse

void anon_tree::postorderTraverse(FunctionType visit)
{
  postorder(root, visit);
}  // end postorderTraverse

/* lookupTree in Level 1 */

bitset<1> anon_tree::lookup_l1_Tree(bitset<1> key)
{
  return lookup_l1(root, key);
} 

bitset<2> anon_tree::lookup_l1_Tree(bitset<2> key)
{
  return lookup_l1(root, key);
} 

bitset<3> anon_tree::lookup_l1_Tree(bitset<3> key)
{
  return lookup_l1(root, key);
} 

bitset<4> anon_tree::lookup_l1_Tree(bitset<4> key)
{
  return lookup_l1(root, key);
} 

bitset<5> anon_tree::lookup_l1_Tree(bitset<5> key)
{
  return lookup_l1(root, key);
} 

bitset<6> anon_tree::lookup_l1_Tree(bitset<6> key)
{
  return lookup_l1(root, key);
} 

bitset<7> anon_tree::lookup_l1_Tree(bitset<7> key)
{
  return lookup_l1(root, key);
} 

bitset<8> anon_tree::lookup_l1_Tree(bitset<8> key)
{
  return lookup_l1(root, key);
} 

bitset<9> anon_tree::lookup_l1_Tree(bitset<9> key)
{
  return lookup_l1(root, key);
} 

bitset<10> anon_tree::lookup_l1_Tree(bitset<10> key)
{
  return lookup_l1(root, key);
} 

bitset<11> anon_tree::lookup_l1_Tree(bitset<11> key)
{
  return lookup_l1(root, key);
} 

bitset<12> anon_tree::lookup_l1_Tree(bitset<12> key)
{
  return lookup_l1(root, key);
} 

bitset<13> anon_tree::lookup_l1_Tree(bitset<13> key)
{
  return lookup_l1(root, key);
} 

bitset<14> anon_tree::lookup_l1_Tree(bitset<14> key)
{
  return lookup_l1(root, key);
} 

bitset<15> anon_tree::lookup_l1_Tree(bitset<15> key)
{
  return lookup_l1(root, key);
} 

bitset<16> anon_tree::lookup_l1_Tree(bitset<16> key)
{
  return lookup_l1(root, key);
} 

bitset<17> anon_tree::lookup_l1_Tree(bitset<17> key)
{
  return lookup_l1(root, key);
} // end lookupTree in Level 1

/* lookupTree in Level 2 */

bitset<1> anon_tree::lookup_l2_Tree(bitset<1> key)
{
  return lookup_l2(root, key);
}

bitset<2> anon_tree::lookup_l2_Tree(bitset<2> key)
{
  return lookup_l2(root, key);
}

bitset<3> anon_tree::lookup_l2_Tree(bitset<3> key)
{
  return lookup_l2(root, key);
}

bitset<4> anon_tree::lookup_l2_Tree(bitset<4> key)
{
  return lookup_l2(root, key);
}

bitset<5> anon_tree::lookup_l2_Tree(bitset<5> key)
{
  return lookup_l2(root, key);
}

bitset<6> anon_tree::lookup_l2_Tree(bitset<6> key)
{
  return lookup_l2(root, key);
}

bitset<7> anon_tree::lookup_l2_Tree(bitset<7> key)
{
  return lookup_l2(root, key);
}

bitset<8> anon_tree::lookup_l2_Tree(bitset<8> key)
{
  return lookup_l2(root, key);
} // end lookupTree in Level 2

anon_tree& anon_tree::operator=(const anon_tree& rhs)
{
  if (this != &rhs) {
    destroyTree(root);  // deallocate left-hand side
    copyTree(rhs.root, root);  // copy right-hand side
  }  // end if
  return *this;
}  // end operator=

void anon_tree::copyTree(TreeNode *treePtr,
			  TreeNode *& newTreePtr) const
{
  // preorder traversal
  if (treePtr != NULL) {
    // copy node
    newTreePtr = new TreeNode(treePtr->item, NULL, NULL);
    copyTree(treePtr->leftChildPtr, newTreePtr->leftChildPtr);
    copyTree(treePtr->rightChildPtr, newTreePtr->rightChildPtr);
  }
  else
    newTreePtr = NULL;  // copy empty tree
}  // end copyTree

void anon_tree::destroyTree(TreeNode *& treePtr)
{
  // postorder traversal
  if (treePtr != NULL) {
    destroyTree(treePtr->leftChildPtr);
    destroyTree(treePtr->rightChildPtr);
    delete treePtr;
    treePtr = NULL;
  }  // end if
}  // end destroyTree

TreeNode *anon_tree::rootPtr() const
{
  return root;
}  // end rootPtr

void anon_tree::setRootPtr(TreeNode *newRoot)
{
  root = newRoot;
}  // end setRoot

void anon_tree::getChildPtrs(TreeNode *nodePtr,
			      TreeNode *& leftPtr,
			      TreeNode *& rightPtr) const
{
  leftPtr = nodePtr->leftChildPtr;
  rightPtr = nodePtr->rightChildPtr;
}  // end getChildPtrs

void anon_tree::setChildPtrs(TreeNode *nodePtr,
			      TreeNode *leftPtr,
			      TreeNode *rightPtr)
{
  nodePtr->leftChildPtr = leftPtr;
  nodePtr->rightChildPtr = rightPtr;
}  // end setChildPtrs

void anon_tree::preorder(TreeNode *treePtr,
			  FunctionType visit)
{
  if (treePtr != NULL) {
    visit(treePtr->item);
    preorder(treePtr->leftChildPtr, visit);
    preorder(treePtr->rightChildPtr, visit);
  } // end if
}  // end preorder

void anon_tree::inorder(TreeNode *treePtr,
			 FunctionType visit)
{
  if (treePtr != NULL) {
    inorder(treePtr->leftChildPtr, visit);
    visit(treePtr->item);
    inorder(treePtr->rightChildPtr, visit);
  } // end if
}  // end inorder

void anon_tree::postorder(TreeNode *treePtr,
			   FunctionType visit)
{
  if (treePtr != NULL) {
    postorder(treePtr->leftChildPtr, visit);
    postorder(treePtr->rightChildPtr, visit);
    visit(treePtr->item);
  } // end if
}  // end postorder

/* Level 1 Lookup Functions */

// lookup level 1 height 1
bitset<1> anon_tree::lookup_l1(TreeNode *treePtr,bitset<1> key)
{
int node[1]; bitset<1>value;
  if (treePtr !=NULL){
	if(treePtr->leftChildPtr->item==key[0])
		{
			node[0] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[0])
		{
			node[0] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
	}
	value.set(0,node[0]);
	return value;
} 

// lookup level 1 height 2
bitset<2> anon_tree::lookup_l1(TreeNode *treePtr,bitset<2> key)
{
int node[2]; int i=1; bitset<2>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<2;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 3
bitset<3> anon_tree::lookup_l1(TreeNode *treePtr,bitset<3> key)
{
int node[3]; int i=2; bitset<3>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<3;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 4
bitset<4> anon_tree::lookup_l1(TreeNode *treePtr,bitset<4> key)
{
int node[4]; int i=3; bitset<4>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<4;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 5
bitset<5> anon_tree::lookup_l1(TreeNode *treePtr,bitset<5> key)
{
int node[5]; int i=4; bitset<5>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}  
   }
	for(int i=0;i<5;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 6
bitset<6> anon_tree::lookup_l1(TreeNode *treePtr,bitset<6> key)
{
int node[6]; int i=5; bitset<6>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<6;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 7
bitset<7> anon_tree::lookup_l1(TreeNode *treePtr,bitset<7> key)
{
int node[7]; int i=6; bitset<7>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}    
   }
	for(int i=0;i<7;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 8
bitset<8> anon_tree::lookup_l1(TreeNode *treePtr,bitset<8> key)
{
int node[8]; int i=7; bitset<8>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	} 
   }
	for(int i=0;i<8;i++)
		value.set(i,node[i]);
	
	return value;
}

// lookup level 1 height 9
bitset<9> anon_tree::lookup_l1(TreeNode *treePtr,bitset<9> key)
{
int node[9]; int i=8; bitset<9>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}  
   }
	for(int i=0;i<9;i++)
		value.set(i,node[i]);
	
	return value;
}

// lookup level 1 height 10
bitset<10> anon_tree::lookup_l1(TreeNode *treePtr,bitset<10> key)
{
int node[10]; int i=9; bitset<10>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<10;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 11
bitset<11> anon_tree::lookup_l1(TreeNode *treePtr,bitset<11> key)
{
int node[11]; int i=10; bitset<11>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<11;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 12
bitset<12> anon_tree::lookup_l1(TreeNode *treePtr,bitset<12> key)
{
int node[12]; int i=11; bitset<12>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}    
   }
	for(int i=0;i<12;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 13
bitset<13> anon_tree::lookup_l1(TreeNode *treePtr,bitset<13> key)
{
int node[13]; int i=12; bitset<13>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<13;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 14
bitset<14> anon_tree::lookup_l1(TreeNode *treePtr,bitset<14> key)
{
int node[14]; int i=13; bitset<14>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<14;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 15
bitset<15> anon_tree::lookup_l1(TreeNode *treePtr,bitset<15> key)
{
int node[15]; int i=14; bitset<15>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}    
   }
	for(int i=0;i<15;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 1 height 16
bitset<16> anon_tree::lookup_l1(TreeNode *treePtr,bitset<16> key)
{
int node[16]; int i=15; bitset<16>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<16;i++)
		value.set(i,node[i]);
	
	return value;
}

// lookup level 1 height 17
bitset<17> anon_tree::lookup_l1(TreeNode *treePtr,bitset<17> key)
{
int node[17]; int i=16; bitset<17>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}    
   }
	for(int i=0;i<17;i++)
		value.set(i,node[i]);
	
	return value;
} // end lookup level 1

/* Level 2 Lookup Functions */

// lookup level 2 height 1
bitset<1> anon_tree::lookup_l2(TreeNode *treePtr,bitset<1> key)
{
int node[1]; bitset<1>value;
  if (treePtr !=NULL){
	if(treePtr->leftChildPtr->item==key[0])
		{
			node[0] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[0])
		{
			node[0] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
	}
	value.set(0,node[0]);
	return value;
} 

// lookup level 2 height 2
bitset<2> anon_tree::lookup_l2(TreeNode *treePtr,bitset<2> key)
{
int node[2]; int i=1; bitset<2>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<2;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 2 height 3
bitset<3> anon_tree::lookup_l2(TreeNode *treePtr,bitset<3> key)
{
int node[3]; int i=2; bitset<3>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<3;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 2 height 4
bitset<4> anon_tree::lookup_l2(TreeNode *treePtr,bitset<4> key)
{
int node[4]; int i=3; bitset<4>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}   
   }
	for(int i=0;i<4;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 2 height 5
bitset<5> anon_tree::lookup_l2(TreeNode *treePtr,bitset<5> key)
{
int node[5]; int i=4; bitset<5>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}    
   }
	for(int i=0;i<5;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 2 height 6
bitset<6> anon_tree::lookup_l2(TreeNode *treePtr,bitset<6> key)
{
int node[6]; int i=5; bitset<6>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}  
   }
	for(int i=0;i<6;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 2 height 7
bitset<7> anon_tree::lookup_l2(TreeNode *treePtr,bitset<7> key)
{
int node[7]; int i=6; bitset<7>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}  
   }
	for(int i=0;i<7;i++)
		value.set(i,node[i]);
	
	return value;
} 

// lookup level 2 height 8
bitset<8> anon_tree::lookup_l2(TreeNode *treePtr,bitset<8> key)
{
int node[8]; int i=7; bitset<8>value;

  if (treePtr !=NULL){
	while(i>=0){
	if(treePtr->leftChildPtr->item==key[i])
		{
			node[i] = 0;			
			treePtr = treePtr->leftChildPtr;			
			
		}
	else if(treePtr->rightChildPtr->item==key[i])
		{
			node[i] = 1;		
			treePtr = treePtr->rightChildPtr;
		}
		i--;
	}    
   }
	for(int i=0;i<8;i++)
		value.set(i,node[i]);
	
	return value;
} 
// End of implementation file.
