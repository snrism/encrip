#include "BinaryTree.h"   // binary tree operations
#include "top_hashing.h"
#include <iostream>
#include <math.h>
#include <fstream>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

using namespace std;

void display(TreeItemType& anItem) {
  cout << anItem << endl;
}

void bubbleSort(int arr[], int n) {
      bool swapped = true;
      int j = 0;
      int tmp;
      while (swapped) {
            swapped = false;
            j++;
            for (int i = 0; i < n - j; i++) {
                  if (arr[i] > arr[i + 1]) {
                        tmp = arr[i];
                        arr[i] = arr[i + 1];
                        arr[i + 1] = tmp;
                        swapped = true;
                  }
            }
      }
}

int mainn() {

//top_hashing top ;
//top.generate_top_hash();

srand(time(NULL));
int arr[256];
for (int i=0;i<256;i++)
	{
		arr[i] = rand()%256;		
		cout << "Rand value is: " << arr[i] <<endl;
		
	}
bubbleSort(arr,256);
for (int i=0;i<256;i++)
	cout << "Sorted Array: " << arr[i] <<endl;
 
/*	int left_node=0,right_node=0;
	
	// Anon Tree number of levels
	int level = 8;
	int total_node = pow(2,level+1)-1;
	int node_variant = pow(2,level)-2;
	
	// Read Crypto Key Files 
	int encrypt_nodes[total_node];
	char encrypt_nodes_string[4];
	
	//ifstream efile("encrypt_key_level_2.txt",std::ios::in |std::ios::binary);
	FILE *efile;
	efile = fopen("encrypt_key_level_2.txt", "r");
	
	if (efile == NULL) perror ("Error opening file");
	else {
		total_node=0;		
		while (fgets (encrypt_nodes_string , sizeof (encrypt_nodes_string) , efile)!=NULL){
		
				//puts(encrypt_nodes_string);
		encrypt_nodes[total_node] = atoi(encrypt_nodes_string);
			//	cout << total_node << " \t " << encrypt_nodes_string<<endl;
		total_node++;
		}	
		}
	fclose(efile);
	
	srand(time(NULL));
	BinaryTree node[total_node];
	
	// Generating Tree nodes
	for (int i=0; i<pow(2,level+1)-1; i++) {
		node[i].setRootData(encrypt_nodes[i]);
	}
	
	//Attaching SubTree nodes
	for (int i=node_variant; i>=0; i--) {
		
		// Get left node
		left_node=((2*i)+1);
		// Get right node
		right_node=((2*i)+2);
		
		//Attaching left subtree
		node[i].attachLeftSubtree(node[left_node]);
		//Attaching right subtree
		node[i].attachRightSubtree(node[right_node]);
	}
		
	
//	cout << "Preorder Traversal - tree" << endl;
//	node[0].preorderTraverse(display);
//	cout << endl << "Inorder Traversal - left subtree" << endl;
//	node[0].getLeftSubtree().inorderTraverse(display);
	*/	
  return 0;
}  // end main
