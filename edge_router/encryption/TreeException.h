// ********************************************************
// Header file TreeException.h for the ADT binary tree.
// ********************************************************
#include <stdexcept>
#include <string>
using namespace std;

class TreeException: public logic_error
{
public:
  TreeException(const string & message = "")
    : logic_error(message.c_str())
  { }
};  // end TreeException
