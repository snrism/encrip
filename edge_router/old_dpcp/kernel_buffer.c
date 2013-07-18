#include <stdio.h>
int main()
{
system("echo 12582912 > /proc/sys/net/core/rmem_default");
system("echo 12582912 > /proc/sys/net/core/rmem_max");
system("echo 12582912 > /proc/sys/net/core/wmem_default");
system("echo 12582912 > /proc/sys/net/core/wmem_max");
 
return 0;
}


