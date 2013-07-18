#include<stdio.h>

int main()
{
system("sudo modprobe iptable_filter");
system("sudo modprobe ip_queue");
system("sudo iptables -A FORWARD -p TCP -j QUEUE");
//system("sudo iptables -A INPUT -p TCP -i eth2 -j QUEUE");
system("sudo iptables -L");
system("echo 12582912 > /proc/sys/net/core/rmem_default");
system("echo 12582912 > /proc/sys/net/core/rmem_max");
system("echo 12582912 > /proc/sys/net/core/wmem_default");
system("echo 12582912 > /proc/sys/net/core/wmem_max");

return 0;
}
