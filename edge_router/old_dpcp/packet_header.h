struct setup_credhdr {
        unsigned int src;
        unsigned int dest;
        unsigned short int nexthdr;
        unsigned short int   request:1;
        unsigned short   challenge:1;
        unsigned short int response:1;
        unsigned short int credentials:1;
        unsigned long int nonce;
        unsigned short int Cindex[4];
        unsigned char Bfilter[16];
};

