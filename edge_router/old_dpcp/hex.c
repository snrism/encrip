int
hex2bin(char *hex, char *bin, int hex_len)
{
        register int i = 0, j = 0;

        if(hex_len == 0 || !hex)
                return -1;

        if(hex_len > 2 && hex[0] == '0' && hex[1] == 'x')
                i = 2;

        for( ; i < hex_len; i++, j += 4) {
                switch(tolower(hex[i])) {
		case '0': memmove(&bin[j], "0000", 4); break;
                        case '1': memmove(&bin[j], "0001", 4); break;
                        case '2': memmove(&bin[j], "0010", 4); break;
                        case '3': memmove(&bin[j], "0011", 4); break;
                        case '4': memmove(&bin[j], "0100", 4); break;
                        case '5': memmove(&bin[j], "0101", 4); break;
                        case '6': memmove(&bin[j], "0110", 4); break;
                        case '7': memmove(&bin[j], "0111", 4); break;
                        case '8': memmove(&bin[j], "1000", 4); break;
                        case '9': memmove(&bin[j], "1001", 4); break;
                        case 'a': memmove(&bin[j], "1010", 4); break;
                        case 'b': memmove(&bin[j], "1011", 4); break;
                        case 'c': memmove(&bin[j], "1100", 4); break;
                        case 'd': memmove(&bin[j], "1101", 4); break;
                        case 'e': memmove(&bin[j], "1110", 4); break;
                        case 'f': memmove(&bin[j], "1111", 4); break;
                        default:
                                return -1;        // invalid hex digit
                }
        }
        return 0;
}

int
main(int argc, char **argv)
{
        static char bin[64];

        if(argc != 2) {
                printf("Usage:  \nNumber can start with 0x.\n");
                exit(911);
        }

        if(hex2bin(argv[1], bin, strlen(argv[1])) == -1)
                printf("Partial binary string [%s]\nError: invalid hex digit recived quitting...\n", bin), exit(911);
        else
                printf("Binary string [%s]\n", bin);
        return 0;
}
