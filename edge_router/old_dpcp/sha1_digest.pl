#! /usr/bin/perl

use Math::BigInt;
use Digest::SHA::PurePerl qw(hmac_sha1 hmac_sha1_hex hmac_sha256_base64);
use Digest::SHA1 qw(sha1);
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
#$data ="10.1.2.2 10.1.1.3 2000 2007 6";



local $/=undef;
open (FIVETUPLE,'fivetuple.txt') or die "Couldnt open file: $!";
binmode FIVETUPLE;
$data = <FIVETUPLE>;
#$datawithoutspaces =~ s/\s//g;
#$data =~ tr/|/ /;
#print "$data\n";
close (FIVETUPLE);



local $/=undef;
open (MYFILE, 'private.pem') or die "Couldnt open file: $!";
binmode MYFILE;
$key = <MYFILE>;
#print "$key\n";
close (MYFILE);



$digestk1 = hmac_sha1_hex($data, $key);
$digestk2 = hmac_sha1_hex($data, "hellorouter1");
$digestk3 = hmac_sha1_hex($data, "worldrouter1");
$digestk4 = hmac_sha1_hex($data, "credentialsrouter1");

#print "$digestk1\n";
#print "$digestk2\n";
#print "$digestk3\n";
#print "$digestk4\n";



#$text = "Hello";
#printf sha1($text);
#$digest = hmac_sha1_hex($data, $key);
#$digest_as_integer = Math::BigInt->new("0x$digest");

while (length($digestk1) % 4) {
               $digestk1 .= '=';
       }
#print "$digestk1\n";
#print "\n";
while (length($digestk2) % 4) {
                $digestk2 .= '=';
        }
#print "$digestk2\n";
#print "\n";

while (length($digestk3) % 4) {
                $digestk3 .= '=';
        }
#print "$digestk3\n";
#print "\n";

while (length($digestk4) % 4) {
                $digestk4 .= '=';
        }
#print "$digestk4\n";
#print "\n";


$digestk11 = substr $digestk1, 0, 7;
#print "$digestk11\n";
$binaryk1 = hex2bin($digestk11);
#printf "$binaryk1\n";

$digestk12 = substr $digestk2,0 , 7;
#print "$digestk12\n";
$binaryk2 = hex2bin($digestk12);
#printf "$binaryk2\n";

$digestk13 = substr $digestk3, 0, 7;
#print "$digestk13\n";
$binaryk3 = hex2bin($digestk13);
#printf "$binaryk3\n";

$digestk14 = substr $digestk4, 0, 7;
#print "$digestk14\n";
$binaryk4 = hex2bin($digestk14);
#printf "$binaryk4\n";


#Split the binary using substring function
open(INDEXFILE, '>>index.txt') or die "Couldnt open file index.txt: $!";

$index1 = substr $binaryk1, 0, 7;
#print "key1 is $index1 \n";
$key1 = bin2dec($index1);
#print "Index1 is $key1\t";

$index2 = substr $binaryk2, 0, 7;
#print "key2 is $index2 \n";
$key2 = bin2dec($index2);
#print "Index2 is $key2\t";

$index3 = substr $binaryk3, 0, 7;
#print "key3 is $index3 \n";
$key3 = bin2dec($index3);
#print "Index3 is $key3\t";

$index4 = substr $binaryk4, 0, 7;

#print "key4 is $index4 \n";
$key4 = bin2dec($index4);
#print "Index4 is $key4\n";




print INDEXFILE $data.";".$key1."|".$key2."|".$key3."|".$key4."\n";

close(INDEXFILE);

open(INDEX, '>Cindex.txt') or die "Couldnt open file Cindex.txt: $!";
print INDEX $key1."\t".$key2."\t".$key3."\t".$key4."\t";
close(INDEX);

#printf "binary = %16s\n",  hex2bin($digest1);

open(CACHE, '>>credential_cache.txt') or die "Couldnt open file credential_cache.txt: $!";
print CACHE $key1."\n".$key2."\n".$key3."\n".$key4."\n";
close(CACHE);


#splitting binary using array

#$binary = hex2bin($digest1);
#@binary_array = split(//,$binary);
#printf "$binary_array[0]\n";
#printf "$binary_array[27]\n";
#print "$digest_as_integer\n";



#Converts Hexadecimal to binary
sub hex2bin {
        $h = shift;
        $hlen = length($h);
        $blen = $hlen * 4;
        return unpack("B$blen", pack("H$hlen", $h));
}

#converts binary to decimal
sub bin2dec{
	return unpack ("N", pack("B32", substr("0" x 32 . shift, -32)));
}


