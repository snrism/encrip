#!/usr/bin/perl 

use Convert::PEM;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use strict;

#my $encrypted_string1 = q(HIc9WK2xaiPkQ6SqqVEbboIFzIlm4wTwXixyKBAlhNr98/K7Pw6YTRRyIiL/RGeGiqyuOv6ytjxtwB35Qcp+CUIxv7C5/4UPtW0abRFvTmINmjNa1P0d4ONCEyMQnJigikNUYiIKbQb09pwLmj9Ha864y4AvCt5G1t4tToP9UjZp0Q/6MlsdHyVgJy3pbGZfYzaMxSbQASPXY330GspcSG38cfySeo+XAC3WGxaE1BudK7URUlpviakXqsuciAjO7mJIQerBVdlxlPbGKbTKHeKo+NgQgMceq3G1BsNF+lk916xa31Vz7J60hbua8sKz2DlznE3mfifLvsqgrZiRxg==);

open (MYFILE, 'encr.txt') or die "Couldn't open file encr.txt: $!";
my $encrypted_string = qq();
my $line;
my @ay;
foreach $line (<MYFILE>)
{
 chomp $line;
 push(@ay,$line);
}
my $encr_st ;
my $encr_st =  join("",@ay);
my $encrypted_string =$encr_st;

#print $encrypted_string."\n";
close (MYFILE);

my $private_key = 'private.pem';

my $password = 'kamlesh';

my $answer = decryptPrivate($private_key,$password,$encrypted_string),  "\n";
#print "RSA Decryption done\n";
print "The NONCE decrypted is $answer\n";

open (NONCERECV, ">noncereceived.txt") or die "Couldn't open noncereceived.txt: $!";
print NONCERECV $answer;
close (NONCERECV);
exit;

sub decryptPrivate {
  my ($private_key,$password,$string) = @_;
  my $key_string = readPrivateKey($private_key,$password);


  return(undef) unless ($key_string); # Decrypt failed.
  my $private = Crypt::OpenSSL::RSA->new_private_key($key_string) ||
  die "$!";

 $private->decrypt(decode_base64($string));
#$private->decrypt($string);
}


sub readPrivateKey {
  my ($file,$password) = @_;
  my $key_string;
  $key_string = decryptPEM($file,$password);
}

sub decryptPEM {
  my ($file,$password) = @_;

  my $pem = Convert::PEM->new(
 Name => 'RSA PRIVATE KEY',
                              ASN  => qq(
                  RSAPrivateKey SEQUENCE {
                      version INTEGER,
                      n INTEGER,
                      e INTEGER,
                      d INTEGER,
                      p INTEGER,
                      q INTEGER,
                      dp INTEGER,
                      dq INTEGER,
                      iqmp INTEGER
                  }
           ));

  my $pkey =
    $pem->read(Filename => $file, Password => $password);

  return(undef) unless ($pkey); # Decrypt failed.
  $pem->encode(Content => $pkey);
}


