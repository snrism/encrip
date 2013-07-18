#!/usr/bin/perl
#use strict;

#my $encrypted_string = q(iGCerhGUTyidWhR4e0Ojkb+3+OLWvC+Wuq0GipOVZ1SZ8q69OOWgwaYigaa32+PVVHb8ZkMRYjYFXbryz0//aflSqkEnxtffugj2zdoqifv9i1QbIvQspEyN0PODb0U7PhMor3wUAlmX9fc9EoJmgW1PRn6AOxh0UuNoHNvvXu5QJo3waN8lVUWmqsvg4Bc9DiYsBQDDeDk8QITy7lSByAN6ATvB+HWKfNQDIX8Y7uMBcDvmzXYP1MZOu9Pt5wAmZ15N6vP2H9bHk3xhZbVvthNmZb3ME2bE0THd2D6tv85GlrGyPp9yQrCksz4cM3cPpQd/8NCIYjJP3Yn4QVj8xg==);

open (MYFILE, 'encr.txt');
my $encrypted_string = <MYFILE>;
chomp $encrypted_string;
$a = 0;
foreach $line (<MYFILE>)
{
 chomp $line;
 push(@ay,$line);
 ++$a;	
}
$kam = "$ay[0]$ay[1]$ay[2]$ay[3]\n";
print "$kam\n";
print "A: $a\n";
#$encrypted_string =~ s/^\s*(.*)\s*\n+$//;
#print $encrypted_string;
close (MYFILE);

