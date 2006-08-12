=head1 NAME

Crypt::Eksblowfish - the Eksblowfish block cipher

=head1 SYNOPSIS

	use Crypt::Eksblowfish;

	$block_size = Crypt::Eksblowfish->blocksize;

	$cipher = Crypt::Eksblowfish->new(8, $salt, $key);

	$block_size = $cipher->blocksize;
	$ciphertext = $cipher->encrypt($plaintext);
	$plaintext = $cipher->decrypt($ciphertext);

=head1 DESCRIPTION

An object of this type encapsulates a keyed instance of the Eksblowfish
block cipher, ready to encrypt and decrypt.

Eksblowfish is a variant of the Blowfish cipher, modified to make the
key setup very expensive.  ("Eks" stands for "expensive key schedule".)
This doesn't make it significantly cryptographically stronger,
but is intended to hinder brute-force attacks.  It also makes it
unsuitable for any application requiring key agility.  It was designed
by Niels Provos and David Mazieres for password hashing in OpenBSD.
See L<Crypt::Eksblowfish::Bcrypt> for the hash algorithm.

Eksblowfish is a parameterised (family-keyed) cipher.  It takes a cost
parameter that controls how expensive the key scheduling is.  It also
takes a family key, known as the "salt".  Cost and salt parameters
together define a cipher family.  Within each family, a key determines an
encryption function in the usual way.  See L<Crypt::Eksblowfish::Family>
for a way to encapsulate an Eksblowfish cipher family.

=cut

package Crypt::Eksblowfish;

use warnings;
use strict;

use XSLoader;

our $VERSION = "0.001";

XSLoader::load(__PACKAGE__, $VERSION);

=head1 CONSTRUCTOR

=over

=item Crypt::Eksblowfish->new(COST, SALT, KEY)

Performs key setup on a new instance of the Eksblowfish algorithm,
returning the keyed state.  The KEY may be any length from 1 byte to 72
bytes inclusive.  The SALT is a family key, and must be exactly 16 bytes.
COST is an integer parameter controlling the expense of keying: the
number of operations in key setup is proportional to 2^COST.  All three
parameters influence all the subkeys; changing any of them produces a
different encryption function.

Due to the mandatory family-keying parameters (COST and SALT), this
constructor does not match the interface expected by C<Crypt::CBC>.  To
use Eksblowfish with C<Crypt::CBC> it is necessary to have an object that
encapsulates a cipher family and provides a constructor that takes only a
key argument.  That facility is supplied by C<Crypt::Eksblowfish::Family>.

=cut

sub new($$$$) {
	my($class, $cost, $salt, $key) = @_;
	my $ks = _setup_keyschedule($cost, $salt, $key);
	return bless(\$ks, $class);
}

=back

=head1 METHODS

=over

=item Crypt::Eksblowfish->blocksize

=item $cipher->blocksize

Returns 8, indicating the Eksblowfish block size of 8 bytes.  This method
may be called on either the class or an instance.

=cut

sub blocksize($) { 8 }

=item $cipher->encrypt(PLAINTEXT)

PLAINTEXT must be exactly eight bytes.  The block is encrypted, and the
ciphertext is returned.

=cut

sub encrypt($$) { _encrypt_block(${$_[0]}, $_[1]) }

=item $cipher->decrypt(CIPHERTEXT)

CIPHERTEXT must be exactly eight bytes.  The block is decrypted, and
the plaintext is returned.

=cut

sub decrypt($$) { _decrypt_block(${$_[0]}, $_[1]) }

=back

=head1 SEE ALSO

L<Crypt::Blowfish>,
L<Crypt::Eksblowfish::Bcrypt>,
L<Crypt::Eksblowfish::Family>,
L<http://www.usenix.org/events/usenix99/provos/provos_html/node4.html>

=head1 AUTHOR

Eksblowfish guts originally by Solar Designer (solar at openwall.com).

Modifications and Perl interface by Andrew Main (Zefram)
<zefram@fysh.org>.

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

The original Eksblowfish code (in the form of crypt()) from which
this module is derived is in the public domain.  It may be found at
L<http://www.openwall.com/crypt/>.

=cut

1;
