=head1 NAME

Crypt::Eksblowfish::Family - Eksblowfish cipher family

=head1 SYNOPSIS

	use Crypt::Eksblowfish::Family;

	$family = Crypt::Eksblowfish::Family->new_family(8, $salt);

	$cost = $family->cost;
	$salt = $family->salt;
	$block_size = $family->blocksize;
	$key_size = $family->keysize;
	$cipher = $family->new($key);

=head1 DESCRIPTION

An object of this class represents an Eksblowfish cipher family.
It contains the family parameters (cost and salt), and if combined
with a key it yields an encryption function.  See L<Crypt::Eksblowfish>
for discussion of the Eksblowfish algorithm.

It is intended that an object of this class can be used as the "-cipher"
parameter to C<Crypt::CBC> and similar systems.  Normally that parameter
is the name of a class, such as "Crypt::Blowfish", where the class
implements a block cipher algorithm.  The class provides a C<new>
constructor that accepts a key.  In the case of Eksblowfish, the key
alone is not sufficient.  An Eksblowfish family fills the role of block
cipher algorithm.  Therefore a family object is used in place of a class
name, and it is the family object the provides the C<new> constructor.

=cut

package Crypt::Eksblowfish::Family;

use warnings;
use strict;

use Carp qw(croak);
use Crypt::Eksblowfish;

our $VERSION = "0.001";

=head1 CONSTRUCTOR

=over

=item Crypt::Eksblowfish::Family->new_family(COST, SALT)

Creates and returns an object representing the Eksblowfish cipher family
specified by the parameters.  The SALT is a family key, and must be
exactly 16 bytes.  COST is an integer parameter controlling the expense of
keying: the number of operations in key setup is proportional to 2^COST.

=cut

sub new_family($$$) {
	my($class, $cost, $salt) = @_;
	return bless({ cost => $cost, salt => $salt }, $class);
}

=back

=head1 METHODS

=over

=item $family->cost

Extracts and returns the cost parameter.

=cut

sub cost($) { $_[0]->{cost} }

=item $family->salt

Extracts and returns the salt parameter.

=cut

sub salt($) { $_[0]->{salt} }

=item $family->blocksize

Returns 8, indicating the Eksblowfish block size of 8 bytes.

=cut

sub blocksize($) { 8 }

=item $family->keysize

Returns 0, indicating that the key size is variable.  This situation is
handled specially by C<Crypt::CBC>.

=cut

sub keysize($) { 0 }

=item $family->new(KEY)

Performs key setup on a new instance of the Eksblowfish algorithm,
returning the keyed state.  The KEY may be any length from 1 byte to 72
bytes inclusive.  The object returned is of class C<Crypt::Eksblowfish>;
see L<Crypt::Eksblowfish> for the encryption and decryption methods.

Note that this method is called on a family object, not on the class
C<Crypt::Eksblowfish::Family>.

=cut

sub new($$) {
	my($self, $key) = @_;
	croak "Crypt::Eksblowfish::Family::new is not a class method ".
			"(perhaps you want new_family instead)"
		if ref($self) eq "";
	return Crypt::Eksblowfish->new($self->{cost}, $self->{salt}, $key);
}

=item $family->encrypt

This method nominally exists, to satisfy C<Crypt::CBC>.  It can't really
be used: it doesn't make any sense.

=cut

sub encrypt { croak "Crypt::Eksblowfish::Family::encrypt called" }

=back

=head1 SEE ALSO

L<Crypt::CBC>,
L<Crypt::Eksblowfish>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
