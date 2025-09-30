package SSVC;

use feature ':5.10';
use strict;
use utf8;
use warnings;

use Carp ();

use SSVC::CISA ();

our $VERSION = '1.00';
$VERSION =~ tr/_//d;    ## no critic

my %METHODOLOGIES = (cisa => 'SSVC::CISA');

sub new {

    my ($class, %params) = @_;

    my $methodology = delete $params{methodology} || Carp::croak 'Missing methodology';

    unless (defined $METHODOLOGIES{$methodology}) {
        Carp::croak 'Unknown SSCV methodology';
    }

    my $methodology_class = $METHODOLOGIES{$methodology};

    return $methodology_class->new(%params);

}

sub from_vector_string {

    my ($class, $methodology, $vector_string) = @_;

    unless (defined $METHODOLOGIES{$methodology}) {
        Carp::croak 'Unknown SSCV methodology';
    }

    my $methodology_class = $METHODOLOGIES{$methodology};
    return SSVC::CISA->from_vector_string($vector_string);

}

1;


__END__
=head1 NAME

SSVC - Perl extension for SSVC (Stakeholder-Specific Vulnerability Categorization)

=head1 SYNOPSIS

  use SSVC;

  $ssvc = SSVC->new(
    methodology              => 'cisa',
    exploitation             => 'active',
    automatable              => 'yes',
    technical_impact         => 'partial',
    mission_prevalence       => 'mission',
    public_well_being_impact => 'irreversible',
  );

  # Get the decision
  say $ssvc->decision; # act

  # Parse SSVC vector string
  $ssvc = SSVC->from_vector_string('cisa', 'SSVCv2/E:A/A:Y/T:P/P:M/B:I/M:H/D:C/2025-01-01T00:00:00');

  # Convert the SSVC object in "vector string"
  say $ssvc; # SSVCv2/E:A/A:Y/T:P/P:M/B:I/M:H/D:C/2025-01-01T00:00:00

  # Get the decision point value
  say $ssvc->public_well_being_impact; # irreversible

  # Convert SSVC in JSON in according of SSVC JSON Schema
  $json = encode_json($ssvc);


=head1 DESCRIPTION

SSVC stands for A Stakeholder-Specific Vulnerability Categorization. It is a
methodology for prioritizing vulnerabilities based on the needs of the
stakeholders involved in the vulnerability management process. SSVC is designed
to be used by any stakeholder in the vulnerability management process, including
finders, vendors, coordinators, deployers, and others.

L<https://certcc.github.io/SSVC/>


=head2 METHODOLOGIES

=over

=item * L<SSVC::CISA>, CISA

=back


=head2 OBJECT-ORIENTED INTERFACE

=over

=item $ssvc = SSVC->new(%params)

Creates a new L<SSVC> instance using the provided pdecision points.

=item $ssvc = SSVC->from_vector_string($methodology, $vector_string);

Converts the given "vector string" to L<SSVC>. Croaks on error

=item $ssvc->TO_JSON

Helper method for JSON modules (L<JSON>, L<JSON::PP>, L<JSON::XS>, L<Mojo::JSON>, etc).

Convert the L<SSVC> object in JSON format.

    encode_json($ssvc);

=back

=head1 SEE ALSO

L<SSVC::CISA>

=over 4

=item [Carnegie Mellon University] SSVC: Stakeholder-Specific Vulnerability Categorization (L<https://certcc.github.io/SSVC/>)

=item [CISA] Stakeholder-Specific Vulnerability Categorization Guide (L<https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf>)

=back


=head1 SUPPORT

=head2 Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/giterlizzi/perl-SSVC/issues>.
You will be notified automatically of any progress on your issue.

=head2 Source Code

This is open source software.  The code repository is available for
public review and contribution under the terms of the license.

L<https://github.com/giterlizzi/perl-SSVC>

    git clone https://github.com/giterlizzi/perl-SSVC.git


=head1 AUTHOR

=over 4

=item * Giuseppe Di Terlizzi <gdt@cpan.org>

=back


=head1 LICENSE AND COPYRIGHT

This software is copyright (c) 2025 by Giuseppe Di Terlizzi.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
