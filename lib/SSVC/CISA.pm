package SSVC::CISA;

use feature ':5.10';
use strict;
use utf8;
use warnings;

use Time::Piece;
use Carp ();

use overload '""' => 'to_vector_string', fallback => 1;

use constant EXPLOITATION              => [qw(none poc active)];
use constant AUTOMATABLE               => [qw(yes no)];
use constant TECHNICAL_IMPACT          => [qw(partial total)];
use constant MISSION_PREVALENCE        => [qw(mission support essential)];
use constant PUBLIC_WELL_BEING_IMPACT  => [qw(minimal material irreversible)];
use constant MISSION_WELL_BEING_IMPACT => [qw(low medium high)];
use constant DECISION                  => [qw(track track* attend act)];

use constant DECISION_POINTS => (
    exploitation              => EXPLOITATION(),
    automatable               => AUTOMATABLE(),
    technical_impact          => TECHNICAL_IMPACT(),
    mission_prevalence        => MISSION_PREVALENCE(),
    public_well_being_impact  => PUBLIC_WELL_BEING_IMPACT(),
    mission_well_being_impact => MISSION_WELL_BEING_IMPACT(),
);

my $VECTOR_STRING_REGEX = qr{
    SSVCv2/
    E:(?<E>[NPA])/
    A:(?<A>[YN])/
    T:(?<T>[PT])/
    P:(?<P>[MSE])/
    B:(?<B>[MAI])/
    M:(?<M>[LMH])/
    D:(?<D>[TRAC])
}x;


#<<<
my %VECTOR = (
    exploitation => {
        name => 'E',
        c2l  => {N => 'none', P => 'poc', A => 'active'},
        l2c  => {none => 'N', poc => 'P', active => 'A'}
    },

    automatable => {
        name => 'A',
        c2l  => {Y => 'yes', N => 'no'},
        l2c  => {yes => 'Y', no => 'N'}},

    technical_impact => {
        name => 'T',
        c2l  => {P => 'partial', T => 'total'},
        l2c  => {partial => 'P', total => 'T'}},

    mission_prevalence => {
        name => 'P',
        c2l  => {M => 'mission', S => 'support', E => 'essential'},
        l2c  => {mission => 'M', support => 'S', essential => 'E'}
    },

    public_well_being_impact => {
        name => 'B',
        c2l  => {M => 'minimal', A => 'material', I => 'irreversible'},
        l2c  => {minimal => 'M', material => 'A', irreversible => 'I'}
    },

    mission_well_being_impact => {
        name => 'M',
        c2l  => {L => 'low', M => 'medium', H => 'high'},
        l2c  => {low => 'L', medium => 'M', high => 'H'}
    },

    decision => {
        name => 'D',
        c2l  => {T => 'track', R => 'track*', A => 'attend', C => 'act'},
        l2c  => {track => 'T', 'track*' => 'R',attend => 'A', act => 'C'}
    },
);
#>>>

# https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf (Figure 1 - Table 9)
my %DECISION_TREE = (
    NNPL => 'T',
    NNPM => 'T',
    NNPH => 'T',
    NNTL => 'T',
    NNTM => 'T',
    NNTH => 'R',
    NYPL => 'T',
    NYPM => 'T',
    NYPH => 'A',
    NYTL => 'T',
    NYTM => 'T',
    NYTH => 'A',
    PNPL => 'T',
    PNPM => 'T',
    PNPH => 'R',
    PNTL => 'T',
    PNTM => 'R',
    PNTH => 'A',
    PYPL => 'T',
    PYPM => 'T',
    PYPH => 'A',
    PYTL => 'T',
    PYTM => 'R',
    PYTH => 'A',
    ANPL => 'T',
    ANPM => 'T',
    ANPH => 'A',
    ANTL => 'T',
    ANTM => 'A',
    ANTH => 'C',
    AYPL => 'A',
    AYPM => 'A',
    AYPH => 'C',
    AYTL => 'A',
    AYTM => 'C',
    AYTH => 'C',
);

# https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf (Table 8)
my %PB_to_M = (

    # - | M | A | I
    # --|---|---|--
    # M | L | M | H
    # S | M | M | H
    # E | H | H | H

    # B = minimal   material  irreversible
    M => {M => 'L', A => 'M', I => 'H'},    # P = mission
    S => {M => 'M', A => 'M', I => 'H'},    # P = support
    E => {M => 'H', A => 'H', I => 'H'},    # P = essential

);

sub new {

    my ($class, %params) = @_;

    my %decision_points = _normalize(%params);
    my %vector          = _vector(%decision_points);

    unless ($vector{P} && $vector{B}) {
        Carp::croak "Cannot compute 'mission_well_being_impact'"
            . ": need 'mission_prevalence' and 'public_well_being_impact'";
    }

    my $computed_M = $PB_to_M{$vector{P}}->{$vector{B}};

    if ($vector{M} && $vector{M} ne $computed_M) {
        Carp::croak "Inconsistent 'mission_well_being_impact' (got: $vector{M}, expected: $computed_M)";
    }

    $vector{M} = $computed_M;


    unless ($vector{E} && $vector{A} && $vector{T} && $vector{M}) {
        Carp::croak "Cannot compute 'decision'"
            . ": need 'exploitation', 'automatable', 'technical_impact' and 'mission_well_being_impact'";
    }

    my $computed_D = $DECISION_TREE{join '', map { $vector{$_} } qw(E A T M)};

    if ($vector{D} && $vector{D} ne $computed_D) {
        Carp::croak "Inconsistent 'decision' (got: $vector{D}, expected: $computed_D)";
    }

    $vector{D} = $computed_D;


    my $self = {
        decision_points => \%decision_points,
        vector          => \%vector,
        decision        => $VECTOR{decision}->{c2l}->{$vector{D}}
    };

    return bless $self, $class;

}

sub from_vector_string {

    my ($class, $vector_string) = @_;

    if ($vector_string =~ /$VECTOR_STRING_REGEX/) {

        my %metrics = %+;

        my %decision_points = (
            exploitation              => $VECTOR{exploitation}->{c2l}->{$metrics{E}},
            automatable               => $VECTOR{automatable}->{c2l}->{$metrics{A}},
            technical_impact          => $VECTOR{technical_impact}->{c2l}->{$metrics{T}},
            mission_prevalence        => $VECTOR{mission_prevalence}->{c2l}->{$metrics{P}},
            public_well_being_impact  => $VECTOR{public_well_being_impact}->{c2l}->{$metrics{B}},
            mission_well_being_impact => $VECTOR{mission_well_being_impact}->{c2l}->{$metrics{M}},
            decision                  => $VECTOR{decision}->{c2l}->{$metrics{D}},
        );

        return __PACKAGE__->new(%decision_points);

    }

    Carp::croak "Malformed CISA SSVCv2 vector string";

}

sub _vector {

    my (%params) = @_;

    my %vector = ();

    for (keys %VECTOR) {
        next unless $params{$_};
        my $decision_point = $VECTOR{$_};
        $vector{$decision_point->{name}} = $decision_point->{l2c}->{$params{$_}};
    }

    return %vector;

}

sub _normalize {

    my %params = @_;

    my %checks = DECISION_POINTS;
    $checks{decision} = DECISION();

    my %normalized = ();

    foreach my $decision_point (keys %checks) {

        next unless defined $params{$decision_point};

        my @allowed = @{$checks{$decision_point}};

        unless (grep { lc $params{$decision_point} eq $_ } @allowed) {
            Carp::croak "Unknown value for '$decision_point' (allowed: " . join(', ', @allowed) . ")";
        }

        $normalized{$decision_point} = lc $params{$decision_point};
    }

    return %normalized;

}

sub decision_points { shift->{decision_points} }

sub exploitation              { shift->{decision_points}->{exploitation} }
sub automatable               { shift->{decision_points}->{automatable} }
sub technical_impact          { shift->{decision_points}->{technical_impact} }
sub mission_prevalence        { shift->{decision_points}->{mission_prevalence} }
sub public_well_being_impact  { shift->{decision_points}->{public_well_being_impact} }
sub mission_well_being_impact { shift->{decision_points}->{mission_well_being_impact} }
sub decision                  { shift->{decision} }

sub to_vector_string {

    my $self = shift;

    return join '/', 'SSVCv2',
        (map { join ':', $_, $self->{vector}->{$_} || Carp::croak 'Missing metric' } qw[E A T P B M D]),
        Time::Piece->new->datetime;

}

sub TO_JSON {

    my $self = shift;

    return {
        exploitation              => $self->exploitation,
        automatable               => $self->automatable,
        technical_impact          => $self->technical_impact,
        mission_prevalence        => $self->mission_prevalence,
        public_well_being_impact  => $self->public_well_being_impact,
        mission_well_being_impact => $self->mission_well_being_impact,
        decision                  => $self->decision,
    };

}

1;


__END__
=head1 NAME

SSVC::CISA - CISA SSVG (Stakeholder-Specific Vulnerability Categorization)

=head1 SYNOPSIS

  use SSVC::CISA;

  $ssvc = SSVC::CISA->new(
    exploitation             => 'active',
    automatable              => 'yes',
    technical_impact         => 'partial',
    mission_prevalence       => 'mission',
    public_well_being_impact => 'irreversible',
  );

  # Get the decision
  say $ssvc->decision; # act

  # Parse SSVC vector string
  $ssvc = SSVC->from_vector_string('SSVCv2/E:A/A:Y/T:P/P:M/B:I/M:H/D:C/2025-01-01T00:00:00');

  # Convert the SSVC object in "vector string"
  say $ssvc; # SSVCv2/E:A/A:Y/T:P/P:M/B:I/M:H/D:C/2025-01-01T00:00:00

  # Get the decision point value
  say $ssvc->public_well_being_impact; # irreversible

  # Convert SSVC in JSON in according of SSVC JSON Schema
  $json = encode_json($ssvc);


=head1 DESCRIPTION

The CISA Stakeholder-Specific Vulnerability Categorization (SSVC) is a customized
decision tree model that assists in prioritizing vulnerability response for the
United States government (USG), state, local, tribal, and territorial (SLTT)
governments; and critical infrastructure (CI) entities. This document serves as a
guide for evaluating vulnerabilities using the CISA SSVC decision tree. The goal
of SSVC is to assist in prioritizing the remediation of a vulnerability based 
on the impact exploitation would have to the particular organization(s). The four
SSVC scoring decisions, described in this guide, outline how CISA messages out
patching prioritization. Any individual or organization can use SSVC to enhance
their own vulnerability management practices.

L<https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf>


=head2 OBJECT-ORIENTED INTERFACE

=over

=item $ssvc = SSVC->new(%params)

Creates a new L<SSVC> instance using the provided pdecision points.


Parameters / Decision Points:

=over

=item * C<exploitation> (required)

=item * C<automatable> (required)

=item * C<technical_impact> (required)

=item * C<mission_prevalence> (required)

=item * C<public_well_being_impact> (required)

=item * C<mission_well_being_impact> (optional), Computed from "mission_prevalence" and "mission_prevalence"

=back

=item $ssvc->decision

The vulnerability scoring decision.

=over

=item * B<track>, The vulnerability does not require action at this time. The organization would
continue to track the vulnerability and reassess it if new information becomes
available. CISA recommends remediating Track vulnerabilities within standard
update timelines.

=item * B<track*>, The vulnerability contains specific characteristics that may require closer
monitoring for changes. CISA recommends remediating Track* vulnerabilities
within standard update timelines.

=item * B<attend>, The vulnerability requires attention from the organization's internal,
supervisory-level individuals. Necessary actions may include requesting
assistance or information about the vulnerability and may involve publishing a
notification, either internally and/or externally, about the vulnerability. CISA
recommends remediating Attend vulnerabilities sooner than standard update
timelines.

=item * B<act>, The vulnerability requires attention from the organization's internal,
supervisory-level and leadership-level individuals. Necessary actions include
requesting assistance or information about the vulnerability, as well as
publishing a notification either internally and/or externally. Typically, internal
groups would meet to determine the overall response and then execute agreed
upon actions. CISA recommends remediating Act vulnerabilities as soon as
possible.

=back

=item $ssvc = SSVC->from_vector_string($methodology, $vector_string);

Converts the given "vector string" to L<SSVC>. Croaks on error

=item $ssvc->TO_JSON

Helper method for JSON modules (L<JSON>, L<JSON::PP>, L<JSON::XS>, L<Mojo::JSON>, etc).

Convert the L<SSVC> object in JSON format.

    encode_json($ssvc);

=back

=head2 DECISION POINTS

=over

=item $ssvc->exploitation

(State of) Exploitation

Evidence of Active Exploitation of a Vulnerability

This measure determines the present state of exploitation of the vulnerability. It does not predict future exploitation or
measure feasibility or ease of adversary development of future exploit code; rather, it acknowledges available
information at time of analysis. As the current state of exploitation often changes over time, answers should be time-
stamped. Sources that can provide public reporting of active exploitation include the vendor's vulnerability
notification, the National Vulnerability Database (NVD) and links therein, bulletins from relevant information sharing
and analysis centers (ISACs), and reliable threat reports that list either the CVE-ID or common name of the
vulnerability.

=over

=item * B<none>, There is no evidence of active exploitation and no public proof of concept (PoC)
of how to exploit the vulnerability.

=item * Public B<poc>, One of the following is true: (1) Typical public PoC exists in sources such as
Metasploit or websites like ExploitDB; or (2) the vulnerability has a well-known
method of exploitation. Some examples of condition (2) are open-source web
proxies that serve as the PoC code for how to exploit any vulnerability in the vein
of improper validation of Transport Layer Security (TLS) certificates, and
Wireshark serving as a PoC for packet replay attacks on ethernet or Wi-Fi
networks.

=item * B<active>, Shared, observable, and reliable evidence that cyber threat actors have used the
exploit in the wild; the public reporting is from a credible source.

=back

=item $ssvc->automatable

Automatable

Automatable represents the ease and speed with which a cyber threat actor can cause exploitation events.
Automatable captures the answer to the question, "Can an attacker reliably automate, creating exploitation events for
this vulnerability?" Several factors influence whether an actor can rapidly cause many exploitation events. These
include attack complexity, the specific code an actor would need to write or configure themselves, and the usual
network deployment of the vulnerable system (i.e., the usual exposure of the system).

=over

=item * B<no>, Steps 1-4 of the kill chain-reconnaissance, weaponization, delivery, and
exploitation-cannot be reliably automated for this vulnerability. 1 Examples for
explanations of why each step may not be reliably automatable include: (1) the
vulnerable component is not searchable or enumerable on the network, (2)
weaponization may require human direction for each target, (3) delivery may
require channels that widely deployed network security configurations block, and
(4) exploitation may be frustrated by adequate exploit-prevention techniques
enabled by default (address space layout randomization [ASLR] is an example of
an exploit-prevention tool).

=item * B<yes>, Steps 1-4 of the of the kill chain can be reliably automated. If the vulnerability
allows unauthenticated remote code execution (RCE) or command injection, the
response is likely yes.

=back

=item $ssvc->technical_impact

Technical Impact

Technical Impact of Exploiting the Vulnerability

Technical impact is similar to the Common Vulnerability Scoring System (CVSS) base score's concept of "severity."
When evaluating technical impact, the definition of scope is particularly important. The decision point, "Total," is
relative to the affected component where the vulnerability resides. If a vulnerability discloses authentication or
authorization credentials to the system, this information disclosure should also be scored as "Total" if those
credentials give an adversary total control of the component.

=over

=item * B<partial>, One of the following is true: The exploit gives the threat actor limited control over,
or information exposure about, the behavior of the software that contains the
vulnerability; or the exploit gives the threat actor a low stochastic opportunity for
total control. In this context, "low" means that the attacker cannot reasonably
make enough attempts to overcome obstacles, either physical or security-based,
to achieve total control. A denial-of-service attack is a form of limited control over
the behavior of the vulnerable component.

=item * B<total>, The exploit gives the adversary total control over the behavior of the software, or it
gives total disclosure of all information on the system that contains the
vulnerability.

=back

=item $ssvc->mission_prevalence

Mission Prevalence

Impact on Mission Essential Functions of Relevant Entities

A mission essential function (MEF) is a function "directly related to accomplishing the organization's mission as set
forth in its statutory or executive charter." Identifying MEFs is part of business continuity planning or crisis planning.
In contrast to non-essential functions, an organization "must perform a [MEF] during a disruption to normal
operations." The mission is the reason an organization exists, and MEFs are how that mission is realized. Non-
essential functions support the smooth delivery or success of MEFs rather than directly supporting the mission. In
the next list, an "entity" is a USG department or agency, an SLTT government, or a critical infrastructure sector
organization.

=over

=item * B<minimal>, Neither support nor essential apply. The vulnerable component may be used within the
entities, but it is not used as a mission-essential component, nor does it provide
impactful support to mission-essential functions.

=item * B<support>, The vulnerable component only supports MEFs for two or more entities.

=item * B<essential>, The vulnerable component directly provides capabilities that constitute at least one MEF
for at least one entity; component failure may (but does not necessarily) lead to overall
mission failure.

=back

=item $ssvc->public_well_being_impact

Public Well-Being Impact

Impacts of Affected System Compromise on Humans

Safety violations are those that negatively impact well-being. SVCC embraces the Centers for Disease Control (CDC)
expansive definition of well-being, one that comprises physical, social, emotional, and psychological health.4
Each decision option lists examples of the effects that qualify for that value/answer in the various types of well-being
violations. These examples are suggestive and not comprehensive or exhaustive. While technical impact captures
adversary control of the computer system, public well-being impact captures wider repercussions.

=item $ssvc->mission_well_being_impact

Mission and Well-Being Impact

  +------------+-----------------------------------+
  | Mission    |     Public Well-Being Impact      |
  | Prevalence | Minimal | Material | Irreversible |
  +------------+---------+----------+--------------+
  | Minimal    | Low     | Medium   | High         |
  | Support    | Medium  | Medium   | High         |
  | Essential  | High    | High     | High         |
  +------------+---------+----------+--------------+

=back

=head2 Decision Tree

  +--------------+-------------+-----------+-------------+----------+
  | Exploitation | Automatable | Technical | Mission and | Decision |
  |              |             | Impact    | Well-Being  |          |
  +--------------+-------------+-----------+-------------+----------+
  | none         | no          | partial   | low         | Track    |
  | none         | no          | partial   | medium      | Track    |
  | none         | no          | partial   | high        | Track    |
  | none         | no          | total     | low         | Track    |
  | none         | no          | total     | medium      | Track    |
  | none         | no          | total     | high        | Track*   |
  | none         | yes         | partial   | low         | Track    |
  | none         | yes         | partial   | medium      | Track    |
  | none         | yes         | partial   | high        | Attend   |
  | none         | yes         | total     | low         | Track    |
  | none         | yes         | total     | medium      | Track    |
  | none         | yes         | total     | high        | Attend   |
  | poc          | no          | partial   | low         | Track    |
  | poc          | no          | partial   | medium      | Track    |
  | poc          | no          | partial   | high        | Track*   |
  | poc          | no          | total     | low         | Track    |
  | poc          | no          | total     | medium      | Track*   |
  | poc          | no          | total     | high        | Attend   |
  | poc          | yes         | partial   | low         | Track    |
  | poc          | yes         | partial   | medium      | Track    |
  | poc          | yes         | partial   | high        | Attend   |
  | poc          | yes         | total     | low         | Track    |
  | poc          | yes         | total     | medium      | Track*   |
  | poc          | yes         | total     | high        | Attend   |
  | active       | no          | partial   | low         | Track    |
  | active       | no          | partial   | medium      | Track    |
  | active       | no          | partial   | high        | Attend   |
  | active       | no          | total     | low         | Track    |
  | active       | no          | total     | medium      | Attend   |
  | active       | no          | total     | high        | Act      |
  | active       | yes         | partial   | low         | Attend   |
  | active       | yes         | partial   | medium      | Attend   |
  | active       | yes         | partial   | high        | Act      |
  | active       | yes         | total     | low         | Attend   |
  | active       | yes         | total     | medium      | Act      |
  | active       | yes         | total     | high        | Act      |
  +--------------+-------------+-----------+-------------+----------+


=head1 SEE ALSO

L<SSVC::CISA>

=over 4

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
