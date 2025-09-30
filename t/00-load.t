#!perl

use strict;
use warnings;

use Test::More;

use_ok('SSVC');
use_ok('SSVC::CISA');

done_testing();

diag("SSVC $SSVC::VERSION, Perl $], $^X");
