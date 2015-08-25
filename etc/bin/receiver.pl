#!/usr/bin/perl

# sdn-ix demo reciever logic
# by Dale W. Carder, dwcarder@wisc.edu 2014-09-01
# Copyright (c) 2014, The University of Wisconsin Board of Regents
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#  
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#  
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#  
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  


use warnings;
use strict;
use JSON::XS;
use Net::Patricia;

# some global variables, because I'm lazy
my $source_nets = new Net::Patricia;
my $dest_nets = new Net::Patricia;
my $jsonobj = JSON::XS->new->ascii->pretty->allow_nonref;
my $allow = 1;
my $deny = 0;
my $num_rules = 0;

############### "configuration" section
my $logfile = '/home/dwcarder/src/sdnix/rec.log';

# technically, we could be creative and stuff way more specific
# things into the patricia trie such as a datastrcture that could
# represent what protocols and ports to allow.  But heck, this is
# just a demo.

# deny everything, then allow specific networks
$source_nets->add_string('0.0.0.0/0',\$deny);
$source_nets->add_string('10.0.0.0/8',\$allow);

# deny everything, then allow specific networks
$dest_nets->add_string('0.0.0.0/0',\$deny);
$dest_nets->add_string('10.0.0.0/8',\$allow);

# TODO: see the verify subroutine for more configy bits
my $rule_limit = 5;

############### end configuration section


### subroutines
sub verify($$);
sub applyflow($$);
sub removeflow();

#################

# non-block and rock!
$| = 1;
open(LOG,">>$logfile") or
	die ("Can't open log file: $!");
select(LOG);
$| = 1;


my $pid = $$;
print LOG "\n\n----  PID  $pid  ---- \n";


# main loop to decode json text from exabgp
while(<>) {
	my $line = $_;
	chomp $line;
	#print LOG "DEBUG: got $line\n\n";
	my $msg = $jsonobj->decode($line);

	if (defined( $$msg{'type'} )) {

		# handle messages from exabgp itself
		if ( $$msg{'type'} eq 'notification' ) {
			print LOG "STATUS: recieved notification: " . $$msg{'notification'} . "\n\n";
		}

		# bgp udpate message
		elsif ( defined($$msg{'type'}) && $$msg{'type'} eq 'update' ) {
			#print LOG "DEBUG: looks like update\n";

			if ( defined( $$msg{'neighbor'}{'message'}{'update'}{'announce'}{'ipv4 flow'}{'none'} ) ) {
				#print LOG "DEBUG: looks like a flow\n";
				my $flowblock = $$msg{'neighbor'}{'message'}{'update'}{'announce'}{'ipv4 flow'}{'none'};

				foreach my $flownum (keys $flowblock) {
					#print LOG "DEBUG: decoded: " . $jsonobj->encode($msg) . "\n\n";

					if ( defined( $$msg{'neighbor'}{'message'}{'update'}{'attribute'}{'community'} ) ) {
						# handle communities
						my @comm = @{$$msg{'neighbor'}{'message'}{'update'}{'attribute'}{'community'}};

						# TODO:  today only support one community which corresponds to an "action"
						my $as = $comm[0][0];
						my $community = $comm[0][1];
						my $com_str = $as . ':' . $community;
						print "got community: $com_str \n";

						if (defined($com_str) && verify($$flowblock{$flownum},$com_str)) {
							applyflow($$flowblock{$flownum},$com_str);
						}
					}

				}

			} else {
				# TODO: handle removing a flow when withdrawn from bgp
				print LOG "DEBUG: not sure what to do with this update...\n";
				print LOG "DEBUG: decoded: " . $jsonobj->encode($msg) . "\n\n";
			}

		} else {
			print LOG "DEBUG: not sure what to do with this message...\n";
			print LOG "DEBUG: decoded: " . $jsonobj->encode($msg) . "\n\n";
		}
	}
	#print LOG "DEBUG: loop end.\n\n";

}

sub verify($$) {
	my $flow = shift;
	my $community = shift;
	my $pass = 0;

	#TODO: these are actually arrays, so handle that... someday
	print LOG "Recieved flow:   ";
	print LOG "source: " . $$flow{'source'}[0];
	print LOG ", s-port: " . $$flow{'source-port'}[0];
	print LOG ", dest: " . $$flow{'destination'}[0];
	print LOG ", d-port: " . $$flow{'destination-port'}[0];
	print LOG ", proto: " . $$flow{'protocol'}[0];
	print LOG "\n";

	$community =~ m/^(\d+):(\d+)/;
	if ($2 == 100) {
		$pass = 1;
	} else {
		print LOG "Rejecting because of invalid community.\n";
	}

	# make sure we only apply so many rules.
	if (($num_rules + 1) > $rule_limit) {
		print LOG "Rejecting because too many flows are already installed.\n";
		return(0);
	}

	# see if source ip is in the range allowed
	my $s_result = $source_nets->match_string($$flow{'source'}[0]);
	if (defined($s_result) && $$s_result==1) {
		$pass = 1;
	} else {
		print LOG "Rejecting because source ip not allowed. " . $$s_result . "\n";
		return(0);
	}

	# see if dest ip is in the range allowed
	my $d_result = $source_nets->match_string($$flow{'destination'}[0]);
	if (defined($d_result) && $$d_result==1) {
		$pass = 1;
	} else {
		print LOG "Rejecting because dest ip not allowed. " . $$d_result . "\n";
		return(0);
	}

	# TODO: make this configurable
	if ($$flow{'protocol'}[0] eq '=TCP') {
		$pass = 1;
	} else {
		print LOG "Rejecting because protocol is not allowed.\n";
		return(0);
	}

	# TODO: make this configurable
	if ($$flow{'destination-port'}[0] eq '=22') {
		$pass = 1;
	} else {
		print LOG "Rejecting because this port is not allowed.\n";
		return(0);
	}

	if ($pass) {
		print LOG "accepting flow\n";
		return(1);
	} else {
		print LOG "rejecting flow\n";
		return(0);
	}

}

sub applyflow($$) {
	$num_rules++;
	my $flow = shift;
	my $community = shift;

	print LOG "Applying flow\n";

	# put your specific logic here.
	#ex: ovs-ofctl add-flow br0 ....
}

sub removeflow() {
	#TODO
	$num_rules--;
}
