sdn-ix demo
===========

This demo was explained during a presentation at the [2014 I2 tech exchange](http://meetings.internet2.edu/2014-technology-exchange/detail/10003432/)
and also at ChiNOG.

The demo runs on two seperate hosts, the "receiver" and "sender", executing
run-receiver.sh and run-sender.sh respectively.  The run scripts call exabgp
on the appropriate configuration file.  In particular, on the receiver, exabgp
will spawn a process 'receiver.pl' to process the json objects that came
in over flowspec.  This is the special sauce where the magic would happen.
This was developed on Ubuntu 14, and origonally the perl script used 'curl' 
to invoke flows into (a now deprecated version of) OpenDaylight.


Packages you will need:
-----------------------
> libnet-patricia-perl 

Things to modify
-----------------------
- ip addresses in etc/*conf and *env for the sender and receiver config section
- config section in the receiver.pl script
- applyflow section in the perl script


See the included file LICENSE for licensing details.  The bundled version of ExaBGP is licensed 
seperately and is just included as a convenience as it is really picky about paths and such.
