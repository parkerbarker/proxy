# PB Proxy

Dec 12th 12:31am

Explored initial stucture with a ruby and rust system

Dec 13th 11:08

Decided to start with ruby initially. Found a old repo that contained a gem for creating proxy servers. Found a few rust examples of proxy servers. Found a lot.

Anyways I've started mapping out the system, which will act
kind of like an event machine. One of the shopify guys had a libary i discovered that was starting to build using the event machine gem. This whole system could be considered an event system. Each event you add on takes some kind of latency.

I'm feeling pretty pumped about this as it's really simple as of right now from a routing perspective. On the Certificate side though it seems complicated. It's pretty exciting actually, I'm interested in understanding it more, and remembered I know a guy from a meet up I went to that runs a certificate business. I wonder if he does consulting and would pair with me on my code.

If you want my advice, start working on the agent spec, then the certificate spec, and end with the middleware spec.
