# pyphpipam
Python client for working with phpIPAM API


This is written to interface with phpIPAM's API. I wrote it to be as straightforward as possible
but I am not an expert. If you see something broken or that could be improved, please let me know.

Encryption is done via HTTPS but the certificate on the machine I use locally fails 
because requests only verifies against a Mozilla public certificate store and the certificate
used on the my IPAdmin box is issued by our internal CA.

A note on simple. The simple argument simplifies a negative return so that it only returns 
a False bool in the case of failure. This is so that you can easily test for truthiness in your own 
scripts instead of handling the failure message, which you may not care about (Imagine implementing a 
big interdependent stack of calls where, if one fails, you want to just roll the whole things back.)
The default is False so simple=True will enable this behavior.

I use the same local setup file in my pypath for all of my day to day scripts. This could be easily
converted to use a json