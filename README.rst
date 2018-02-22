Python MMDB encoder
=========================

At Cloudflare, as part of the network automation, we build our IP prefix tables.

An example of how to use it:
:: 
    import mmdbencoder
    enc = mmdbencoder.Encoder(
        6, # IP version
        32, # Size of the pointers
        'My-Custom-Table', # Name of the table
        ['en'], # Languages
        {'en': 'Lorem Ipsum'}, # Description
        compat=True) # Map IPv4 in IPv6 (::abcd instead of ::ffff:abcd) to be read by official libraries
    data = enc.insert_data({'info': 'Hello World'})
    enc.insert_network(u'10.0.0.0/24', data)
    enc.write_file('hello.mmdb')

Installation
============

From source:
::
    $ ./setup.py install
    $ 

From pypi:
::
    $ pip install py-mmdb-encoder
    $ 
