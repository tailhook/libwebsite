Libwebsite
==========

Libwebsite is `evhttp` replacement for `libev` users. It's designed specifically
for [zerogw](http://github.com/tailhook/zerogw), but can be used for other
applications as well.

Dependencies (you need ``*-dev`` versions of packages):

 * libev
 * openssl

Build Instructions
------------------

Build process is done with autotools

    ./autoreconf
    .configure --prefix=/usr
    make
    make install


