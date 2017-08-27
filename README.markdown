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

Build process is done with CMake:

    mkdir build && cd build
    cmake ..
    cmake --build .

For building test examples:

    cmake --build . --target tests
