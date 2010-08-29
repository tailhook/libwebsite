#!/usr/bin/env python
# -*- coding: utf-8 -*-
APPNAME='libwebsite'
VERSION='0.1'

top = '.'
out = 'build'

def set_options(opt):
    opt.tool_options('compiler_cc')

def configure(conf):
    conf.check_tool('compiler_cc')

def build(bld):
    bld(
        features     = ['cc', 'cprogram'],
        source       = [
            'src/core.c',
            'src/search.c',
            'test/simple.c',
            ],
        target       = 'simple',
        includes     = ['src', 'include'],
        defines      = [],
        ccflags      = ['-std=c99', '-g'],
        lib          = ['ev'],
        )
    bld(
        features     = ['cc', 'cprogram'],
        source       = [
            'src/core.c',
            'src/search.c',
            'test/detailed.c',
            ],
        target       = 'detailed',
        includes     = ['src', 'include'],
        defines      = [],
        ccflags      = ['-std=c99', '-g'],
        lib          = ['ev'],
        )
    bld(
        features     = ['cc', 'cprogram'],
        source       = [
            'src/core.c',
            'src/search.c',
            'test/routing.c',
            ],
        target       = 'routing',
        includes     = ['src', 'include'],
        defines      = [],
        ccflags      = ['-std=c99', '-g'],
        lib          = ['ev'],
        )
