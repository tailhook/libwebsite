#!/usr/bin/env python
# -*- coding: utf-8 -*-
import Scripting, Options

APPNAME='libwebsite'
VERSION='0.1.2'

top = '.'
out = 'build'

def set_options(opt):
    opt.tool_options('compiler_cc')
    opt.add_option('--build-shared', action="store_true", dest="build_shared",
        help="Build shared library instead of static")
    opt.add_option('--build-tests', action="store_true", dest="build_tests",
        help="Build test cases")

def configure(ctx):
    ctx.check_tool('compiler_cc')

def build(bld):
    bld(
        features     = ['cc', ('cshlib'
            if Options.options.build_shared else 'cstaticlib')],
        source       = [
            'src/core.c',
            'src/search.c',
            ],
        target       = 'website',
        includes     = ['src', 'include'],
        defines      = [],
        ccflags      = ['-std=c99'],
        lib          = ['ev'],
        )
    if Options.options.build_shared:
        bld.install_files('${PREFIX}/lib', [bld.bdir+'/default/libwebsite.so'])
    else:
        bld.install_files('${PREFIX}/lib', [bld.bdir+'/default/libwebsite.a'])
    bld.install_files('${PREFIX}/include', ['include/website.h'])
    if Options.options.build_tests:
        bld(
            features     = ['cc', 'cprogram'],
            source       = [
                'test/simple.c',
                ],
            target       = 'simple',
            includes     = ['src', 'include'],
            defines      = [],
            ccflags      = ['-std=c99'],
            libpath      = [bld.bdir+'/default'],
            lib          = ['ev', 'website'],
            )
        bld(
            features     = ['cc', 'cprogram'],
            source       = [
                'test/detailed.c',
                ],
            target       = 'detailed',
            includes     = ['src', 'include'],
            defines      = [],
            ccflags      = ['-std=c99'],
            libpath      = [bld.bdir+'/default'],
            lib          = ['ev', 'website'],
            )
        bld(
            features     = ['cc', 'cprogram'],
            source       = [
                'test/routing.c',
                ],
            target       = 'routing',
            includes     = ['src', 'include'],
            defines      = [],
            ccflags      = ['-std=c99'],
            libpath      = [bld.bdir+'/default'],
            lib          = ['ev', 'website'],
            )
        bld(
            features     = ['cc', 'cprogram'],
            source       = [
                'test/runtests.c',
                ],
            target       = 'runtests',
            includes     = ['src', 'include'],
            defines      = [],
            ccflags      = ['-std=c99'],
            libpath      = [bld.bdir+'/default'],
            lib          = ['ev', 'cunit', 'website'],
            )
        bld.add_group()
        bld(rule=bld.bdir + '/default/runtests', always=True)
        bld.add_group()
        bld(rule='cd '+bld.srcnode.abspath()+';'
            ' python '+bld.srcnode.abspath()+'/test/httptest.py -v',
            always=True)

def test(ctx):
    Scripting.commands += ['build']
    Options.options.build_tests = True
