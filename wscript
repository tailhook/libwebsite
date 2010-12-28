#!/usr/bin/env python
# -*- coding: utf-8 -*-
import Scripting, Options

APPNAME='libwebsite'
VERSION='0.2.5'

top = '.'
out = 'build'

def set_options(opt):
    opt.tool_options('compiler_cc')
    opt.add_option('--build-shared', action="store_true", dest="build_shared",
        help="Build shared library instead of static", default=False)
    opt.add_option('--build-tests', action="store_true", dest="build_tests",
        help="Build test cases", default=False)
    opt.add_option('--run-tests', action="store_true", dest="run_tests",
        help="Run test cases as a part of build", default=False)

def configure(ctx):
    ctx.check_tool('compiler_cc')
    ctx.env.BUILD_TESTS = Options.options.build_tests
    ctx.env.BUILD_SHARED = Options.options.build_shared

def build(bld):
    bld(
        features     = ['cc', ('cshlib'
            if bld.env.BUILD_SHARED else 'cstaticlib')],
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
    if bld.env.BUILD_TESTS:
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
            lib          = ['ev', 'website', 'crypto'],
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
            lib          = ['ev', 'website', 'crypto'],
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
            lib          = ['ev', 'website', 'crypto'],
            )
        bld(
            features     = ['cc', 'cprogram'],
            source       = [
                'test/websocket.c',
                ],
            target       = 'websocket',
            includes     = ['src', 'include'],
            defines      = [],
            ccflags      = ['-std=c99'],
            libpath      = [bld.bdir+'/default'],
            lib          = ['ev', 'website', 'crypto'],
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
        if Options.options.run_tests:
            bld.add_group()
            bld(rule=bld.bdir + '/default/runtests', always=True)
            bld.add_group()
            bld(rule='cd '+bld.srcnode.abspath()+';'
                ' python '+bld.srcnode.abspath()+'/test/httptest.py -v',
                always=True)

def test(ctx):
    Scripting.commands += ['build']
    Options.options.run_tests = True
