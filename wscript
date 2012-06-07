#!/usr/bin/env python
# -*- coding: utf-8 -*-
from waflib.Build import BuildContext
from waflib import Utils, Options

import os.path
import subprocess

APPNAME='libwebsite'
if os.path.exists('.git'):
    VERSION = subprocess.Popen(['git', 'describe'], stdout=subprocess.PIPE)\
        .communicate()[0].decode('ascii').strip().lstrip('v').replace('-', '_')
else:
    VERSION='0.2.21'

top = '.'
out = 'build'

def options(opt):
    opt.load('compiler_c')
    opt.add_option('--build-shared', action="store_true", dest="build_shared",
        help="Build shared library instead of static", default=False)

def configure(ctx):
    ctx.check_tool('compiler_c')
    ctx.env.BUILD_SHARED = Options.options.build_shared

def build(bld):
    bld(
        features     = ['c', ('cshlib'
            if bld.env.BUILD_SHARED else 'cstlib')],
        source       = [
            'src/core.c',
            'src/search.c',
            ],
        target       = 'website',
        includes     = ['src', 'include'],
        cflags       = ['-std=c99'],
        )
    if Options.options.build_shared:
        bld.install_files('${PREFIX}/lib', 'libwebsite.so')
    else:
        bld.install_files('${PREFIX}/lib', 'libwebsite.a')
    bld.install_files('${PREFIX}/include', 'include/website.h')

def build_tests(bld):
    build(bld)
    bld.add_group()
    lib = [
        'website',
        'ev',
        'crypto',
        'm',
        'cunit',
        ]
    bld(
        features     = ['c', 'cprogram'],
        source       = [
            'test/simple.c',
            ],
        target       = 'simple',
        includes     = ['src', 'include'],
        cflags       = ['-std=gnu99'],
        libpath      = ['.'],
        lib          = lib,
        )
    bld(
        features     = ['c', 'cprogram'],
        source       = [
            'test/detailed.c',
            ],
        target       = 'detailed',
        includes     = ['src', 'include'],
        defines      = [],
        cflags       = ['-std=c99'],
        libpath      = ['.'],
        lib          = lib,
        )
    bld(
        features     = ['c', 'cprogram'],
        source       = [
            'test/routing.c',
            ],
        target       = 'routing',
        includes     = ['src', 'include'],
        cflags       = ['-std=c99'],
        libpath      = ['.'],
        lib          = lib,
        )
    bld(
        features     = ['c', 'cprogram'],
        source       = [
            'test/websocket.c',
            ],
        target       = 'websocket',
        includes     = ['src', 'include'],
        cflags       = ['-std=c99'],
        libpath      = ['.'],
        lib          = lib,
        )
    bld(
        features     = ['c', 'cprogram'],
        source       = [
            'test/runtests.c',
            ],
        target       = 'runtests',
        includes     = ['src', 'include'],
        cflags       = ['-std=c99'],
        libpath      = ['.'],
        lib          = lib,
        )
    bld.add_group()
    bld(rule='./runtests', always=True)
    bld.add_group()
    bld(rule='cd ${SRC[0].parent.abspath()};'
        ' SIMPLE_BIN=${SRC[1].abspath()}'
        ' WEBSOCK_BIN=${SRC[2].abspath()}'
        ' DETAILED_BIN=${SRC[3].abspath()}'
        ' python ${SRC[0].abspath()} -v',
        source=['test/httptest.py', 'simple', 'websocket', 'detailed'],
        always=True)

class test(BuildContext):
    cmd = 'test'
    fun = 'build_tests'
    variant = 'test'


def dist(ctx):
    ctx.excl = ['.waf*', '*.tar.bz2', '*.zip', 'build',
        '.git*', '.lock*', '**/*.pyc']
    ctx.algo = 'tar.bz2'

def make_pkgbuild(task):
    import hashlib
    task.outputs[0].write(Utils.subst_vars(task.inputs[0].read(), {
        'VERSION': VERSION,
        'DIST_MD5': hashlib.md5(task.inputs[1].read('rb')).hexdigest(),
        }))

def archpkg(ctx):
    from waflib import Options
    Options.commands = ['dist', 'makepkg'] + Options.commands

def build_package(bld):
    distfile = APPNAME + '-' + VERSION + '.tar.bz2'
    bld(rule=make_pkgbuild,
        source=['PKGBUILD.tpl', distfile, 'wscript'],
        target='PKGBUILD')
    bld(rule='cp ${SRC} ${TGT}', source=distfile, target='.')
    bld.add_group()
    bld(rule='makepkg -f', source=distfile)
    bld.add_group()
    bld(rule='makepkg -f --source', source=distfile)

class makepkg(BuildContext):
    cmd = 'makepkg'
    fun = 'build_package'
    variant = 'archpkg'
