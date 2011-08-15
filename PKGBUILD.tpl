# Maintainer: Paul Colomiets <pc@gafol.net>

pkgname=libwebsite
pkgver=${VERSION}
pkgrel=1
pkgdesc="An http/websocket protocol implementation for fast web servers"
arch=('i686' 'x86_64')
url="http://github.com/tailhook/libwebsite"
license=('GPL')
depends=('libev' 'openssl')
makedepends=('python3')
source=(https://github.com/downloads/tailhook/libwebsite/$pkgname-$pkgver.tar.bz2)
md5sums=('${DIST_MD5}')

build() {
  cd $srcdir/$pkgname-$pkgver
  ./waf configure --prefix=/usr
  ./waf build
}

check() {
  cd $srcdir/$pkgname-$pkgver
  ./waf test
}

package() {
  cd $srcdir/$pkgname-$pkgver
  ./waf install --destdir=$pkgdir
}
