# Maintainer: Bill Sideris <bill88t@feline.gr>
pkgname=gpmaster
pkgver=1.1.2
pkgrel=1
pkgdesc="GPG-backed lockbox for secrets management"
arch=('any')
url="https://github.com/bill88t/gpmaster"
license=('GPL3')
depends=('python>=3.8' 'python-gnupg' 'gnupg')
optdepends=('python-pyotp')
makedepends=('python-setuptools-scm' 'python-build' 'python-installer' 'python-wheel')
source=()
sha256sums=()

build() {
    cp -r "$srcdir/../gpmaster" "$srcdir/"
    cp -r "$srcdir/../pyproject.toml" "$srcdir/"
    cp -r "$srcdir/../README.md" "$srcdir/"
    cp -r "$srcdir/../setup.py" "$srcdir/"
    cp "$srcdir/../gpmaster-completion.bash" "$srcdir/"
    python -m build --wheel --no-isolation
}

package() {
    python -m installer --destdir="$pkgdir" dist/*.whl

    # Install bash completion
    install -Dm644 gpmaster-completion.bash "$pkgdir/usr/share/bash-completion/completions/gpmaster"

    # Install license if available
    if [ -f LICENSE ]; then
        install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    fi
}
