# Maintainer: Bill Sideris <bill88t@feline.gr>

pkgname=gpmaster
pkgver=1.5.1
pkgrel=1
pkgdesc="GPG-backed lockbox for secrets management"
arch=('any')
url="https://github.com/bill88t/gpmaster"
license=('GPL3')

depends=('python>=3.8' 'python-gnupg' 'gnupg' 'python-cryptography')
optdepends=('python-pyotp')
makedepends=('python-setuptools-scm' 'python-build' 'python-installer' 'python-wheel')
source=()
sha256sums=()

build() {
    cp -r "$srcdir/../gpmaster" "$srcdir/"
    cp -r "$srcdir/../pyproject.toml" "$srcdir/"
    cp -r "$srcdir/../README.md" "$srcdir/"
    cp -r "$srcdir/../setup.py" "$srcdir/"
    cp -r "$srcdir/../packaging" "$srcdir/"
    cp -r "$srcdir/../LICENSE" "$srcdir/"
    cp "$srcdir/../gpmaster-completion.bash" "$srcdir/"
    python -m build --wheel --no-isolation
}

package() {
    python -m installer --destdir="$pkgdir" dist/*.whl
    install -Dm755 packaging/gpmaster-agent "$pkgdir/usr/bin/gpmaster-agent"
    install -Dm644 packaging/gpmaster-agent.service "$pkgdir/usr/lib/systemd/user/gpmaster-agent.service"
    install -Dm755 packaging/gpg-wrap "$pkgdir/usr/lib/gpmaster/gpg-wrap"
    install -Dm644 gpmaster-completion.bash "$pkgdir/usr/share/bash-completion/completions/gpmaster"

    if [ -f LICENSE ]; then
        install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    fi
}
