PREFIX?=/opt/nets
CARGO?=cargo
TARGET?=release

.PHONY: all build-linux build-windows build-macos vendor clean package-deb package-rpm package-msi package-dmg

all: build-linux

vendor:
$(CARGO) vendor --locked --versioned-dirs

build-linux:
$(CARGO) build --workspace --release --target x86_64-unknown-linux-gnu

build-windows:
$(CARGO) build --workspace --release --target x86_64-pc-windows-msvc

build-macos:
$(CARGO) build --workspace --release --target x86_64-apple-darwin

package-deb: build-linux
./scripts/package-deb.sh $(PREFIX)

package-rpm: build-linux
./scripts/package-rpm.sh $(PREFIX)

package-msi: build-windows
powershell -File scripts/package-msi.ps1 -Prefix $(PREFIX)

package-dmg: build-macos
bash scripts/package-dmg.sh $(PREFIX)

clean:
rm -rf target vendor
