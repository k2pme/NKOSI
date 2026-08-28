.PHONY: build release install clean test deb fmt clippy test-all ci

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt -- --check

clippy:
	cargo clippy -- -D warnings

test-all:
	cargo test --all

ci: fmt clippy test-all
	@echo "CI passed!"

clean:
	cargo clean

install: release
	sudo mkdir -p /etc/nkosi
	sudo mkdir -p /var/lib/nkosi
	sudo mkdir -p /var/log/nkosi
	sudo cp config/nkosi.toml /etc/nkosi/
	sudo cp target/release/nkosi-agent /usr/local/bin/
	sudo cp target/release/nkosi-cli /usr/local/bin/
	sudo cp target/release/nkosi-ui /usr/local/bin/
	sudo cp target/release/nkosi-central /usr/local/bin/ 2>/dev/null || true
	sudo cp target/release/nkosi-console /usr/local/bin/ 2>/dev/null || true
	sudo cp config/nkosi-agent.service /etc/systemd/system/
	sudo cp config/nkosi-console.service /etc/systemd/system/ 2>/dev/null || true
	sudo cp config/nkosi-ti-update.service /etc/systemd/system/
	sudo cp config/nkosi-ti-update.timer /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable nkosi-agent
	sudo systemctl enable nkosi-ti-update.timer
	@echo "Installation complete!"
	@echo "Run: sudo systemctl start nkosi-agent"

uninstall:
	sudo systemctl stop nkosi-agent || true
	sudo systemctl disable nkosi-agent || true
	sudo systemctl stop nkosi-ti-update.timer || true
	sudo systemctl disable nkosi-ti-update.timer || true
	sudo rm -f /etc/systemd/system/nkosi-agent.service
	sudo rm -f /etc/systemd/system/nkosi-console.service
	sudo rm -f /etc/systemd/system/nkosi-ti-update.service
	sudo rm -f /etc/systemd/system/nkosi-ti-update.timer
	sudo systemctl daemon-reload
	sudo rm -f /usr/local/bin/nkosi-agent
	sudo rm -f /usr/local/bin/nkosi-cli
	sudo rm -f /usr/local/bin/nkosi-ui
	sudo rm -f /usr/local/bin/nkosi-central
	sudo rm -f /usr/local/bin/nkosi-console
	@echo "Uninstalled (data preserved in /var/lib/nkosi)"

deb: release
	@mkdir -p /tmp/nkosi-deb/DEBIAN
	@mkdir -p /tmp/nkosi-deb/usr/local/bin
	@mkdir -p /tmp/nkosi-deb/etc/nkosi
	@mkdir -p /tmp/nkosi-deb/etc/systemd/system
	@mkdir -p /tmp/nkosi-deb/etc/bash_completion.d
	@mkdir -p /tmp/nkosi-deb/usr/share/zsh/vendor-completions
	@mkdir -p /tmp/nkosi-deb/usr/share/man/man1
	@mkdir -p /tmp/nkosi-deb/var/lib/nkosi
	@mkdir -p /tmp/nkosi-deb/var/log/nkosi
	@cp target/release/nkosi-agent /tmp/nkosi-deb/usr/local/bin/
	@cp target/release/nkosi-cli /tmp/nkosi-deb/usr/local/bin/
	@cp target/release/nkosi-ui /tmp/nkosi-deb/usr/local/bin/
	@cp target/release/nkosi-api /tmp/nkosi-deb/usr/local/bin/ 2>/dev/null || true
	@cp target/release/nkosi-central /tmp/nkosi-deb/usr/local/bin/ 2>/dev/null || true
	@cp target/release/nkosi-console /tmp/nkosi-deb/usr/local/bin/ 2>/dev/null || true
	@cp config/nkosi.toml /tmp/nkosi-deb/etc/nkosi/
	@cp config/nkosi-agent.service /tmp/nkosi-deb/etc/systemd/system/
	@cp config/nkosi-console.service /tmp/nkosi-deb/etc/systemd/system/ 2>/dev/null || true
	@cp config/nkosi-ti-update.service /tmp/nkosi-deb/etc/systemd/system/
	@cp config/nkosi-ti-update.timer /tmp/nkosi-deb/etc/systemd/system/ 2>/dev/null || true
	@cp man/nkosi.1 /tmp/nkosi-deb/usr/share/man/man1/ 2>/dev/null || true
	@cp completions/nkosi.bash /tmp/nkosi-deb/etc/bash_completion.d/ 2>/dev/null || true
	@cp completions/_nkosi /tmp/nkosi-deb/usr/share/zsh/vendor-completions/ 2>/dev/null || true
	@echo 'Package: nkosi' > /tmp/nkosi-deb/DEBIAN/control
	@echo 'Version: 0.2.0' >> /tmp/nkosi-deb/DEBIAN/control
	@echo 'Section: utils' >> /tmp/nkosi-deb/DEBIAN/control
	@echo 'Priority: optional' >> /tmp/nkosi-deb/DEBIAN/control
	@echo 'Architecture: amd64' >> /tmp/nkosi-deb/DEBIAN/control
	@echo 'Depends: libssl3, iptables' >> /tmp/nkosi-deb/DEBIAN/control
	@echo 'Maintainer: NKOSI Team' >> /tmp/nkosi-deb/DEBIAN/control
	@echo 'Description: NKOSI Security Agent for Linux' >> /tmp/nkosi-deb/DEBIAN/control
	@echo ' Antivirus et protection endpoint pour Linux.' >> /tmp/nkosi-deb/DEBIAN/control
	@echo ' Dashboard web, pare-feu integre, scan rootkit.' >> /tmp/nkosi-deb/DEBIAN/control
	@dpkg-deb --build /tmp/nkosi-deb nkosi_0.2.0_amd64.deb
	@rm -rf /tmp/nkosi-deb
	@echo "Package created: nkosi_0.2.0_amd64.deb"
