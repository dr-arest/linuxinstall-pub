SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

###############################################################################
# Files / crypto settings
###############################################################################

ENV_OPEN        := env.sh
ENV_AES         := env.sh.enc
ENV_SHA256      := env.sh.enc.sha256

# Upgraded cipher: AES-256-GCM (AEAD)
OPENSSL_CIPHER  := -aes-256-gcm
OPENSSL_KDF     := -pbkdf2 -iter 200000 -salt -base64

###############################################################################
# Public targets
###############################################################################

.PHONY: \
	all help create install install-fast auth logout \
	verify-env test-env show-env rekey rotate-token \
	install-user install-system \
	clean clean-sec

.DEFAULT_GOAL := help
all: install

###############################################################################
# Help
###############################################################################

help:
	@printf '%s\n' \
	'Available targets:' \
	'  make create         - create encrypted env file (GH_TOKEN + optional vars)' \
	'  make install        - verify, decrypt, auth gh if needed, run installers' \
	'  make install-fast   - same as install but skips forced auth when already ok' \
	'  make auth           - decrypt and authenticate gh only' \
	'  make logout         - gh logout' \
	'  make rotate-token   - update GH_TOKEN only' \
	'  make rekey          - re-encrypt file with new password' \
	'  make verify-env     - verify checksum' \
	'  make test-env       - print decrypted content' \
	'  make show-env       - alias for test-env' \
	'  make install-user   - run ./user executable scripts' \
	'  make install-system - run ./system executable scripts with sudo' \
	'  make clean          - remove plaintext env file if exists'

###############################################################################
# Main targets
###############################################################################

install: verify-env
	@printf '\n==> Install workflow\n'
	@read -r -s -p "Enter decryption password: " PASS; echo; \
	PLAINTEXT="$$(openssl enc -d $(OPENSSL_CIPHER) \
		-in "$(ENV_AES)" \
		$(OPENSSL_KDF) \
		-pass pass:"$$PASS" 2>/dev/null)" \
		|| { echo "Decryption failed."; exit 1; }; \
	unset PASS; \
	GH_TOKEN="$$(printf '%s\n' "$$PLAINTEXT" | sed -n 's/^GH_TOKEN=\(.*\)$$/\1/p')"; \
	unset PLAINTEXT; \
	[ -n "$$GH_TOKEN" ] || { echo "GH_TOKEN missing."; exit 1; }; \
	if gh auth status >/dev/null 2>&1; then \
		echo "gh already authenticated."; \
	else \
		printf '%s' "$$GH_TOKEN" | gh auth login --with-token; \
	fi; \
	unset GH_TOKEN; \
	$(MAKE) install-user; \
	$(MAKE) install-system

install-fast: install

auth: verify-env
	@printf '\n==> Authenticate gh\n'
	@read -r -s -p "Enter decryption password: " PASS; echo; \
	PLAINTEXT="$$(openssl enc -d $(OPENSSL_CIPHER) \
		-in "$(ENV_AES)" \
		$(OPENSSL_KDF) \
		-pass pass:"$$PASS" 2>/dev/null)" \
		|| { echo "Decryption failed."; exit 1; }; \
	unset PASS; \
	GH_TOKEN="$$(printf '%s\n' "$$PLAINTEXT" | sed -n 's/^GH_TOKEN=\(.*\)$$/\1/p')"; \
	unset PLAINTEXT; \
	[ -n "$$GH_TOKEN" ] || { echo "GH_TOKEN missing."; exit 1; }; \
	printf '%s' "$$GH_TOKEN" | gh auth login --with-token; \
	unset GH_TOKEN

logout:
	@gh auth logout || true

###############################################################################
# Create / rotate / verify
###############################################################################

create:
	@printf '\n==> Create encrypted env\n'
	@TOKEN="$${GH_TOKEN:-}"; \
	if [ -z "$$TOKEN" ]; then \
		read -r -p "Enter GH_TOKEN: " TOKEN; \
	fi; \
	[ -n "$$TOKEN" ] || { echo "GH_TOKEN empty."; exit 1; }; \
	read -r -s -p "Enter encryption password: " PASS1; echo; \
	read -r -s -p "Repeat encryption password: " PASS2; echo; \
	[ "$$PASS1" = "$$PASS2" ] || { echo "Passwords do not match."; exit 1; }; \
	umask 077; \
	{ \
		printf 'GH_TOKEN=%s\n' "$$TOKEN"; \
		[ -n "$${GH_USER:-}" ] && printf 'GH_USER=%s\n' "$${GH_USER}"; \
		[ -n "$${DEPLOY_ENV:-}" ] && printf 'DEPLOY_ENV=%s\n' "$${DEPLOY_ENV}"; \
	} > "$(ENV_OPEN)"; \
	chmod 600 "$(ENV_OPEN)"; \
	openssl enc $(OPENSSL_CIPHER) \
		-in "$(ENV_OPEN)" \
		-out "$(ENV_AES)" \
		$(OPENSSL_KDF) \
		-pass pass:"$$PASS1"; \
	sha256sum "$(ENV_AES)" > "$(ENV_SHA256)"; \
	shred -u "$(ENV_OPEN)" 2>/dev/null || rm -f "$(ENV_OPEN)"; \
	unset TOKEN PASS1 PASS2; \
	echo "Created $(ENV_AES)"

rotate-token: verify-env
	@printf '\n==> Rotate GH_TOKEN\n'
	@read -r -s -p "Enter current decryption password: " PASS; echo; \
	PLAINTEXT="$$(openssl enc -d $(OPENSSL_CIPHER) \
		-in "$(ENV_AES)" \
		$(OPENSSL_KDF) \
		-pass pass:"$$PASS" 2>/dev/null)" \
		|| { echo "Wrong password."; exit 1; }; \
	read -r -p "Enter new GH_TOKEN: " NEWTOKEN; \
	[ -n "$$NEWTOKEN" ] || { echo "Empty token."; exit 1; }; \
	UPDATED="$$(printf '%s\n' "$$PLAINTEXT" | awk -F= 'BEGIN{s=0} $$1=="GH_TOKEN"{print "GH_TOKEN='"$$NEWTOKEN"'"; s=1; next} {print} END{if(!s) print "GH_TOKEN='"$$NEWTOKEN"'"}')"; \
	TMP="$$(mktemp "$(ENV_AES).tmp.XXXXXX")"; \
	chmod 600 "$$TMP"; \
	printf '%s\n' "$$UPDATED" | openssl enc $(OPENSSL_CIPHER) \
		$(OPENSSL_KDF) \
		-pass pass:"$$PASS" \
		-out "$$TMP"; \
	mv "$$TMP" "$(ENV_AES)"; \
	sha256sum "$(ENV_AES)" > "$(ENV_SHA256)"; \
	unset PASS PLAINTEXT NEWTOKEN UPDATED TMP; \
	echo "Token rotated."

verify-env:
	@printf '\n==> Verify encrypted env\n'
	@[ -f "$(ENV_AES)" ] || { echo "Missing $(ENV_AES)"; exit 1; }
	@[ -f "$(ENV_SHA256)" ] || { echo "Missing $(ENV_SHA256)"; exit 1; }
	@sha256sum -c "$(ENV_SHA256)"

test-env: verify-env
	@printf '\n==> Decrypted content\n'
	@read -r -s -p "Enter decryption password: " PASS; echo; \
	openssl enc -d $(OPENSSL_CIPHER) \
		-in "$(ENV_AES)" \
		$(OPENSSL_KDF) \
		-pass pass:"$$PASS"

show-env: test-env

###############################################################################
# Rekey
###############################################################################

rekey: verify-env
	@printf '\n==> Change encryption password\n'
	@read -r -s -p "Enter current password: " OLDPASS; echo; \
	PLAINTEXT="$$(openssl enc -d $(OPENSSL_CIPHER) \
		-in "$(ENV_AES)" \
		$(OPENSSL_KDF) \
		-pass pass:"$$OLDPASS" 2>/dev/null)" \
		|| { echo "Wrong password."; exit 1; }; \
	read -r -s -p "Enter new password: " NEW1; echo; \
	read -r -s -p "Repeat new password: " NEW2; echo; \
	[ "$$NEW1" = "$$NEW2" ] || { echo "Passwords do not match."; exit 1; }; \
	TMP="$$(mktemp "$(ENV_AES).tmp.XXXXXX")"; \
	chmod 600 "$$TMP"; \
	printf '%s\n' "$$PLAINTEXT" | openssl enc $(OPENSSL_CIPHER) \
		$(OPENSSL_KDF) \
		-pass pass:"$$NEW1" \
		-out "$$TMP"; \
	mv "$$TMP" "$(ENV_AES)"; \
	sha256sum "$(ENV_AES)" > "$(ENV_SHA256)"; \
	unset PLAINTEXT OLDPASS NEW1 NEW2 TMP; \
	echo "Rekey complete."

###############################################################################
# Install scripts
###############################################################################

install-user:
	@printf '\n==> Run user installers\n'
	@if [ -d ./user ]; then \
		found=0; \
		while IFS= read -r file; do \
			found=1; \
			echo "==> $$file"; \
			bash "$$file"; \
		done < <(find ./user -maxdepth 1 -type f -executable | sort); \
		[ $$found -eq 1 ] || echo "No executable files in ./user"; \
	else \
		echo "Directory ./user not found."; \
	fi

install-system:
	@printf '\n==> Run system installers\n'
	@if [ -d ./system ]; then \
		found=0; \
		while IFS= read -r file; do \
			found=1; \
			echo "==> $$file"; \
			sudo "$$file"; \
		done < <(find ./system -maxdepth 1 -type f -executable | sort); \
		[ $$found -eq 1 ] || echo "No executable files in ./system"; \
	else \
		echo "Directory ./system not found."; \
	fi

###############################################################################
# Cleanup
###############################################################################

clean:
	@rm -f "$(ENV_OPEN)"

clean-sec: clean
