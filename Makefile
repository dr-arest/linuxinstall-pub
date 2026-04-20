SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

ENV_OPEN := env.sh
ENV_AES  := env.sh.aes

.PHONY: install create clean test-env

############################################################
# INSTALL
############################################################

install:
	@read -s -p "Enter decrypt password: " PASS; echo; \
	eval "$$(openssl enc -d -aes-256-gcm \
		-in $(ENV_AES) \
		-pbkdf2 -iter 10000 -salt -base64 \
		-pass pass:$$PASS 2>/dev/null)" ; \
	unset PASS ; \
	[ -n "$$GH_TOKEN" ] || { echo "GH_TOKEN not found"; exit 1; }; \
	echo "Token loaded."; \
	echo "$$GH_TOKEN" | gh auth login --with-token ; \
	$(MAKE) install-user ; \
	$(MAKE) install-system

############################################################
# CREATE
############################################################

create:
	@TOKEN="$${GH_TOKEN:-}"; \
	if [ -z "$$TOKEN" ]; then \
		read -p "Enter GH_TOKEN: " TOKEN; \
	fi; \
	[ -n "$$TOKEN" ] || { echo "Empty token"; exit 1; }; \
	read -s -p "Enter encryption password: " PASS; echo; \
	printf 'export GH_TOKEN="%s"\n' "$$TOKEN" > $(ENV_OPEN); \
	chmod 600 $(ENV_OPEN); \
	openssl enc -aes-256-gcm \
		-in $(ENV_OPEN) \
		-out $(ENV_AES) \
		-pbkdf2 -iter 10000 -salt -base64 \
		-pass pass:$$PASS; \
	shred -u $(ENV_OPEN) 2>/dev/null || rm -f $(ENV_OPEN); \
	echo "Created $(ENV_AES)"

############################################################
# USER INSTALL
############################################################

install-user:
	@echo "Running user installers..."
	@if [ -d ./user ]; then \
		while read file; do \
			echo "==> $$file"; \
			bash "$$file"; \
		done < <(find ./user -maxdepth 1 -type f -executable | sort); \
	fi

############################################################
# SYSTEM INSTALL
############################################################

install-system:
	@echo "Running system installers..."
	@if [ -d ./system ]; then \
		while read file; do \
			echo "==> $$file"; \
			sudo "$$file"; \
		done < <(find ./system -maxdepth 1 -type f -executable | sort); \
	fi

############################################################
# CLEAN
############################################################

clean:
	rm -f $(ENV_OPEN)

############################################################
# TEST
############################################################

test-env:
	@read -s -p "Password: " PASS; echo; \
	openssl enc -d -aes-256-gcm \
		-in $(ENV_AES) \
		-pbkdf2 -iter 10000 -salt -base64 \
		-pass pass:$$PASS
