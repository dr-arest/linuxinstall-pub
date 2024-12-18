SHELL := /bin/bash
CRED_FILE_BASE := githubsec
CRED_FILE_OPEN := ./$(CRED_FILE_BASE).conf
CRED_FILE_AES := ./$(CRED_FILE_BASE).aes
CRED_FILE_SHA256 := ./$(CRED_FILE_BASE).aes.sha256
TOKEN = $(shell cat $(CRED_FILE_OPEN))

.PHONY: all prepare decrypt git-auth git-repos git-repo-linuxinstall git-repo-home_etc git-repo-QuickRef install install-user install-system clean clean-sec clean-public


# Виконує скрипт prepare_install.sh
all: prepare decrypt git-auth git-repos clean-sec

prepare:
		sudo apt install git gh
decrypt:
		FAIL=0; [ ! -f $(CRED_FILE_AES) ] && FAIL=1; [ ! -f $(CRED_FILE_SHA256) ] && FAIL=1; if [ $$FAIL -eq 1 ]; then echo "Files $(CRED_FILE_AES) and $(CRED_FILE_SHA256) are required"; exit 1; else echo "Files $(CRED_FILE_AES) and $(CRED_FILE_SHA256) are present. Verifying checksum..."; fi
		if ! sha256sum -c $(CRED_FILE_SHA256); then echo "File corrupted. Exit." >&2; exit 1; else echo "Checksum correct."; fi
                echo -n "Enter password: "; \
                read -s password; \
                echo; \
                if echo $$password | openssl enc -d -aes-256-cbc -in $(CRED_FILE_AES) -pbkdf2 -iter 10000 -salt -out $(CRED_FILE_OPEN) -base64 -pass stdin; then \
                        echo "Decryption successful."; \
                else \
                        echo "Decryption failed."; \
                        exit 1; \
                fi
		chmod 600 $(CRED_FILE_OPEN)

git-auth:
		@if [ -f $(CRED_FILE_OPEN) ]; then \
			echo "Reading token from $(CRED_FILE_OPEN)..."; \
			gh auth login --with-token < githubsec.conf; \
		else \
			echo "File not found: $(CRED_FILE_OPEN)"; \
			exit 1; \
		fi

git-repos: git-repo-linuxinstall git-repo-home_etc  git-repo-QuickRef

git-repo-linuxinstall:
		cd; gh repo clone dr-arest/linuxinstall
	
git-repo-home_etc:
		cd; gh repo clone dr-arest/.home_etc
	
git-repo-QuickRef:
		cd ; gh repo clone dr-arest/QuickRef
	
git-repo-bashlib:
		cd; gh repo clone dr-arest-bashlib


install:	install-user install-system

install-user:
		while read file; do \
			bash $$file && echo Done. || echo -e "Failed!"; \
		done < <(readlink -f $$(find ./user -maxdepth 1 -type f -executable   -print))

install-system:
		while read file; do \
			sudo $$file && echo "Done." || echo -e "Failed!"; \
		done < <(readlink -f $$(find ./system -maxdepth 1 -type f -executable   -print))

clean: clean-sec clean-public
clean-sec:
	rm -rf githubsec.conf

clean-public:
	rm -rf ~/linuxinstall-public
