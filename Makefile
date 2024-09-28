
.PHONY: all prepare decrypt git-auth git-repos git-repo-linuxinstall git-repo-home_etc git-repo-QuickRef git-repo-bashlib iinstall install-user install-system clean clean-sec clean-public


# Виконує скрипт prepare_install.sh
all: prepare decrypt git-auth git-repos clean-sec

prepare:
		sudo apt install git gh
decrypt:
		[ ! -f githubsec.aes -o ! -f githubsec.aes.sha256 ] && echo "Files githubsec.aes and githubsec.aes.sha256 are required" && exit 1
		sha256sum -c ./githubsec.aes.sha256 || { echo "File corrupted. Exit." >&2; exit 1; }
		echo "Enter password: "; read -s password; export password
		openssl enc -d -aes-256-cbc -in ./githubsec.aes -pbkdf2 -iter 10000 -salt -out ./githubsec.conf -base64 -pass env:password && echo "Decryption successfull." || echo "Decryption failed."
		chmod 600 githubsec.conf
git-auth:
		gh auth login --with-token < githubsec.conf

git-repos: git-repo-linuxinstall git-repo-home_etc  git-repo-QuickRef git-repo-bashlib

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
		while read file; do
			bash $file && echo Done. || echo -e "Failed!"
		done < <(readlink -f $(find ./user -maxdepth 1 -type f -executable   -print))

install-system:
		while read file; do
			sudo $file && echo "Done." || echo -e "Failed!"
		done < <(readlink -f $(find ./system -maxdepth 1 -type f -executable   -print))

clean: clean-sec clean-public
clean-sec:
	rm -rf githubsec.conf

clean-public:
	rm -rf ~/linuxinstall-public
