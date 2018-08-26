---
layout: post
title: Terminal Setup
---

## Kali VM

- Terminal - **Tilix**
	- `sudo apt-get install tilix`
- Tilix Themes
	- Tilix themes [GitHub Repo](https://github.com/storm119/Tilix-Themes)
	- **Argonaut**
	- `wget -qO $HOME"/.config/tilix/schemes/argonaut.json" https://git.io/v7QV5`
	- Apply color scheme
		- Preferences/Default/Color/Color scheme
	- [Other Themes](https://github.com/storm119/Tilix-Themes/blob/master/Themes.md)
- Shell - **zsh**
	- `chsh -s /bin/zsh`

- Zsh Theme - **oh-my-zsh**
	- oh-my-zsh [GitHub Repo](https://github.com/robbyrussell/oh-my-zsh)
	- Install via curl : `sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"`
	- Install via wget : `sh -c "$(wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"`
	- Theme - **Agnoster**
	- Edit ~/.zshrc and set theme as follows
		- `ZSH_THEME="agnoster"`
	- Install Powerline fonts. (Fixes font issue with agnoster theme)
		- `git clone https://github.com/powerline/fonts`
		- `cd fonts`
		- `./install.sh`
		- or `sudo apt-get install fonts-powerline`


## MacOS/OSX Setup

- Terminal Emulator - [**iTerm2**](https://www.iterm2.com/)
- iTerm2 Themes
	- iTerm2 theme [GitHub Repo](https://github.com/mbadolato/iTerm2-Color-Schemes)
	- **Argonaut**
	- `git clone https://github.com/mbadolato/iTerm2-Color-Schemes.git`
	- Open **iTerm2> Preferences> Profile> Colors> Color Presets**
	- Click import and select theme in schemes directory inside cloned repo.
	- Select **Argonaut** color scheme from Color Presets drop down
- Shell - **zsh**
	- `chsh -s /bin/zsh`
- Zsh Theme - **oh-my-zsh**
	- Follow instructions same as for Kali.
	- Set font **Meslo LG L for powerline** in iTerm2.
	- Uncheck **use different font for non-ASCII text**

