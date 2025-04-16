# zsh-ssh

Enhanced SSH host management and completion for Zsh with fzf integration.

[![asciicast](https://asciinema.org/a/381405.svg)](https://asciinema.org/a/381405)

## Features

- 🔍 Interactive host selection with fzf
- 📝 SSH config management (add/modify/remove)
- 🔐 Secure password storage with base64 encoding
- 🎯 Smart host completion with descriptions
- 📋 Detailed host information preview
- 🔄 Proxy command support
- 📦 Backup mechanism for config changes

## Dependencies

Before installing zsh-ssh, make sure you have the following tools installed:

### Required Dependencies

#### fzf (Fuzzy Finder)
```shell
# macOS
brew install fzf

# Ubuntu/Debian
sudo apt-get install fzf

# CentOS/RHEL
sudo yum install fzf

# Arch Linux
sudo pacman -S fzf
```

#### gawk (GNU awk)
```shell
# macOS
brew install gawk

# Ubuntu/Debian
sudo apt-get install gawk

# CentOS/RHEL
sudo yum install gawk

# Arch Linux
sudo pacman -S gawk
```

### Optional Dependencies

#### sshpass (for password authentication)
```shell
# macOS
brew install sshpass

# Ubuntu/Debian
sudo apt-get install sshpass

# CentOS/RHEL
sudo yum install sshpass

# Arch Linux
sudo pacman -S sshpass
```

## Installation

Make sure you have installed all the required dependencies before proceeding.

### Zinit

```shell
zinit light sunlei/zsh-ssh
```

### Antigen

```shell
antigen bundle sunlei/zsh-ssh
```

### Oh My Zsh

1. Clone this repository into `$ZSH_CUSTOM/plugins` (by default `~/.oh-my-zsh/custom/plugins`)

    ```shell
    git clone https://github.com/sunlei/zsh-ssh ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-ssh
    ```

2. Add the plugin to the list of plugins for Oh My Zsh to load (inside `~/.zshrc`):

    ```shell
    plugins=(zsh-ssh $plugins)
    ```

3. Start a new terminal session.

### Sheldon

1. Add this config to `~/.config/sheldon/plugins.toml`

    ```toml
    [plugins.zsh-ssh]
    github = 'sunlei/zsh-ssh'
    ```

2. Run `sheldon lock` to install the plugin.

3. Start a new terminal session.

### Manual (Git Clone)

1. Clone this repository somewhere on your machine. For example: `~/.zsh/zsh-ssh`.

    ```shell
    git clone https://github.com/sunlei/zsh-ssh ~/.zsh/zsh-ssh
    ```

2. Add the following to your `.zshrc`:

    ```shell
    source ~/.zsh/zsh-ssh/zsh-ssh.zsh
    ```

3. Start a new terminal session.

## Usage

### SSH Host Completion

Press <kbd>Tab</kbd> after `ssh` command to get interactive host selection with fzf.

### SSH Config Management

#### Add New Host
```shell
sshadd
```
Interactive prompt to add a new SSH host configuration.

#### Modify Existing Host
```shell
sshmod [hostname]
```
- Without hostname: Interactive selection with fzf
- With hostname: Directly modify specified host

#### Remove Host
```shell
sshrm [hostname]
```
- Without hostname: Interactive selection with fzf
- With hostname: Directly remove specified host

### SSH Config Example

You can use `#_Desc` to set description and `#_Password` for encrypted password storage.

~/.ssh/config

```text
# Development Server
Host dev-server
    Hostname 1.1.1.1
    User developer
    #_Desc Development Environment
    #_Password <base64-encoded-password>
    IdentityFile ~/.ssh/dev-key

# Production Server
Host prod-server
    Hostname 2.2.2.2
    User admin
    #_Desc Production Environment
    Port 2222
    ProxyCommand ssh -q -W %h:%p jump@bastion.example.com
```

## Features in Detail

### Interactive Host Selection
- Fuzzy search through all configured hosts
- Preview host details in real-time
- Color-coded descriptions
- Keyboard navigation support

### Secure Password Management
- Passwords stored in base64 encoding
- Optional password authentication
- Secure password input (hidden)

### Proxy Support
- Jump server configuration
- Custom proxy commands
- Proxy user specification

### Backup System
- Automatic backup before modifications
- Timestamped backup files
- Config validation

## Requirements

- zsh
- fzf (required)
- gawk (required)
- base64 (usually pre-installed)
- sshpass (optional, for password authentication)
