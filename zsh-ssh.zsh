# Improved SSH Config Parser for Zsh with proper handling of SSH config formats

setopt no_beep # Don't beep

SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
EXPECT_SCRIPT_DIR="${HOME}/.ssh/expect"
[[ ! -d "$EXPECT_SCRIPT_DIR" ]] && mkdir -p "$EXPECT_SCRIPT_DIR"

# Parse the SSH config file
_parse_config_file() {
  setopt localoptions rematchpcre
  unsetopt nomatch

  local config_file_path=$(realpath "$1")
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Handle include directive
    if [[ $line =~ ^[Ii]nclude[[:space:]]+(.*) ]]; then
      local include_path="${match[1]}"
      if [[ $include_path == ~* ]]; then
        local expanded_include_path=${include_path/#\~/$HOME}
      else
        local expanded_include_path="$HOME/.ssh/$include_path"
      fi
      for include_file_path in $expanded_include_path; do
        if [[ -f "$include_file_path" ]]; then
          _parse_config_file "$include_file_path"
        fi
      done
    else
      echo "$line"
    fi
  done < "$config_file_path"
}

_ssh_host_list() {
  local ssh_config host_list

  ssh_config=$(_parse_config_file $SSH_CONFIG_FILE)
  ssh_config=$(echo "$ssh_config" | command grep -v -E "^\s*#[^_]")

  host_list=$(echo "$ssh_config" | gawk '
    # Function to extract description
    function extract_desc(line) {
      if (line ~ /^[[:space:]]*#_Desc[[:space:]]+/) {
        sub(/^[[:space:]]*#_Desc[[:space:]]+/, "", line)
        return line
      }
      return ""
    }

    BEGIN {
      IGNORECASE = 1
      FS="\n"
      RS=""
      host_list = ""
    }
    {
      match_directive = ""
      user = " "
      host_name = ""
      alias = ""
      desc = ""
      desc_formated = " "
      proxy_command = ""

      for (line_num = 1; line_num <= NF; ++line_num) {
        current_line = $line_num
        desc_match = extract_desc(current_line)
        if (desc_match != "") {
          desc = desc_match
          continue
        }

        # Skip empty lines
        if (current_line ~ /^[[:space:]]*$/) continue

        # Use gawk match function with array parameter
        if (match(current_line, /^[[:space:]]*([^[:space:]]+)[[:space:]]+(.*)$/, matches)) {
          key = tolower(matches[1])
          value = matches[2]

          if (key == "match") { match_directive = value }
          if (key == "host") { aliases = value }
          if (key == "user") { user = value }
          if (key == "hostname") { host_name = value }
          if (key == "proxycommand") { proxy_command = value }
        }
      }

      split(aliases, alias_list, " ")
      for (i in alias_list) {
        alias = alias_list[i]

        if (!host_name && alias) {
          host_name = alias
        }

        if (desc) {
          desc_formated = sprintf("[\033[00;34m%s\033[0m]", desc)
        }

        if ((host_name && !match_directive)) {
          host = sprintf("%s|->|%s|%s|%s\n", alias, host_name, user, desc_formated)
          host_list = host_list host
        }
      }
    }
    END {
      print host_list
    }
  ')

  for arg in "$@"; do
    case $arg in
    -*) shift;;
    *) break;;
    esac
  done

  host_list=$(command grep -i "$1" <<< "$host_list")
  host_list=$(echo "$host_list" | command sort -u)

  echo "$host_list"
}

_ssh_connect() {
  local host=$1
  local password_encoded=$(awk -v host="$host" '
    BEGIN { in_block = 0 }
    $0 ~ "^Host[[:space:]]+" host "$" { in_block = 1; next }
    in_block && /^[[:space:]]*#_Password[[:space:]]+/ { 
      sub(/^[[:space:]]*#_Password[[:space:]]*/, "", $0)
      print $0
      exit
    }
    in_block && /^Host / { exit }
  ' "$SSH_CONFIG_FILE")
  
  if [[ -n "$password_encoded" ]]; then
    local password=$(echo "$password_encoded" | base64 -d)
    # Check if sshpass is installed
    if ! command -v sshpass &> /dev/null; then
      echo "sshpass is not installed. Please install it first:"
      echo "  - On macOS: brew install sshpass"
      echo "  - On Ubuntu/Debian: sudo apt-get install sshpass"
      echo "  - On CentOS/RHEL: sudo yum install sshpass"
      return 1
    fi
    
    # Use sshpass to connect
    sshpass -p "$password" ssh "$host"
  else
    ssh "$host"
  fi
}

# Create SSH config with optional fields
_add_ssh_config() {
  local alias hostname user port identity_file desc proxy_host proxy_user password config_entry
  local prompt_color="\033[00;34m"
  local reset_color="\033[0m"

  printf "${prompt_color}Adding new SSH config entry:${reset_color}\n"
  printf "${prompt_color}Alias${reset_color} (e.g., myserver): "
  read alias
  printf "${prompt_color}Description${reset_color} (optional, for better organization): "
  read desc
  printf "${prompt_color}Hostname${reset_color} (e.g., example.com): "
  read hostname
  printf "${prompt_color}User${reset_color} (default: $USER): "
  read user
  user=${user:-$USER}
  printf "${prompt_color}Port${reset_color} (default: 22): "
  read port
  port=${port:-22}
  printf "${prompt_color}Use password authentication?${reset_color} [y/N]: "
  read use_password

  if [[ "${use_password:l}" == "y" ]]; then
    printf "${prompt_color}Password${reset_color} (will be stored encrypted): "
    read -s password
    echo
    if [[ -n "$password" ]]; then
      password_encoded=$(echo -n "$password" | base64)
    fi
  else
    printf "${prompt_color}Identity file${reset_color} (optional, e.g., ~/.ssh/id_rsa): "
    read identity_file
  fi

  printf "${prompt_color}Need ProxyCommand?${reset_color} [y/N]: "
  read need_proxy

  if [[ "${need_proxy:l}" == "y" ]]; then
    printf "${prompt_color}Proxy Host${reset_color} (e.g., jumpserver.com): "
    read proxy_host
    printf "${prompt_color}Proxy User${reset_color} (default: $USER): "
    read proxy_user
    proxy_user=${proxy_user:-$USER}
  fi

  config_entry="\n# Added on $(date '+%Y-%m-%d %H:%M:%S')"
  config_entry+="\nHost $alias"
  config_entry+="\n    HostName $hostname"
  config_entry+="\n    User $user"
  if [[ -n "$port" ]]; then
    config_entry+="\n    Port $port"
  fi
  if [[ -n "$desc" ]]; then
    config_entry+="\n    #_Desc $desc"
  fi
  if [[ -n "$password_encoded" ]]; then
    config_entry+="\n    #_Password $password_encoded"
  fi
  if [[ -n "$identity_file" ]]; then
    config_entry+="\n    IdentityFile $identity_file"
  fi
  if [[ "${need_proxy:l}" == "y" && -n "$proxy_host" && -n "$proxy_user" ]]; then
    config_entry+="\n    ProxyCommand ssh -q -W %h:%p ${proxy_user}@${proxy_host}"
  fi

  if [[ -f "$SSH_CONFIG_FILE" ]]; then
    echo -e "$config_entry" >> "$SSH_CONFIG_FILE"
    printf "${prompt_color}SSH config added successfully!${reset_color}\n"
  else
    printf "${prompt_color}Creating new SSH config file...${reset_color}\n"
    echo -e "$config_entry" > "$SSH_CONFIG_FILE"
    chmod 600 "$SSH_CONFIG_FILE"
  fi
}

_fzf_list_generator() {
  local header host_list

  if [ -n "$1" ]; then
    host_list="$1"
  else
    host_list=$(_ssh_host_list)
  fi

  header="
Alias|->|Hostname|User|Desc
─────|──|────────|────|────
"

  host_list="${header}\n${host_list}"

  echo $host_list | command column -t -s '|'
}

_set_lbuffer() {
  local result selected_host connect_cmd is_fzf_result
  result="$1"
  is_fzf_result="$2"

  if [ "$is_fzf_result" = false ] ; then
    result=$(cut -f 1 -d "|" <<< ${result})
  fi

  selected_host=$(cut -f 1 -d " " <<< ${result})
  connect_cmd="ssh ${selected_host}"

  LBUFFER="$connect_cmd"
}

fzf_complete_ssh() {
  local tokens cmd result selected_host
  setopt localoptions noshwordsplit noksh_arrays noposixbuiltins

  tokens=(${(z)LBUFFER})
  cmd=${tokens[1]}

  if [[ "$LBUFFER" =~ "^ *ssh$" ]]; then
    zle ${fzf_ssh_default_completion:-expand-or-complete}
  elif [[ "$cmd" == "ssh" ]]; then
    result=$(_ssh_host_list ${tokens[2, -1]})
    fuzzy_input="${LBUFFER#"$tokens[1] "}"

    if [ -z "$result" ]; then
      zle ${fzf_ssh_default_completion:-expand-or-complete}
      return
    fi

    if [ $(echo $result | wc -l) -eq 1 ]; then
      _set_lbuffer $result false
      zle reset-prompt
      # zle redisplay
      return
    fi

    result=$(_fzf_list_generator $result | fzf \
      --height 40% \
      --ansi \
      --border \
      --cycle \
      --info=inline \
      --header-lines=2 \
      --reverse \
      --prompt='SSH Remote > ' \
      --query=$fuzzy_input \
      --no-separator \
      --bind 'shift-tab:up,tab:down,bspace:backward-delete-char/eof' \
      --preview 'ssh -T -G $(cut -f 1 -d " " <<< {}) | grep -i -E "^User |^HostName |^Port |^ControlMaster |^ForwardAgent |^LocalForward |^IdentityFile |^RemoteForward |^ProxyCommand |^ProxyJump " | column -t' \
      --preview-window=right:40%
    )

    if [ -n "$result" ]; then
      _set_lbuffer $result true
      zle accept-line
    fi

    zle reset-prompt
    # zle redisplay

  # Fall back to default completion
  else
    zle ${fzf_ssh_default_completion:-expand-or-complete}
  fi
}


[ -z "$fzf_ssh_default_completion" ] && {
  binding=$(bindkey '^I')
  [[ $binding =~ 'undefined-key' ]] || fzf_ssh_default_completion=$binding[(s: :w)2]
  unset binding
}


zle -N fzf_complete_ssh
bindkey '^I' fzf_complete_ssh

# Set up aliases for SSH config management
alias sshadd='_add_ssh_config'
alias sshrm='_ssh_remove_config'
alias sshmod='_ssh_modify_config'

# Remove SSH config entry
_ssh_remove_config() {
  local host=$1
  local temp_file=$(mktemp)
  
  # If no host specified, use fzf to select one
  if [[ -z "$host" ]]; then
    host=$(_fzf_list_generator | fzf \
      --height 40% \
      --ansi \
      --border \
      --cycle \
      --info=inline \
      --header-lines=2 \
      --reverse \
      --prompt='Select host to remove > ' \
      --no-separator \
      --preview 'ssh -T -G $(cut -f 1 -d " " <<< {}) | grep -i -E "^User |^HostName |^Port |^ControlMaster |^ForwardAgent |^LocalForward |^IdentityFile |^RemoteForward |^ProxyCommand |^ProxyJump " | column -t' \
      --preview-window=right:40% | cut -f 1 -d " "
    )
    
    if [[ -z "$host" ]]; then
      echo "No host selected"
      return 1
    fi
  fi

  # Create a backup before modification
  cp "$SSH_CONFIG_FILE" "${SSH_CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"

  # Remove the host block from config
  awk -v host="$host" '
    BEGIN { in_block = 0; skip_block = 0 }
    $0 ~ "^Host[[:space:]]+" host "$" { in_block = 1; skip_block = 1; next }
    in_block && /^Host / { in_block = 0; skip_block = 0 }
    !skip_block { print }
  ' "$SSH_CONFIG_FILE" > "$temp_file"

  if diff "$SSH_CONFIG_FILE" "$temp_file" > /dev/null; then
    echo "Host '$host' not found in config"
    rm "$temp_file"
    return 1
  fi

  mv "$temp_file" "$SSH_CONFIG_FILE"
  echo "Successfully removed host '$host' from config"
}

# Modify SSH config entry
_ssh_modify_config() {
  local host=$1
  local temp_file=$(mktemp)
  local prompt_color="\033[00;34m"
  local reset_color="\033[0m"
  
  # If no host specified, use fzf to select one
  if [[ -z "$host" ]]; then
    host=$(_fzf_list_generator | fzf \
      --height 40% \
      --ansi \
      --border \
      --cycle \
      --info=inline \
      --header-lines=2 \
      --reverse \
      --prompt='Select host to modify > ' \
      --no-separator \
      --preview 'ssh -T -G $(cut -f 1 -d " " <<< {}) | grep -i -E "^User |^HostName |^Port |^ControlMaster |^ForwardAgent |^LocalForward |^IdentityFile |^RemoteForward |^ProxyCommand |^ProxyJump " | column -t' \
      --preview-window=right:40% | cut -f 1 -d " "
    )
    
    if [[ -z "$host" ]]; then
      echo "No host selected"
      return 1
    fi
  fi

  # Check if host exists
  if ! grep -q "^Host[[:space:]]\+$host$" "$SSH_CONFIG_FILE"; then
    echo "Host '$host' not found in config"
    return 1
  fi

  # Create a backup before modification
  cp "$SSH_CONFIG_FILE" "${SSH_CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"

  # Extract current config
  local current_config=$(awk -v host="$host" '
    BEGIN { in_block = 0 }
    $0 ~ "^Host[[:space:]]+" host "$" { in_block = 1; print; next }
    in_block && /^Host / { in_block = 0 }
    in_block { print }
  ' "$SSH_CONFIG_FILE")

  # Parse current values
  local current_hostname=$(echo "$current_config" | awk '/^[[:space:]]*HostName/ { print $2 }')
  local current_user=$(echo "$current_config" | awk '/^[[:space:]]*User/ { print $2 }')
  local current_port=$(echo "$current_config" | awk '/^[[:space:]]*Port/ { print $2 }')
  local current_desc=$(echo "$current_config" | awk '/^[[:space:]]*#_Desc/ { $1=""; sub(/^[[:space:]]+/, ""); print }')
  local current_password=$(echo "$current_config" | awk '/^[[:space:]]*#_Password/ { print $2 }')
  local current_identity=$(echo "$current_config" | awk '/^[[:space:]]*IdentityFile/ { print $2 }')
  local current_proxy=$(echo "$current_config" | grep "^[[:space:]]*ProxyCommand")

  # Prompt for new values
  printf "${prompt_color}Hostname${reset_color} (current: $current_hostname): "
  read hostname
  hostname=${hostname:-$current_hostname}

  printf "${prompt_color}User${reset_color} (current: $current_user): "
  read user
  user=${user:-$current_user}

  printf "${prompt_color}Port${reset_color} (current: $current_port): "
  read port
  port=${port:-$current_port}

  printf "${prompt_color}Description${reset_color} (current: $current_desc): "
  read desc
  desc=${desc:-$current_desc}

  printf "${prompt_color}Change password?${reset_color} [y/N]: "
  read change_password
  if [[ "${change_password:l}" == "y" ]]; then
    printf "${prompt_color}New Password${reset_color} (will be stored encrypted): "
    read -s password
    echo
    if [[ -n "$password" ]]; then
      password_encoded=$(echo -n "$password" | base64)
    fi
  else
    password_encoded=$current_password
  fi

  printf "${prompt_color}Identity file${reset_color} (current: $current_identity): "
  read identity_file
  identity_file=${identity_file:-$current_identity}

  printf "${prompt_color}Need ProxyCommand?${reset_color} [y/N]: "
  read need_proxy
  if [[ "${need_proxy:l}" == "y" ]]; then
    printf "${prompt_color}Proxy Host${reset_color}: "
    read proxy_host
    printf "${prompt_color}Proxy User${reset_color} (default: $USER): "
    read proxy_user
    proxy_user=${proxy_user:-$USER}
  fi

  # Remove old config
  _ssh_remove_config "$host"

  # Add new config
  config_entry="\n# Modified on $(date '+%Y-%m-%d %H:%M:%S')"
  config_entry+="\nHost $host"
  config_entry+="\n    HostName $hostname"
  config_entry+="\n    User $user"
  if [[ -n "$port" ]]; then
    config_entry+="\n    Port $port"
  fi
  if [[ -n "$desc" ]]; then
    config_entry+="\n    #_Desc $desc"
  fi
  if [[ -n "$password_encoded" ]]; then
    config_entry+="\n    #_Password $password_encoded"
  fi
  if [[ -n "$identity_file" ]]; then
    config_entry+="\n    IdentityFile $identity_file"
  fi
  if [[ "${need_proxy:l}" == "y" && -n "$proxy_host" && -n "$proxy_user" ]]; then
    config_entry+="\n    ProxyCommand ssh -q -W %h:%p ${proxy_user}@${proxy_host}"
  fi

  echo -e "$config_entry" >> "$SSH_CONFIG_FILE"
  printf "${prompt_color}SSH config modified successfully!${reset_color}\n"
}

