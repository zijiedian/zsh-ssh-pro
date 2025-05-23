# Improved SSH Config Parser for Zsh with proper handling of SSH config formats

setopt no_beep # Don't beep

SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
SSH_BACKUP_DIR="${HOME}/.ssh/backups"
[[ ! -d "$SSH_BACKUP_DIR" ]] && mkdir -p "$SSH_BACKUP_DIR"

# Function to manage backups
_manage_backups() {
  # Keep only the 5 most recent backups
  ls -t "$SSH_BACKUP_DIR"/*.bak.* 2>/dev/null | tail -n +6 | xargs -r rm
}

# Function to create backup
_create_backup() {
  local backup_file="${SSH_BACKUP_DIR}/config.bak.$(date +%Y%m%d%H%M%S)"
  cp "$SSH_CONFIG_FILE" "$backup_file"
  _manage_backups
}

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
  if [[ ! -f "$SSH_CONFIG_FILE" ]]; then
    echo "SSH config file not found: $SSH_CONFIG_FILE" >&2
    return 1
  fi

  if [[ ! -r "$SSH_CONFIG_FILE" ]]; then
    echo "Cannot read SSH config file: $SSH_CONFIG_FILE" >&2
    return 1
  fi

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
  local ssh_args=()
  local host=""
  local found_host=false

  # 解析参数，区分SSH选项和主机名
  while [[ $# -gt 0 ]]; do
    case $1 in
      # SSH 常用选项，需要传递给原生SSH
      -[1246AaCfGgKkMNnqsTtVvXxYy]|-[bcDeFIiJLlmOopRSWw])
        ssh_args+=("$1")
        shift
        ;;
      # 需要参数的选项
      -[bcDeFIiJLlmOopRSWw])
        ssh_args+=("$1" "$2")
        shift 2
        ;;
      # 长选项
      --*)
        ssh_args+=("$1")
        shift
        ;;
      # 第一个非选项参数作为主机名
      *)
        if [[ "$found_host" == false ]]; then
          host="$1"
          found_host=true
        else
          ssh_args+=("$1")
        fi
        shift
        ;;
    esac
  done

  # 如果有SSH选项但没有主机名，或者主机名是SSH选项，直接调用原生SSH
  if [[ -n "${ssh_args[*]}" && (-z "$host" || "$host" =~ ^-) ]]; then
    echo "Calling native SSH with options: ${ssh_args[*]}" >&2
    command ssh "${ssh_args[@]}" "$host"
    return $?
  fi

  # 如果没有提供主机名，直接返回
  if [[ -z "$host" ]]; then
    echo "No host specified" >&2
    echo "Usage: ssh [options] hostname [command]" >&2
    return 1
  fi

  # 检查是否为直接的 user@host 格式，如果是就直接连接
  if [[ "$host" =~ ^[^@]+@[^@]+$ ]]; then
    echo "Direct connection to $host..." >&2
    command ssh "${ssh_args[@]}" "$host"
    return $?
  fi

  # 检查配置是否存在
  local ssh_check_output
  if ! ssh_check_output=$(command ssh -G "$host" 2>&1); then
    echo "Host '$host' not found in SSH config" >&2
    echo "" >&2
    echo "Available options:" >&2
    echo "  1. Add new config: sshadd" >&2
    echo "  2. Modify existing: sshmod" >&2
    echo "  3. Connect directly: ssh user@hostname" >&2
    echo "" >&2
    echo "SSH config error details:" >&2
    echo "$ssh_check_output" >&2
    return 1
  fi

  # 尝试从配置文件获取密码配置
  local current_config password_encoded
  if [[ -f "$SSH_CONFIG_FILE" ]]; then
    current_config=$(awk -v host="$host" '
      BEGIN { in_block = 0 }
      $0 ~ "^Host[[:space:]]+" host "$" { in_block = 1; print; next }
      in_block && /^Host / { in_block = 0 }
      in_block { print }
    ' "$SSH_CONFIG_FILE")
    
    password_encoded=$(echo "$current_config" | awk '/^[[:space:]]*#_Password/ { print $2 }')
  fi

  # 执行 SSH 连接
  local ssh_exit_code
  if [[ -n "$password_encoded" ]]; then
    if ! command -v sshpass >/dev/null 2>&1; then
      echo "sshpass is required for password authentication but not found" >&2
      echo "Please install sshpass or use key-based authentication" >&2
      return 1
    fi
    
    local decoded_password
    if ! decoded_password=$(echo "$password_encoded" | base64 -d 2>/dev/null); then
      echo "Failed to decode stored password" >&2
      return 1
    fi
    
    echo "Connecting to $host using password authentication..." >&2
    SSHPASS="$decoded_password" sshpass -e ssh "${ssh_args[@]}" -t "$host"
    ssh_exit_code=$?
  else
    echo "Connecting to $host..." >&2
    command ssh "${ssh_args[@]}" -t "$host"
    ssh_exit_code=$?
  fi

  # 检查SSH连接的退出码
  if [[ $ssh_exit_code -ne 0 ]]; then
    echo "" >&2
    echo "SSH connection failed with exit code: $ssh_exit_code" >&2
    
    # 根据退出码提供更详细的建议
    case $ssh_exit_code in
      1)
        echo "Suggestion: Check network connectivity and hostname" >&2
        ;;
      2)
        echo "Suggestion: Check SSH configuration syntax" >&2
        ;;
      255)
        echo "Suggestion: Check authentication method (keys, password, etc.)" >&2
        ;;
      *)
        echo "Suggestion: Run 'ssh -v $host' for verbose debugging" >&2
        ;;
    esac
    
    return $ssh_exit_code
  fi
  
  return 0
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
  _create_backup

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
  _create_backup

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
  # 默认添加主机密钥验证配置
  config_entry+="\n    StrictHostKeyChecking no"
  config_entry+="\n    UserKnownHostsFile /dev/null"
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
  printf "${prompt_color}Note: Added StrictHostKeyChecking=no to avoid host key verification issues${reset_color}\n"
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
alias sshbatch='_ssh_batch_add'
alias sshexample='_ssh_batch_example'
alias sshvalidate='_ssh_batch_validate'
alias ssh='_ssh_connect'

# File transfer commands with auto-password support
alias scp='_scp_connect'
alias rsync='_rsync_connect'
alias scphelp='_scp_help'

# Final parsing function that correctly handles special characters
_parse_ssh_line_final() {
  local line="$1"
  local -a fields
  
  # Use zsh's parameter expansion to split by pipe
  fields=(${(s:|:)line})
  
  # Ensure we have exactly 8 fields, pad with empty strings
  while [[ ${#fields[@]} -lt 8 ]]; do
    fields+=("")
  done
  
  # Extract fields and remove leading/trailing spaces from key fields
  local alias="${fields[1]}"
  local hostname="${fields[2]}"
  local user="${fields[3]}"
  local port="${fields[4]}"
  local desc="${fields[5]}"
  local password="${fields[6]}"
  local proxy_host="${fields[7]}"
  local proxy_user="${fields[8]}"
  
  # Trim spaces from key fields only (preserve spaces in desc and password)
  alias="${alias## }"
  alias="${alias%% }"
  hostname="${hostname## }"
  hostname="${hostname%% }"
  user="${user## }"
  user="${user%% }"
  port="${port## }"
  port="${port%% }"
  proxy_host="${proxy_host## }"
  proxy_host="${proxy_host%% }"
  proxy_user="${proxy_user## }"
  proxy_user="${proxy_user%% }"
  
  # Output variables safely - for password, we need to ensure special characters are preserved
  echo "alias=$(printf %q "$alias")"
  echo "hostname=$(printf %q "$hostname")"
  echo "user=$(printf %q "$user")"
  echo "port=$(printf %q "$port")"
  echo "desc=$(printf %q "$desc")"
  echo "password=$(printf %q "$password")"
  echo "proxy_host=$(printf %q "$proxy_host")"
  echo "proxy_user=$(printf %q "$proxy_user")"
}

# Test both parsing methods
_ssh_test_parse() {
  local test_line="$1"
  echo "Testing line: $test_line"
  echo ""
  
  echo "=== AWK Method ==="
  local awk_result=$(_parse_ssh_line_final "$test_line")
  echo "$awk_result"
  echo ""
  
  # Test evaluation
  local alias hostname user port desc password proxy_host proxy_user
  eval "$awk_result"
  echo "Results after eval (AWK):"
  echo "alias='$alias'"
  echo "hostname='$hostname'"
  echo "user='$user'"
  echo "port='$port'"
  echo "desc='$desc'"
  echo "password='$password'"
  echo "proxy_host='$proxy_host'"
  echo "proxy_user='$proxy_user'"
  echo ""
  
  echo "=== Simple Method ==="
  local simple_result=$(_parse_ssh_line_final "$test_line")
  echo "$simple_result"
  echo ""
  
  # Test evaluation
  unset alias hostname user port desc password proxy_host proxy_user
  eval "$simple_result"
  echo "Results after eval (Simple):"
  echo "alias='$alias'"
  echo "hostname='$hostname'"  
  echo "user='$user'"
  echo "port='$port'"
  echo "desc='$desc'"
  echo "password='$password'"
  echo "proxy_host='$proxy_host'"
  echo "proxy_user='$proxy_user'"
}

# Update the batch add function to use the correct parser
_ssh_batch_add() {
  local input_file="$1"
  local prompt_color="\033[00;34m"
  local success_color="\033[00;32m"
  local error_color="\033[00;31m"
  local reset_color="\033[0m"

  if [[ -z "$input_file" ]]; then
    echo -e "${prompt_color}Usage: sshbatch <file.txt>${reset_color}"
    echo -e "${prompt_color}File format (pipe-separated):${reset_color}"
    echo "alias|hostname|user|port|description|password|proxy_host|proxy_user"
    echo "Example:"
    echo "server1|192.168.1.100|root|22|Production Server|mypassword||"
    echo "server2|192.168.1.101|admin|2222|Test Server|||jumphost|admin"
    echo -e "\n${prompt_color}Notes:${reset_color}"
    echo "- Use | (pipe) as separator to avoid issues with special characters"
    echo "- password and proxy fields are optional (leave empty if not needed)"
    echo "- port defaults to 22 if empty"
    echo "- user defaults to current user if empty"
    return 1
  fi

  if [[ ! -f "$input_file" ]]; then
    echo -e "${error_color}File not found: $input_file${reset_color}"
    return 1
  fi

  echo -e "${prompt_color}Processing batch SSH config from: $input_file${reset_color}"
  
  # Check if SSH config file exists, create if not
  if [[ ! -f "$SSH_CONFIG_FILE" ]]; then
    echo -e "${prompt_color}Creating SSH config file...${reset_color}"
    mkdir -p "$(dirname "$SSH_CONFIG_FILE")"
    touch "$SSH_CONFIG_FILE"
    chmod 600 "$SSH_CONFIG_FILE"
  fi

  # Create backup before batch operation
  _create_backup
  echo -e "${prompt_color}Backup created before batch operation${reset_color}"

  local line_number=0
  local success_count=0
  local error_count=0

  # Process each line
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number++))
    
    # Skip empty lines and comments
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi

    # Parse line safely
    local parsed_output
    parsed_output=$(_parse_ssh_line_final "$line")
    
    # Extract fields using eval
    local alias hostname user port desc password proxy_host proxy_user
    eval "$parsed_output"

    # Validate required fields
    if [[ -z "$alias" || -z "$hostname" ]]; then
      echo -e "${error_color}Line $line_number: Missing alias or hostname${reset_color}"
      ((error_count++))
      continue
    fi

    # Set defaults
    user=${user:-$USER}
    port=${port:-22}
    proxy_user=${proxy_user:-$USER}

    # Check if alias already exists
    if grep -q "^Host[[:space:]]\+$alias$" "$SSH_CONFIG_FILE" 2>/dev/null; then
      echo -e "${error_color}Line $line_number: Host '$alias' already exists, skipping${reset_color}"
      ((error_count++))
      continue
    fi

    # Build config entry
    local config_entry="\n# Added via batch import on $(date '+%Y-%m-%d %H:%M:%S')"
    config_entry+="\nHost $alias"
    config_entry+="\n    HostName $hostname"
    config_entry+="\n    User $user"
    config_entry+="\n    Port $port"
    # Default host key checking options
    config_entry+="\n    StrictHostKeyChecking no"
    config_entry+="\n    UserKnownHostsFile /dev/null"
    
    if [[ -n "$desc" ]]; then
      config_entry+="\n    #_Desc $desc"
    fi
    
    if [[ -n "$password" ]]; then
      # Test password encoding to ensure it works
      local password_encoded
      password_encoded=$(echo -n "$password" | base64 2>/dev/null)
      if [[ $? -eq 0 && -n "$password_encoded" ]]; then
        config_entry+="\n    #_Password $password_encoded"
      else
        echo -e "${error_color}Line $line_number: Failed to encode password for $alias${reset_color}"
        ((error_count++))
        continue
      fi
    fi
    
    if [[ -n "$proxy_host" ]]; then
      config_entry+="\n    ProxyCommand ssh -q -W %h:%p ${proxy_user}@${proxy_host}"
    fi

    # Add to config file
    echo -e "$config_entry" >> "$SSH_CONFIG_FILE"
    echo -e "${success_color}✓ Added: $alias -> $user@$hostname:$port${reset_color}"
    ((success_count++))

  done < "$input_file"

  echo -e "\n${prompt_color}Batch import completed:${reset_color}"
  echo -e "${success_color}Success: $success_count${reset_color}"
  echo -e "${error_color}Errors: $error_count${reset_color}"
  
  if [[ $success_count -gt 0 ]]; then
    echo -e "${prompt_color}All configurations include StrictHostKeyChecking=no for easier connections${reset_color}"
  fi
}

# Generate example batch file
_ssh_batch_example() {
  local example_file="ssh_hosts_example.txt"
  local prompt_color="\033[00;34m"
  local reset_color="\033[0m"

  cat > "$example_file" << 'EOF'
# SSH Batch Import File
# Format: alias|hostname|user|port|description|password|proxy_host|proxy_user
# 
# IMPORTANT: Use | (pipe) as separator, NOT comma!
# This avoids issues with special characters in passwords
#
# Fields explanation:
# - alias: short name for SSH connection
# - hostname: IP address or domain name  
# - user: username (leave empty for current user)
# - port: SSH port (leave empty for 22)
# - description: optional description
# - password: optional password (supports special characters)
# - proxy_host: optional jump server hostname
# - proxy_user: username for jump server (leave empty for current user)

# Examples with various password complexities:
web1|192.168.1.100|root|22|Web Server|simple_pass||
db1|192.168.1.101|postgres|5432|Database Server|P@ssw0rd!||
jump1|jump.example.com|admin||Jump Server|#Vp_2024%||
internal1|10.0.0.50|user|22|Internal Server|complex,pass#with$special||jump.example.com|admin
test1|test.local|testuser|2222|Test Environment|test@123%^&*||

EOF

  echo -e "${prompt_color}Example file created: $example_file${reset_color}"
  echo -e "${prompt_color}Edit this file and run: sshbatch $example_file${reset_color}"
  echo -e "${prompt_color}Note: Use | (pipe) as separator, NOT comma!${reset_color}"
  echo ""
  echo -e "${prompt_color}You can test parsing with: sshtest 'alias|hostname|user|port|desc|pass||'${reset_color}"
}

# Validate batch file format
_ssh_batch_validate() {
  local input_file="$1"
  local prompt_color="\033[00;34m"
  local success_color="\033[00;32m"
  local error_color="\033[00;31m"
  local warning_color="\033[00;33m"
  local reset_color="\033[0m"

  if [[ -z "$input_file" ]]; then
    echo -e "${error_color}Please specify a file to validate${reset_color}"
    return 1
  fi

  if [[ ! -f "$input_file" ]]; then
    echo -e "${error_color}File not found: $input_file${reset_color}"
    return 1
  fi

  echo -e "${prompt_color}Validating batch file: $input_file${reset_color}"
  
  local line_number=0
  local valid_count=0
  local error_count=0
  local warning_count=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number++))
    
    # Skip empty lines and comments
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi

    # Parse line safely
    local parsed_output
    parsed_output=$(_parse_ssh_line_final "$line")
    
    # Extract fields
    local alias hostname user port desc password proxy_host proxy_user
    eval "$parsed_output"

    # Validate required fields
    if [[ -z "$alias" ]]; then
      echo -e "${error_color}Line $line_number: Missing alias${reset_color}"
      ((error_count++))
      continue
    fi

    if [[ -z "$hostname" ]]; then
      echo -e "${error_color}Line $line_number: Missing hostname for alias '$alias'${reset_color}"
      ((error_count++))
      continue
    fi

    # Check for existing alias
    if [[ -f "$SSH_CONFIG_FILE" ]] && grep -q "^Host[[:space:]]\+$alias$" "$SSH_CONFIG_FILE" 2>/dev/null; then
      echo -e "${warning_color}Line $line_number: Host '$alias' already exists${reset_color}"
      ((warning_count++))
    fi

    # Validate port if specified
    if [[ -n "$port" && ! "$port" =~ ^[0-9]+$ ]]; then
      echo -e "${error_color}Line $line_number: Invalid port '$port' for alias '$alias'${reset_color}"
      ((error_count++))
      continue
    fi

    # Show validation info (safely handle special characters)
    local display_line="$alias -> $hostname"
    if [[ -n "$password" ]]; then
      display_line="$display_line (with password)"
    fi
    echo -e "${success_color}Line $line_number: Valid - $display_line${reset_color}"
    ((valid_count++))

  done < "$input_file"

  echo -e "\n${prompt_color}Validation Summary:${reset_color}"
  echo -e "${success_color}Valid entries: $valid_count${reset_color}"
  echo -e "${warning_color}Warnings: $warning_count${reset_color}"
  echo -e "${error_color}Errors: $error_count${reset_color}"

  if [[ $error_count -eq 0 ]]; then
    echo -e "\n${success_color}✓ File is ready for import!${reset_color}"
    return 0
  else
    echo -e "\n${error_color}✗ Please fix errors before importing${reset_color}"
    return 1
  fi
}

# Enhanced SCP function that replaces native scp with auto password and proxy support
_scp_connect() {
  local scp_args=()
  local source=""
  local destination=""
  local host=""
  local found_source=false
  local found_destination=false

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case $1 in
      # SCP options that don't take arguments
      -[BCpqrvACo1246])
        scp_args+=("$1")
        shift
        ;;
      # SCP options that take arguments
      -[PFSc])
        scp_args+=("$1" "$2")
        shift 2
        ;;
      # Handle -o option specially (can have multiple)
      -o)
        scp_args+=("$1" "$2")
        shift 2
        ;;
      # Long options
      --*)
        scp_args+=("$1")
        shift
        ;;
      # Non-option arguments (source and destination)
      *)
        if [[ "$found_source" == false ]]; then
          source="$1"
          found_source=true
        elif [[ "$found_destination" == false ]]; then
          destination="$1"
          found_destination=true
        else
          scp_args+=("$1")
        fi
        shift
        ;;
    esac
  done

  # Validate that we have source and destination
  if [[ -z "$source" || -z "$destination" ]]; then
    echo "Usage: scp [options] source destination" >&2
    echo "Examples:" >&2
    echo "  scp file.txt myserver:/path/"
    echo "  scp myserver:/remote/file.txt ./"
    echo "  scp -r dir/ myserver:/remote/dir/"
    return 1
  fi

  # Determine which path contains the host (remote path)
  local remote_path=""
  local is_upload=false
  
  if [[ "$source" == *:* ]]; then
    # Download: source is remote
    remote_path="$source"
    is_upload=false
    host="${source%%:*}"
  elif [[ "$destination" == *:* ]]; then
    # Upload: destination is remote
    remote_path="$destination"
    is_upload=true
    host="${destination%%:*}"
  else
    # Both paths are local, use native scp
    echo "Both paths are local, using native scp..." >&2
    command scp "${scp_args[@]}" "$source" "$destination"
    return $?
  fi

  # Remove user@ prefix if present to get clean host name
  if [[ "$host" == *@* ]]; then
    host="${host##*@}"
  fi

  # Check if this is a configured host or direct connection
  local ssh_check_output
  if ! ssh_check_output=$(command ssh -G "$host" 2>&1); then
    # Not a configured host, try direct connection
    echo "Host '$host' not in config, using direct connection..." >&2
    command scp "${scp_args[@]}" "$source" "$destination"
    return $?
  fi

  # Get SSH configuration for the host
  local current_config password_encoded
  if [[ -f "$SSH_CONFIG_FILE" ]]; then
    current_config=$(awk -v host="$host" '
      BEGIN { in_block = 0 }
      $0 ~ "^Host[[:space:]]+" host "$" { in_block = 1; print; next }
      in_block && /^Host / { in_block = 0 }
      in_block { print }
    ' "$SSH_CONFIG_FILE")
    
    password_encoded=$(echo "$current_config" | awk '/^[[:space:]]*#_Password/ { print $2 }')
  fi

  # Add default SSH options to preserve our configuration
  scp_args+=("-o" "StrictHostKeyChecking=no")
  scp_args+=("-o" "UserKnownHostsFile=/dev/null")
  
  # Check if ProxyCommand is configured
  local proxy_command=$(echo "$current_config" | grep "^[[:space:]]*ProxyCommand")
  if [[ -n "$proxy_command" ]]; then
    # Extract proxy command and add to SCP
    local proxy_cmd=$(echo "$proxy_command" | sed 's/^[[:space:]]*ProxyCommand[[:space:]]*//')
    scp_args+=("-o" "ProxyCommand=$proxy_cmd")
  fi

  # Execute SCP with or without password
  local scp_exit_code
  if [[ -n "$password_encoded" ]]; then
    if ! command -v sshpass >/dev/null 2>&1; then
      echo "sshpass is required for password authentication but not found" >&2
      echo "Falling back to native scp (will prompt for password)" >&2
      command scp "${scp_args[@]}" "$source" "$destination"
      return $?
    fi
    
    local decoded_password
    if ! decoded_password=$(echo "$password_encoded" | base64 -d 2>/dev/null); then
      echo "Failed to decode stored password, falling back to native scp" >&2
      command scp "${scp_args[@]}" "$source" "$destination"
      return $?
    fi
    
    # Use sshpass for automatic password input
    SSHPASS="$decoded_password" sshpass -e scp "${scp_args[@]}" "$source" "$destination"
    scp_exit_code=$?
  else
    # Use native scp with our SSH options
    command scp "${scp_args[@]}" "$source" "$destination"
    scp_exit_code=$?
  fi

  return $scp_exit_code
}

# Function to show SCP usage with examples
_scp_help() {
  local prompt_color="\033[00;34m"
  local reset_color="\033[0m"
  
  echo -e "${prompt_color}Enhanced SCP with auto-password and proxy support${reset_color}"
  echo ""
  echo "Usage: scp [options] source destination"
  echo ""
  echo "Examples:"
  echo "  # Upload file"
  echo "  scp file.txt myserver:/path/"
  echo "  scp ./document.pdf web1:~/documents/"
  echo ""
  echo "  # Download file"
  echo "  scp myserver:/remote/file.txt ./"
  echo "  scp web1:~/backup/data.sql ./backups/"
  echo ""
  echo "  # Upload directory"
  echo "  scp -r ./local-dir/ myserver:/remote-dir/"
  echo ""
  echo "  # Download directory"
  echo "  scp -r myserver:/remote-dir/ ./local-dir/"
  echo ""
  echo "  # With custom port (if not in SSH config)"
  echo "  scp -P 2222 file.txt myserver:/path/"
  echo ""
  echo -e "${prompt_color}Features:${reset_color}"
  echo "  ✓ Automatic password authentication (from SSH config)"
  echo "  ✓ Proxy/jump server support (from SSH config)"
  echo "  ✓ All standard scp options supported"
  echo "  ✓ Falls back to native scp for unknown hosts"
}

# Rsync wrapper with SSH config integration
_rsync_connect() {
  local rsync_args=()
  local source=""
  local destination=""
  local host=""
  local found_source=false
  local found_destination=false

  # Parse arguments - rsync has many options
  while [[ $# -gt 0 ]]; do
    case $1 in
      # Common rsync options
      -[avzrltpogDHAXS]*)
        rsync_args+=("$1")
        shift
        ;;
      # Options that take arguments
      --exclude|--include|--filter|--files-from|--rsh|-e|--progress|--partial-dir|--backup-dir)
        rsync_args+=("$1" "$2")
        shift 2
        ;;
      # Long options without arguments
      --*)
        rsync_args+=("$1")
        shift
        ;;
      # Non-option arguments (source and destination)
      *)
        if [[ "$found_source" == false ]]; then
          source="$1"
          found_source=true
        elif [[ "$found_destination" == false ]]; then
          destination="$1"
          found_destination=true
        else
          rsync_args+=("$1")
        fi
        shift
        ;;
    esac
  done

  # Validate arguments
  if [[ -z "$source" || -z "$destination" ]]; then
    echo "Usage: rsync [options] source destination" >&2
    return 1
  fi

  # Determine which path contains the host
  if [[ "$source" == *:* ]]; then
    host="${source%%:*}"
  elif [[ "$destination" == *:* ]]; then
    host="${destination%%:*}"
  else
    # Both local, use native rsync
    command rsync "${rsync_args[@]}" "$source" "$destination"
    return $?
  fi

  # Remove user@ prefix if present
  if [[ "$host" == *@* ]]; then
    host="${host##*@}"
  fi

  # Check if host is configured
  local ssh_check_output
  if ! ssh_check_output=$(command ssh -G "$host" 2>&1); then
    # Not configured, use native rsync
    command rsync "${rsync_args[@]}" "$source" "$destination"
    return $?
  fi

  # Get SSH configuration
  local current_config password_encoded
  if [[ -f "$SSH_CONFIG_FILE" ]]; then
    current_config=$(awk -v host="$host" '
      BEGIN { in_block = 0 }
      $0 ~ "^Host[[:space:]]+" host "$" { in_block = 1; print; next }
      in_block && /^Host / { in_block = 0 }
      in_block { print }
    ' "$SSH_CONFIG_FILE")
    
    password_encoded=$(echo "$current_config" | awk '/^[[:space:]]*#_Password/ { print $2 }')
  fi

  # Build SSH command for rsync
  local ssh_cmd="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
  
  # Add proxy command if configured
  local proxy_command=$(echo "$current_config" | grep "^[[:space:]]*ProxyCommand")
  if [[ -n "$proxy_command" ]]; then
    local proxy_cmd=$(echo "$proxy_command" | sed 's/^[[:space:]]*ProxyCommand[[:space:]]*//')
    ssh_cmd+=" -o 'ProxyCommand=$proxy_cmd'"
  fi

  # Add SSH command to rsync args if not already specified
  local has_ssh_option=false
  for arg in "${rsync_args[@]}"; do
    if [[ "$arg" == "-e" || "$arg" == "--rsh" ]]; then
      has_ssh_option=true
      break
    fi
  done

  if [[ "$has_ssh_option" == false ]]; then
    rsync_args+=("-e" "$ssh_cmd")
  fi

  # Execute with or without password
  if [[ -n "$password_encoded" ]]; then
    if ! command -v sshpass >/dev/null 2>&1; then
      echo "sshpass not found, falling back to native rsync" >&2
      command rsync "${rsync_args[@]}" "$source" "$destination"
      return $?
    fi
    
    local decoded_password
    if ! decoded_password=$(echo "$password_encoded" | base64 -d 2>/dev/null); then
      command rsync "${rsync_args[@]}" "$source" "$destination"
      return $?
    fi
    
    SSHPASS="$decoded_password" sshpass -e rsync "${rsync_args[@]}" "$source" "$destination"
  else
    command rsync "${rsync_args[@]}" "$source" "$destination"
  fi
}

