#!/bin/bash

# Source common variables and functions
# shellcheck source=./common.sh
# shellcheck disable=SC1091
source "$(dirname "$(realpath "$0")")/common.sh"

# Alias for compatibility - letscerts uses 'warn' instead of 'warning'
warn() {
	warning "$@"
}

print_logo() {
	cat <<EOF
${RED}
 (                 (                (            
 )\ )        *   ) )\ )   (         )\ )  *   )  
(()/(  (   \` )  /((()/(   )\   (   (()/(\` )  /(  
 /(_)) )\   ( )(_))/(_))(((_)  )\   /(_))( )(_)) 
(_))  ((_) (_(_())(_))  )\___ ((_) (_)) (_(_())  
${BLUE}| |   | __||_   _|/ __|((/ __|| __|| _ \|_   _|  
| |__ | _|   | |  \__ \ | (__ | _| |   /  | |    
|____||___|  |_|  |___/  \___||___||_|_\  |_|    
EOF
}

setup() {
	# set default values
	CHALLENGE="dns"
	KEY_SIZE=4096
	STAGING=false
	PRODUCTION=true
	DOMAINS=()
	EMAIL=""
	local base_dir="$HOME/.letsencrypt"
	# check if the config directory exists
	if [ ! -d "$base_dir" ]; then
		mkdir -p "$base_dir"
	fi
	CFG_DIR="$base_dir/config"
	# check if the config directory exists
	if [ ! -f "$CFG_DIR" ]; then
		mkdir -p "$CFG_DIR"
	fi
	WORK_DIR="$base_dir/work"
	# check if the work directory exists
	if [ ! -f "$WORK_DIR" ]; then
		mkdir -p "$WORK_DIR"
	fi
	LOG_DIR="$base_dir/log"
	# check if the log directory exists
	if [ ! -f "$LOG_DIR" ]; then
		mkdir -p "$LOG_DIR"
	fi
	# make sure that certbot is installed
	if ! command_exists certbot; then
		error "certbot is not installed"
		# prompt if the user wants to install certbot
		read -p "Do you want to install certbot? [y/n]: " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			install_certbot
		else
			error "certbot is required to run this script, exiting..."
			exit 1
		fi
	fi
}

install_certbot() {
	if ! install_package "certbot"; then
		error "Could not install certbot"
		exit 1
	fi
}

parse_args() {
	# parse arguments
	while [ "$1" != "" ]; do
		case $1 in
		--domains)
			shift
			IFS=' ' read -ra DOMAINS <<<"$1"
			;;
		--email)
			shift
			EMAIL=$1
			;;
		--staging)
			STAGING=true
			;;
		--production)
			PRODUCTION=true
			;;
		--challenge)
			shift
			CHALLENGE=$1
			;;
		--key-size)
			shift
			KEY_SIZE=$1
			;;
		-h | --help)
			usage
			exit
			;;
		*)
			exit 1
			;;
		esac
		shift
	done
}

usage() {
	cat <<EOF
Usage: $(basename "$0") [OPTIONS]
Options:
  -h, --help                  Display this help message
	  --domains               List of domains to make a cert for (space-separated)
	  --email                 Email to use for letsencrypt
	  --staging               Use the staging server (default: false)
	  --production            Use the production server (default: true)
	  --challenge             Challenge type to use (DNS or HTTP, defaults to DNS)
	  --key-size              Size of the key to generate (default: 4096)

EXAMPLES:
  $(basename "$0") --domains example.com www.example.com --email user@example.com
  $(basename "$0") --domains staging.example.com --email user@example.com --staging --challenge DNS --key-size 2028
  $(basename "$0") --domains example.com --email user@example.com --challenge HTTP
EOF
	echo
}

main() {
	print_logo
	echo
	green "Welcome to letscert.sh, setting up..."
	setup
	parse_args "$@"
	local errs=false

	if [ ${#DOMAINS[@]} -eq 0 ]; then
		# echo "No domains specified"
		error "No domains specified"
		errs=true
	fi

	if [ -z "$EMAIL" ]; then
		# echo "No email specified"
		error "No email specified"
		errs=true
	fi
	if [ "$errs" = true ]; then
		echo "Errors found, exiting"
		exit 1
	fi

	if [ "$STAGING" = true ]; then
		SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
	fi

	if [ "$PRODUCTION" = true ]; then
		SERVER="https://acme-v02.api.letsencrypt.org/directory"
	fi

	if [ "$CHALLENGE" = "DNS" ]; then
		CHALLENGE="dns"
	fi

	if [ "$CHALLENGE" = "HTTP" ]; then
		CHALLENGE="http"
	fi

	# print_vars
	certbot certonly --manual --preferred-challenges "$CHALLENGE" \
		--email "$EMAIL" --server "$SERVER" --rsa-key-size="$KEY_SIZE" \
		--agree-tos -d "${DOMAINS[@]}" \
		--config-dir "$CFG_DIR" --work-dir "$WORK_DIR" --logs-dir "$LOG_DIR"

}

# Main script execution
main "$@"
