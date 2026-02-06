#!/bin/bash
#
# Nginx Reverse Proxy Setup with Let's Encrypt (acme.sh + Azure/Cloudflare DNS)
# Configures nginx as a reverse proxy with automatic SSL certificate management
#
# Usage: ./reverse-proxy.sh -c config.conf [-h|--help]
#

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Constants
MARKER_FILE="/etc/nginx/.reverse-proxy-managed"
NGINX_SSL_DIR="/etc/nginx/ssl"
ACME_HOME="/root/.acme.sh"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Show usage/help
show_help() {
    cat <<EOF
Usage: $0 [-c config.conf] [-h|--help]

Nginx reverse proxy with automatic Let's Encrypt SSL certificates.

Options:
  -c config.conf    Config file for initial setup or management
  -h, --help        Show this help message

DNS Providers (set DNS_PROVIDER in config):
  azure       Azure DNS — requires AZURE_TENANT_ID, AZURE_CLIENT_ID,
              AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID, AZURE_DNS_ZONE,
              AZURE_DNS_RESOURCE_GROUP
  cloudflare  Cloudflare DNS — requires CF_TOKEN (API Token with
              Zone:DNS:Edit permission). CF_ACCOUNT_ID and CF_ZONE_ID
              are optional.

Modes:
  Initial setup:  $0 -c config.conf  (when no prior setup exists)
  Management:     $0                  (interactive menu after setup)
EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    CONFIG_FILE=""

    # Check for --help before getopts (getopts doesn't handle long options)
    for arg in "$@"; do
        case "$arg" in
            --help) show_help ;;
        esac
    done

    while getopts "c:h" opt; do
        case $opt in
            c)
                CONFIG_FILE="$OPTARG"
                ;;
            h)
                show_help
                ;;
            \?)
                echo "Usage: $0 [-c config.conf] [-h|--help]"
                exit 1
                ;;
        esac
    done
}

# Load configuration file
load_config() {
    local config_path="$1"
    if [[ -n "$config_path" && -f "$config_path" ]]; then
        log_info "Loading configuration from $config_path"
        source "$config_path"
        return 0
    fi
    return 1
}

# Prompt for missing value
prompt_value() {
    local var_name="$1"
    local prompt_text="$2"
    local is_secret="${3:-false}"
    local current_value="${!var_name:-}"

    if [[ -n "$current_value" ]]; then
        return 0
    fi

    if [[ "$is_secret" == "true" ]]; then
        read -rs -p "$prompt_text: " value
        echo ""
    else
        read -r -p "$prompt_text: " value
    fi

    eval "$var_name='$value'"
}

# Validate required DNS provider parameters
validate_dns_config() {
    local provider="${DNS_PROVIDER:-azure}"

    case "$provider" in
        azure)
            local missing=()

            [[ -z "${AZURE_TENANT_ID:-}" ]] && missing+=("AZURE_TENANT_ID")
            [[ -z "${AZURE_CLIENT_ID:-}" ]] && missing+=("AZURE_CLIENT_ID")
            [[ -z "${AZURE_CLIENT_SECRET:-}" ]] && missing+=("AZURE_CLIENT_SECRET")
            [[ -z "${AZURE_SUBSCRIPTION_ID:-}" ]] && missing+=("AZURE_SUBSCRIPTION_ID")
            [[ -z "${AZURE_DNS_ZONE:-}" ]] && missing+=("AZURE_DNS_ZONE")
            [[ -z "${AZURE_DNS_RESOURCE_GROUP:-}" ]] && missing+=("AZURE_DNS_RESOURCE_GROUP")

            if [[ ${#missing[@]} -gt 0 ]]; then
                log_warn "Missing Azure DNS configuration. Please provide the following:"
                for param in "${missing[@]}"; do
                    case $param in
                        AZURE_CLIENT_SECRET)
                            prompt_value "$param" "  $param" true
                            ;;
                        *)
                            prompt_value "$param" "  $param"
                            ;;
                    esac
                done
            fi
            ;;
        cloudflare)
            if [[ -z "${CF_TOKEN:-}" ]]; then
                log_warn "Missing Cloudflare DNS configuration. Please provide the following:"
                prompt_value "CF_TOKEN" "  CF_TOKEN (API Token with Zone:DNS:Edit)" true
            fi
            ;;
        *)
            log_error "Unknown DNS_PROVIDER: $provider (supported: azure, cloudflare)"
            exit 1
            ;;
    esac

    # Validate ACME email
    if [[ -z "${ACME_EMAIL:-}" ]]; then
        prompt_value "ACME_EMAIL" "Let's Encrypt notification email"
    fi
}

# Parse domain configuration string into arrays
# Format: domain:backend_host:backend_port[:https]
parse_domains() {
    DOMAIN_LIST=()
    BACKEND_HOST_LIST=()
    BACKEND_PORT_LIST=()
    BACKEND_PROTO_LIST=()

    if [[ -z "${NGINX_PROXY_DOMAINS:-}" ]]; then
        return 1
    fi

    while IFS= read -r line; do
        # Skip empty lines and comments
        line=$(echo "$line" | xargs)  # trim whitespace
        [[ -z "$line" || "$line" == \#* ]] && continue

        IFS=':' read -r domain host port proto <<< "$line"

        if [[ -z "$domain" || -z "$host" || -z "$port" ]]; then
            log_warn "Invalid domain config line: $line"
            continue
        fi

        DOMAIN_LIST+=("$domain")
        BACKEND_HOST_LIST+=("$host")
        BACKEND_PORT_LIST+=("$port")
        BACKEND_PROTO_LIST+=("${proto:-http}")
    done <<< "$NGINX_PROXY_DOMAINS"

    if [[ ${#DOMAIN_LIST[@]} -eq 0 ]]; then
        return 1
    fi

    return 0
}

# Get list of deployed domains from nginx sites-available
get_deployed_domains() {
    DEPLOYED_DOMAINS=()
    DEPLOYED_BACKENDS=()

    if [[ ! -d /etc/nginx/sites-available ]]; then
        return
    fi

    for conf in /etc/nginx/sites-available/*.conf; do
        [[ -f "$conf" ]] || continue
        [[ "$(basename "$conf")" == "00-default-redirect.conf" ]] && continue

        # Extract domain from filename
        local domain
        domain=$(basename "$conf" .conf)

        # Extract backend from config file comment
        local backend
        backend=$(grep -m1 "^# Backend:" "$conf" 2>/dev/null | sed 's/# Backend: //' || echo "unknown")

        DEPLOYED_DOMAINS+=("$domain")
        DEPLOYED_BACKENDS+=("$backend")
    done
}

# Get default domain from marker file
get_default_domain() {
    if [[ -f "$MARKER_FILE" ]]; then
        grep "^DEFAULT_DOMAIN=" "$MARKER_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo ""
    fi
}

# Add official nginx.org repository for latest nginx version
add_nginx_repo() {
    local keyring="/usr/share/keyrings/nginx-archive-keyring.gpg"
    local sources_list="/etc/apt/sources.list.d/nginx.list"

    if [[ -f "$sources_list" ]]; then
        log_info "nginx.org repository already configured"
        return 0
    fi

    log_step "Adding official nginx.org repository..."

    # Install prerequisites
    apt-get update
    apt-get install -y ca-certificates curl gnupg

    # Add nginx signing key
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o "$keyring"

    # Add repository for Ubuntu (mainline branch for latest features)
    local codename
    codename=$(lsb_release -cs)
    echo "deb [signed-by=$keyring] http://nginx.org/packages/mainline/ubuntu $codename nginx" > "$sources_list"

    # Pin nginx.org packages to have higher priority than Ubuntu's
    cat > /etc/apt/preferences.d/99nginx <<'EOF'
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 900
EOF

    apt-get update
    log_info "nginx.org repository added (mainline branch)"
}

# Install nginx if not present
install_nginx() {
    if command -v nginx &>/dev/null; then
        log_info "nginx is already installed (version: $(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+'))"
        return 0
    fi

    log_step "Installing nginx..."
    export DEBIAN_FRONTEND=noninteractive

    # Add official nginx.org repo for latest version (1.26+)
    add_nginx_repo

    apt-get install -y nginx

    # Enable and start nginx
    systemctl enable nginx
    systemctl start nginx

    log_info "nginx installed successfully (version: $(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+'))"
}

# Check if nginx version supports "http2 on;" directive (1.25.1+)
# Returns 0 (true) if supported, 1 (false) if not
nginx_supports_http2_directive() {
    local version_output
    version_output=$(nginx -v 2>&1)

    # Extract version number (e.g., "nginx/1.24.0" -> "1.24.0")
    local version
    version=$(echo "$version_output" | grep -oP 'nginx/\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [[ -z "$version" ]]; then
        # Can't determine version, assume old syntax for safety
        return 1
    fi

    # Split version into parts
    local major minor patch
    IFS='.' read -r major minor patch <<< "$version"

    # http2 directive added in 1.25.1
    if [[ "$major" -gt 1 ]]; then
        return 0
    elif [[ "$major" -eq 1 && "$minor" -gt 25 ]]; then
        return 0
    elif [[ "$major" -eq 1 && "$minor" -eq 25 && "$patch" -ge 1 ]]; then
        return 0
    else
        return 1
    fi
}

# Install acme.sh if not present
install_acme() {
    if [[ -f "$ACME_HOME/acme.sh" ]]; then
        log_info "acme.sh is already installed"
        return 0
    fi

    log_step "Installing acme.sh..."

    # Install dependencies
    apt-get install -y curl socat

    # Install acme.sh
    curl -fsSL https://get.acme.sh | sh -s email="$ACME_EMAIL"

    # Source acme.sh
    source "$ACME_HOME/acme.sh.env" 2>/dev/null || true

    log_info "acme.sh installed successfully"
}

# Configure DNS provider credentials for acme.sh
configure_dns_credentials() {
    local provider="${DNS_PROVIDER:-azure}"

    log_step "Configuring $provider DNS credentials for acme.sh..."

    case "$provider" in
        azure)
            export AZUREDNS_SUBSCRIPTIONID="$AZURE_SUBSCRIPTION_ID"
            export AZUREDNS_TENANTID="$AZURE_TENANT_ID"
            export AZUREDNS_APPID="$AZURE_CLIENT_ID"
            export AZUREDNS_CLIENTSECRET="$AZURE_CLIENT_SECRET"
            ;;
        cloudflare)
            export CF_Token="$CF_TOKEN"
            export CF_Account_ID="${CF_ACCOUNT_ID:-}"
            export CF_Zone_ID="${CF_ZONE_ID:-}"
            ;;
    esac

    # acme.sh will save these to account.conf on first use
    log_info "$provider DNS credentials configured"
}

# Setup base nginx configuration
setup_nginx_base() {
    log_step "Setting up nginx base configuration..."

    # Create SSL directory
    mkdir -p "$NGINX_SSL_DIR"

    # Backup original nginx.conf if not already backed up
    if [[ ! -f /etc/nginx/nginx.conf.original ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.original
    fi

    # Check if WebSocket map already exists
    if ! grep -q "map \$http_upgrade \$connection_upgrade" /etc/nginx/nginx.conf; then
        # Add WebSocket upgrade map to http block
        sed -i '/^http {/a \
    # WebSocket upgrade map\
    map $http_upgrade $connection_upgrade {\
        default upgrade;\
        '\'''\'' close;\
    }\
' /etc/nginx/nginx.conf
        log_info "Added WebSocket upgrade map to nginx.conf"
    fi

    # Create sites-available and sites-enabled if they don't exist
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled

    # Ensure sites-enabled is included in nginx.conf
    if ! grep -q "include /etc/nginx/sites-enabled/\*" /etc/nginx/nginx.conf; then
        sed -i '/^http {/a \
    include /etc/nginx/sites-enabled/*;\
' /etc/nginx/nginx.conf
        log_info "Added sites-enabled include to nginx.conf"
    fi

    # Remove default site if it exists
    rm -f /etc/nginx/sites-enabled/default

    log_info "nginx base configuration complete"
}

# Create HTTP to HTTPS redirect catch-all
create_http_redirect() {
    log_step "Creating HTTP to HTTPS redirect..."

    cat > /etc/nginx/sites-available/00-default-redirect.conf <<'EOF'
# HTTP to HTTPS redirect - Managed by reverse-proxy.sh
# Catches all HTTP requests and redirects to HTTPS

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}
EOF

    # Enable the redirect
    ln -sf /etc/nginx/sites-available/00-default-redirect.conf /etc/nginx/sites-enabled/

    log_info "HTTP redirect configured"
}

# Issue certificate for a domain using acme.sh
issue_certificate() {
    local domain="$1"

    log_step "Issuing certificate for $domain..."

    # Check if certificate already exists
    if [[ -d "$ACME_HOME/${domain}_ecc" ]]; then
        log_info "Certificate for $domain already exists, skipping issuance"
        return 0
    fi

    # Determine acme server
    local acme_server="letsencrypt"
    if [[ "${ACME_USE_STAGING:-false}" == "true" ]]; then
        acme_server="letsencrypt_test"
        log_warn "Using Let's Encrypt STAGING server (certificates will not be trusted)"
    fi

    # Determine DNS plugin based on provider
    local dns_plugin
    case "${DNS_PROVIDER:-azure}" in
        azure)      dns_plugin="dns_azure" ;;
        cloudflare) dns_plugin="dns_cf" ;;
    esac

    # Issue certificate
    if ! "$ACME_HOME/acme.sh" --issue \
        --dns "$dns_plugin" \
        -d "$domain" \
        --keylength ec-256 \
        --server "$acme_server" \
        --dnssleep 30; then
        log_error "Failed to issue certificate for $domain"
        return 1
    fi

    log_info "Certificate issued for $domain"
    return 0
}

# Create certificate symlinks
create_cert_symlinks() {
    local domain="$1"

    log_step "Creating certificate symlinks for $domain..."

    local cert_dir="$NGINX_SSL_DIR/$domain"
    local acme_cert_dir="$ACME_HOME/${domain}_ecc"

    mkdir -p "$cert_dir"

    # Create symlinks
    ln -sf "$acme_cert_dir/fullchain.cer" "$cert_dir/fullchain.pem"
    ln -sf "$acme_cert_dir/${domain}.key" "$cert_dir/privkey.pem"

    # Set reload command for certificate renewal
    "$ACME_HOME/acme.sh" --install-cert -d "$domain" \
        --ecc \
        --reloadcmd "systemctl reload nginx"

    log_info "Certificate symlinks created for $domain"
}

# Generate nginx site configuration
generate_site_config() {
    local domain="$1"
    local backend_host="$2"
    local backend_port="$3"
    local backend_proto="$4"
    local is_default="${5:-false}"

    log_step "Generating nginx config for $domain..."

    local default_flag=""
    if [[ "$is_default" == "true" ]]; then
        default_flag=" default_server"
    fi

    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Detect nginx version for http2 syntax
    local listen_directive http2_directive
    if nginx_supports_http2_directive; then
        # nginx 1.25.1+ uses separate http2 directive
        listen_directive="listen 443 ssl${default_flag};"
        http2_directive=$'\n    http2 on;'
        log_info "Using nginx 1.25+ http2 syntax"
    else
        # nginx < 1.25.1 uses http2 in listen line
        listen_directive="listen 443 ssl http2${default_flag};"
        http2_directive=""
        log_info "Using nginx 1.24 http2 syntax"
    fi

    cat > "/etc/nginx/sites-available/${domain}.conf" <<EOF
# ${domain} - Managed by reverse-proxy.sh
# Backend: ${backend_proto}://${backend_host}:${backend_port}
# Generated: ${timestamp}

server {
    ${listen_directive}
    ${listen_directive/443/[::]:443}
    server_name ${domain};${http2_directive}

    # SSL Certificates (symlinks to acme.sh)
    ssl_certificate ${NGINX_SSL_DIR}/${domain}/fullchain.pem;
    ssl_certificate_key ${NGINX_SSL_DIR}/${domain}/privkey.pem;

    # Modern SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Per-domain logging
    access_log /var/log/nginx/${domain}.access.log;
    error_log /var/log/nginx/${domain}.error.log;

    # Proxy Configuration
    location / {
        proxy_pass ${backend_proto}://${backend_host}:${backend_port};
        proxy_http_version 1.1;

        # WebSocket support (enabled by default)
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;

        # Client IP forwarding (best practice)
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Forwarded "for=\$remote_addr;proto=\$scheme;host=\$host";

        # Other forwarded context
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
EOF

    # Enable the site
    ln -sf "/etc/nginx/sites-available/${domain}.conf" /etc/nginx/sites-enabled/

    log_info "nginx config created for $domain"
}

# Test nginx configuration
test_nginx_config() {
    log_step "Testing nginx configuration..."

    local output
    if output=$(nginx -t 2>&1); then
        log_info "nginx configuration test passed"
        echo "$output"
        return 0
    else
        log_error "nginx configuration test failed"
        echo "$output"
        return 1
    fi
}

# Reload nginx
reload_nginx() {
    log_step "Reloading nginx..."
    systemctl reload nginx
    log_info "nginx reloaded"
}

# Backup nginx configuration before changes
backup_nginx_config() {
    local backup_dir
    backup_dir="/etc/nginx/backups/backup-$(date +%Y%m%d-%H%M%S)"

    log_step "Creating backup of nginx configuration..."

    mkdir -p "$backup_dir"

    # Backup sites-available
    if [[ -d /etc/nginx/sites-available ]]; then
        cp -r /etc/nginx/sites-available "$backup_dir/"
    fi

    # Backup sites-enabled (just the symlink names)
    if [[ -d /etc/nginx/sites-enabled ]]; then
        ls -la /etc/nginx/sites-enabled/ > "$backup_dir/sites-enabled-list.txt" 2>/dev/null || true
    fi

    # Backup ssl directory structure (not the actual certs, just symlinks)
    if [[ -d /etc/nginx/ssl ]]; then
        cp -r /etc/nginx/ssl "$backup_dir/"
    fi

    # Backup nginx.conf
    if [[ -f /etc/nginx/nginx.conf ]]; then
        cp /etc/nginx/nginx.conf "$backup_dir/"
    fi

    log_info "Backup created: $backup_dir"
    echo "  To restore: cp -r $backup_dir/* /etc/nginx/"
}

# Create marker file
create_marker_file() {
    local config_path="$1"
    local default_domain="$2"

    cat > "$MARKER_FILE" <<EOF
# Nginx Reverse Proxy - Managed Configuration
# Do not edit this file manually
SETUP_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
SETUP_CONFIG="$config_path"
ACME_EMAIL="$ACME_EMAIL"
DEFAULT_DOMAIN="$default_domain"
EOF

    log_info "Marker file created"
}

# Remove a domain configuration
remove_domain() {
    local domain="$1"

    log_step "Removing domain $domain..."

    # Disable site
    rm -f "/etc/nginx/sites-enabled/${domain}.conf"

    # Remove site config
    rm -f "/etc/nginx/sites-available/${domain}.conf"

    # Remove cert symlinks
    rm -rf "${NGINX_SSL_DIR:?}/${domain:?}"

    # Note: We don't revoke or remove the actual certificate from acme.sh
    # It will be kept for potential future use

    log_info "Domain $domain removed"
}

# Add a single domain (interactive or from config)
add_domain() {
    local domain="$1"
    local backend_host="$2"
    local backend_port="$3"
    local backend_proto="$4"
    local is_default="${5:-false}"

    # Issue certificate
    if ! issue_certificate "$domain"; then
        return 1
    fi

    # Create symlinks
    create_cert_symlinks "$domain"

    # Generate nginx config
    generate_site_config "$domain" "$backend_host" "$backend_port" "$backend_proto" "$is_default"

    return 0
}

# Display comparison table
display_comparison() {
    local -n config_domains=$1
    local -n deployed_domains=$2

    echo ""
    echo "  Status comparison:"
    echo "  +--------------------------+-------------+-------------+"
    echo "  | Domain                   | In Config   | Deployed    |"
    echo "  +--------------------------+-------------+-------------+"

    # Combine both lists
    declare -A all_domains
    for d in "${config_domains[@]}"; do
        all_domains["$d"]=1
    done
    for d in "${deployed_domains[@]}"; do
        all_domains["$d"]=1
    done

    for domain in "${!all_domains[@]}"; do
        local in_config="  "
        local in_deployed="  "

        # Check if in config
        for d in "${config_domains[@]}"; do
            if [[ "$d" == "$domain" ]]; then
                in_config="Y "
                break
            fi
        done

        # Check if deployed
        for d in "${deployed_domains[@]}"; do
            if [[ "$d" == "$domain" ]]; then
                in_deployed="Y "
                break
            fi
        done

        # Determine status
        local config_status="N"
        local deployed_status="N"
        [[ "$in_config" == "Y " ]] && config_status="Y"
        [[ "$in_deployed" == "Y " ]] && deployed_status="Y"

        local config_display="$config_status"
        local deployed_display="$deployed_status"

        if [[ "$config_status" == "Y" && "$deployed_status" == "N" ]]; then
            deployed_display="N (missing)"
        elif [[ "$config_status" == "N" && "$deployed_status" == "Y" ]]; then
            config_display="N (extra)  "
        fi

        printf "  | %-24s | %-11s | %-11s |\n" "$domain" "$config_display" "$deployed_display"
    done

    echo "  +--------------------------+-------------+-------------+"
    echo ""
}

# Sync domains with config
sync_with_config() {
    local config_path="$1"

    # Parse config domains
    if ! parse_domains; then
        log_error "No domains found in config"
        return 1
    fi

    # Get deployed domains
    get_deployed_domains

    # Find domains to add (in config but not deployed)
    local to_add=()
    for i in "${!DOMAIN_LIST[@]}"; do
        local domain="${DOMAIN_LIST[$i]}"
        local found=false
        for deployed in "${DEPLOYED_DOMAINS[@]}"; do
            if [[ "$deployed" == "$domain" ]]; then
                found=true
                break
            fi
        done
        if [[ "$found" == "false" ]]; then
            to_add+=("$i")
        fi
    done

    # Find domains to remove (deployed but not in config)
    local to_remove=()
    for deployed in "${DEPLOYED_DOMAINS[@]}"; do
        local found=false
        for domain in "${DOMAIN_LIST[@]}"; do
            if [[ "$domain" == "$deployed" ]]; then
                found=true
                break
            fi
        done
        if [[ "$found" == "false" ]]; then
            to_remove+=("$deployed")
        fi
    done

    # Find domains with changed backends (in both but different settings)
    local backend_changes=()
    for i in "${!DOMAIN_LIST[@]}"; do
        local domain="${DOMAIN_LIST[$i]}"
        local config_backend="${BACKEND_PROTO_LIST[$i]}://${BACKEND_HOST_LIST[$i]}:${BACKEND_PORT_LIST[$i]}"

        for j in "${!DEPLOYED_DOMAINS[@]}"; do
            if [[ "${DEPLOYED_DOMAINS[$j]}" == "$domain" ]]; then
                local deployed_backend="${DEPLOYED_BACKENDS[$j]}"
                if [[ "$config_backend" != "$deployed_backend" ]]; then
                    backend_changes+=("$domain|$deployed_backend|$config_backend")
                fi
                break
            fi
        done
    done

    # Show what will be done
    echo ""
    if [[ ${#to_add[@]} -eq 0 && ${#to_remove[@]} -eq 0 && ${#backend_changes[@]} -eq 0 ]]; then
        log_info "Everything is in sync. No changes needed."
        return 0
    fi

    if [[ ${#to_add[@]} -gt 0 ]]; then
        echo -e "${GREEN}Domains to ADD:${NC}"
        for i in "${to_add[@]}"; do
            echo "  + ${DOMAIN_LIST[$i]} -> ${BACKEND_HOST_LIST[$i]}:${BACKEND_PORT_LIST[$i]}"
        done
    fi

    if [[ ${#to_remove[@]} -gt 0 ]]; then
        echo -e "${RED}Domains to REMOVE:${NC}"
        for domain in "${to_remove[@]}"; do
            echo "  - $domain"
        done
    fi

    # Warn about backend changes (not automatically handled)
    if [[ ${#backend_changes[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}WARNING: Backend changes detected but NOT automatically updated:${NC}"
        echo -e "${YELLOW}(To update, remove the domain and re-add it, or manually edit the nginx config)${NC}"
        for change in "${backend_changes[@]}"; do
            IFS='|' read -r domain old_backend new_backend <<< "$change"
            echo "  ~ $domain"
            echo "      Current:  $old_backend"
            echo "      Config:   $new_backend"
        done
    fi

    if [[ ${#to_add[@]} -eq 0 && ${#to_remove[@]} -eq 0 ]]; then
        log_info "No add/remove actions to perform (only backend changes detected above)"
        return 0
    fi

    echo ""
    read -r -p "Proceed with sync? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Sync cancelled"
        return 0
    fi

    # Backup before making changes
    backup_nginx_config

    # Configure Azure DNS
    configure_dns_credentials

    # Remove domains
    for domain in "${to_remove[@]}"; do
        remove_domain "$domain"
    done

    # Add domains - track if we've set a default
    local default_domain
    default_domain=$(get_default_domain)
    local first_add=true
    for i in "${to_add[@]}"; do
        local is_default="false"
        # Set as default if: no existing default AND this is the first domain we're adding
        # AND the first config domain (index 0) is being added
        if [[ -z "$default_domain" && "$first_add" == "true" && "${DOMAIN_LIST[$i]}" == "${DOMAIN_LIST[0]}" ]]; then
            is_default="true"
            default_domain="${DOMAIN_LIST[$i]}"
        fi
        add_domain "${DOMAIN_LIST[$i]}" "${BACKEND_HOST_LIST[$i]}" "${BACKEND_PORT_LIST[$i]}" "${BACKEND_PROTO_LIST[$i]}" "$is_default"
        first_add=false
    done

    # Test and reload nginx
    if test_nginx_config; then
        reload_nginx
        log_info "Sync complete"
    else
        log_error "nginx config test failed after sync"
        return 1
    fi
}

# Show certificate status
show_cert_status() {
    log_step "Certificate status:"
    echo ""

    get_deployed_domains

    if [[ ${#DEPLOYED_DOMAINS[@]} -eq 0 ]]; then
        log_info "No domains configured"
        return
    fi

    for domain in "${DEPLOYED_DOMAINS[@]}"; do
        local cert_file="$NGINX_SSL_DIR/$domain/fullchain.pem"
        if [[ -f "$cert_file" ]]; then
            local expiry
            expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
            local expiry_epoch
            expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            local now_epoch
            now_epoch=$(date +%s)
            local days_left
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            if [[ $days_left -lt 0 ]]; then
                echo -e "  ${RED}$domain${NC}: EXPIRED ($expiry)"
            elif [[ $days_left -lt 30 ]]; then
                echo -e "  ${YELLOW}$domain${NC}: $days_left days left ($expiry)"
            else
                echo -e "  ${GREEN}$domain${NC}: $days_left days left ($expiry)"
            fi
        else
            echo -e "  ${RED}$domain${NC}: Certificate not found"
        fi
    done
    echo ""
}

# Manual add domain (interactive)
manual_add_domain() {
    echo ""
    read -r -p "Domain name (e.g., app.example.com): " domain

    if [[ -z "$domain" ]]; then
        log_error "Domain name required"
        return 1
    fi

    # Check if domain already exists
    get_deployed_domains
    for deployed in "${DEPLOYED_DOMAINS[@]}"; do
        if [[ "$deployed" == "$domain" ]]; then
            log_error "Domain $domain is already configured"
            return 1
        fi
    done

    read -r -p "Backend host (e.g., localhost, 192.168.1.100): " backend_host
    read -r -p "Backend port (e.g., 3000, 8080): " backend_port
    read -r -p "Backend protocol [http/https] (default: http): " backend_proto
    backend_proto="${backend_proto:-http}"

    if [[ -z "$backend_host" || -z "$backend_port" ]]; then
        log_error "Backend host and port are required"
        return 1
    fi

    echo ""
    echo "Configuration:"
    echo "  Domain: $domain"
    echo "  Backend: ${backend_proto}://${backend_host}:${backend_port}"
    echo ""
    read -r -p "Proceed? [y/N] " confirm

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Cancelled"
        return 0
    fi

    # Backup before making changes
    backup_nginx_config

    # Configure Azure DNS if needed
    validate_dns_config
    configure_dns_credentials

    # Determine if this should be default
    local is_default="false"
    if [[ ${#DEPLOYED_DOMAINS[@]} -eq 0 ]]; then
        is_default="true"
    fi

    # Add the domain
    if add_domain "$domain" "$backend_host" "$backend_port" "$backend_proto" "$is_default"; then
        if test_nginx_config; then
            reload_nginx
            log_info "Domain $domain added successfully"

            # Update marker file if this is the default
            if [[ "$is_default" == "true" ]]; then
                local config_path
                config_path=$(grep "^SETUP_CONFIG=" "$MARKER_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
                create_marker_file "$config_path" "$domain"
            fi
        else
            log_error "nginx config test failed"
            remove_domain "$domain"
            return 1
        fi
    else
        return 1
    fi
}

# Manual remove domain (interactive)
manual_remove_domain() {
    get_deployed_domains

    if [[ ${#DEPLOYED_DOMAINS[@]} -eq 0 ]]; then
        log_info "No domains configured"
        return 0
    fi

    local default_domain
    default_domain=$(get_default_domain)

    echo ""
    echo "Deployed domains:"
    for i in "${!DEPLOYED_DOMAINS[@]}"; do
        local domain="${DEPLOYED_DOMAINS[$i]}"
        local default_tag=""
        if [[ "$domain" == "$default_domain" ]]; then
            default_tag=" [DEFAULT]"
        fi
        echo "  $((i+1)). ${domain}${default_tag}"
    done
    echo ""

    read -r -p "Enter number to remove (or 0 to cancel): " choice

    if [[ "$choice" == "0" || -z "$choice" ]]; then
        return 0
    fi

    local index=$((choice - 1))
    if [[ $index -lt 0 || $index -ge ${#DEPLOYED_DOMAINS[@]} ]]; then
        log_error "Invalid selection"
        return 1
    fi

    local domain="${DEPLOYED_DOMAINS[$index]}"

    # Check if trying to remove default domain
    if [[ "$domain" == "$default_domain" && ${#DEPLOYED_DOMAINS[@]} -gt 1 ]]; then
        log_error "Cannot remove default domain while other domains exist"
        log_info "Remove all other domains first, or remove all domains at once"
        return 1
    fi

    read -r -p "Remove $domain? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        return 0
    fi

    # Backup before making changes
    backup_nginx_config

    remove_domain "$domain"

    if test_nginx_config; then
        reload_nginx
        log_info "Domain $domain removed successfully"
    fi
}

# Display main management menu
show_main_menu() {
    local config_path="$1"
    local has_config="$2"

    echo ""
    echo "========================================================"
    echo "         Nginx Reverse Proxy Management"
    echo "========================================================"

    if [[ "$has_config" == "true" ]]; then
        echo "  Config file: $config_path"
        echo ""

        # Parse and display comparison
        if parse_domains; then
            get_deployed_domains
            display_comparison DOMAIN_LIST DEPLOYED_DOMAINS
        fi

        echo "  [S] Sync with config (add missing, remove extra)"
        echo "  [C] Compare only (show detailed diff)"
    else
        echo "  No config file available"
        echo ""
        get_deployed_domains
        echo "  Deployed domains: ${#DEPLOYED_DOMAINS[@]}"
        echo ""
    fi

    echo "  [M] Manual operations (add/remove domains)"
    echo "  [L] List certificate status"
    echo "  [T] Test nginx configuration"
    echo "  [Q] Quit"
    echo ""
    echo "========================================================"
}

# Manual operations submenu
show_manual_menu() {
    while true; do
        echo ""
        echo "========================================================"
        echo "           Manual Domain Management"
        echo "========================================================"

        get_deployed_domains
        local default_domain
        default_domain=$(get_default_domain)

        if [[ ${#DEPLOYED_DOMAINS[@]} -eq 0 ]]; then
            echo "  No domains currently configured"
        else
            echo "  Currently deployed:"
            for i in "${!DEPLOYED_DOMAINS[@]}"; do
                local domain="${DEPLOYED_DOMAINS[$i]}"
                local backend="${DEPLOYED_BACKENDS[$i]}"
                local default_tag=""
                if [[ "$domain" == "$default_domain" ]]; then
                    default_tag=" [DEFAULT]"
                fi
                echo "    $((i+1)). ${domain} -> ${backend}${default_tag}"
            done
        fi

        echo ""
        echo "  [A] Add new domain"
        echo "  [R] Remove domain"
        echo "  [B] Back to main menu"
        echo ""
        echo "========================================================"
        read -r -p "  Select option: " choice

        case "${choice^^}" in
            A)
                manual_add_domain
                read -r -p "Press Enter to continue..."
                ;;
            R)
                manual_remove_domain
                read -r -p "Press Enter to continue..."
                ;;
            B)
                return
                ;;
            *)
                log_warn "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Management mode main loop
management_mode() {
    local config_path="$1"
    local has_config="false"

    # Try to load config
    if [[ -n "$config_path" && -f "$config_path" ]]; then
        load_config "$config_path"
        has_config="true"
    else
        # Try config from marker file
        local saved_config
        saved_config=$(grep "^SETUP_CONFIG=" "$MARKER_FILE" 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
        if [[ -n "$saved_config" && -f "$saved_config" ]]; then
            load_config "$saved_config"
            config_path="$saved_config"
            has_config="true"
        fi
    fi

    while true; do
        show_main_menu "$config_path" "$has_config"
        read -r -p "  Select option: " choice

        case "${choice^^}" in
            S)
                if [[ "$has_config" == "true" ]]; then
                    sync_with_config "$config_path"
                    read -r -p "Press Enter to continue..."
                else
                    log_warn "No config file available for sync"
                    sleep 2
                fi
                ;;
            C)
                if [[ "$has_config" == "true" ]]; then
                    echo ""
                    show_cert_status
                    read -r -p "Press Enter to continue..."
                else
                    log_warn "No config file available for comparison"
                    sleep 2
                fi
                ;;
            M)
                show_manual_menu
                ;;
            L)
                show_cert_status
                read -r -p "Press Enter to continue..."
                ;;
            T)
                test_nginx_config
                read -r -p "Press Enter to continue..."
                ;;
            Q)
                echo ""
                log_info "Goodbye!"
                exit 0
                ;;
            *)
                log_warn "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Initial setup mode
initial_setup() {
    local config_path="$1"

    log_info "Starting initial setup..."
    echo ""

    # Validate Azure config
    validate_dns_config

    # Parse domains
    if ! parse_domains; then
        log_warn "No domains configured in config file. Starting interactive mode."

        # Install nginx and acme.sh first
        install_nginx
        install_acme
        setup_nginx_base
        create_http_redirect

        # Create marker file with empty default
        create_marker_file "$config_path" ""

        # Test and reload nginx
        if test_nginx_config; then
            reload_nginx
        fi

        log_info "Base setup complete. Use manual mode to add domains."
        management_mode "$config_path"
        return
    fi

    # Install components
    install_nginx
    install_acme

    # Configure Azure DNS
    configure_dns_credentials

    # Setup nginx
    setup_nginx_base
    create_http_redirect

    # Process each domain
    local default_domain=""
    for i in "${!DOMAIN_LIST[@]}"; do
        local domain="${DOMAIN_LIST[$i]}"
        local backend_host="${BACKEND_HOST_LIST[$i]}"
        local backend_port="${BACKEND_PORT_LIST[$i]}"
        local backend_proto="${BACKEND_PROTO_LIST[$i]}"

        local is_default="false"
        if [[ $i -eq 0 ]]; then
            is_default="true"
            default_domain="$domain"
        fi

        log_info "Processing domain $((i+1))/${#DOMAIN_LIST[@]}: $domain"

        if ! add_domain "$domain" "$backend_host" "$backend_port" "$backend_proto" "$is_default"; then
            log_error "Failed to setup $domain"
            continue
        fi
    done

    # Test and reload nginx
    if test_nginx_config; then
        reload_nginx
    else
        log_error "nginx configuration test failed"
        exit 1
    fi

    # Create marker file
    create_marker_file "$config_path" "$default_domain"

    # Summary
    echo ""
    echo "========================================="
    log_info "Initial Setup Complete!"
    echo "========================================="
    echo ""
    echo "Configured domains:"
    for i in "${!DOMAIN_LIST[@]}"; do
        local domain="${DOMAIN_LIST[$i]}"
        local default_tag=""
        if [[ $i -eq 0 ]]; then
            default_tag=" [DEFAULT]"
        fi
        echo "  - ${domain}${default_tag} -> ${BACKEND_PROTO_LIST[$i]}://${BACKEND_HOST_LIST[$i]}:${BACKEND_PORT_LIST[$i]}"
    done
    echo ""
    echo "SSL certificates will auto-renew via acme.sh cron"
    echo "nginx will be reloaded automatically after renewal"
    echo ""
    echo "Run this script again to manage domains"
    echo "========================================="
}

#############################################
# MAIN
#############################################

check_root
parse_args "$@"

# Load config if provided
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    load_config "$CONFIG_FILE"
fi

# Determine mode
if [[ -f "$MARKER_FILE" ]]; then
    log_info "Existing installation detected. Entering management mode..."
    management_mode "$CONFIG_FILE"
else
    log_info "No existing installation found. Starting initial setup..."

    if [[ -z "$CONFIG_FILE" ]]; then
        log_warn "No config file specified. You will be prompted for all values."
        echo ""
        read -r -p "Continue with interactive setup? [y/N] " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Usage: $0 -c config.conf"
            exit 0
        fi
    fi

    initial_setup "$CONFIG_FILE"
fi
