#!/bin/bash

DEBUG_LOG() {
    #updated to run in container
    if [ -z "$1" ]; then
        echo "Usage: DEBUG_LOG <log_message>"
        return 1
    fi

    local log_file="/logs/esdb_cloud_init.log"

    if [ ! -f "$log_file" ]; then
        touch "$log_file" || {
            echo "Failed to create log file: $log_file"
            return 1
        }
    fi

    local current_time=$(date +"%Y-%m-%d %H:%M:%S")
    local log_message="$1"

    echo "$current_time - $log_message" >>"$log_file"
}

LOG_COMMAND() {
    #updated to run in container
    local log_file="/logs/esdb_cloud_init.log"
    local current_time=$(date +"%Y-%m-%d %H:%M:%S")

    # Log command to be executed
    local log_message="$1"
    echo "$current_time - Command: $log_message " >>"$log_file"

    # Log command output to log file
    "$@" >>"$log_file" 2>&1

    #Log command exit status
    local exit_status=$?
    echo "$current_time - Exit Status: $exit_status" >>"$log_file"
}

CHECK_VARIABLE() {
    local variable_name=$1

    # Using indirect parameter expansion
    eval "local variable_value=\$$variable_name"

    if [ -z "$variable_value" ]; then
        DEBUG_LOG "Variable $variable_name is not set or is empty"
        return 1
    else
        DEBUG_LOG "Variable $variable_name is set with value $variable_value"
        return 0
    fi
}

get_secret_value() {
    #updated to run in container
    local local_secret_name=$1
    #simplifed for local container testing, will need to be updated to access Azure secrets from keyvault
    # Replace hyphens with underscores in local_secret_name
    local env_var_name="secret_${local_secret_name//-/_}"

    # Directly assigning the value of the environment variable to secret_value
    local secret_value=${!env_var_name}

    if [ -z "$secret_value" ]; then
        DEBUG_LOG "Environment variable $env_var_name is not set."
        exit 1
    else
        DEBUG_LOG "Successfully got value from environment variable $env_var_name"
    fi
    echo "$secret_value"
}

get_parameter_store_value() {
    #updated to run in container
    local local_secret_name=$1
    #simplifed for local container testing, will need to be updated to access Azure secrets from keyvault
    # Replace hyphens with underscores in local_secret_name
    local env_var_name="parameter_${local_secret_name//-/_}"

    # Directly assigning the value of the environment variable to secret_value
    local secret_value=${!env_var_name}

    if [ -z "$secret_value" ]; then
        DEBUG_LOG "Environment variable $env_var_name is not set."
        exit 1
    else
        DEBUG_LOG "Successfully got value from environment variable $env_var_name"
    fi
    echo "$secret_value"
}

update_users_and_acl() {
    local local_domain=$1
    local local_admin_password=$2

    ADMIN_PASSWORD_RESET_URL="https://$local_domain:2113/users/admin/command/reset-password"
    OPS_PASSWORD_RESET_URL="https://$local_domain:2113/users/ops/command/reset-password"
    HTTP_API_USER_ENDPOINT="https://$local_domain:2113/users/"
    HTTP_STREAMS_SETTING_URL="https://$local_domain:2113/streams/%24settings"

    DEBUG_LOG "Reset Ops password"
    if [ -n "$local_admin_password" ] && [ -n "$OPS_PASSWORD" ]; then
        response=$(curl -s -D - -o /dev/null -X POST "$OPS_PASSWORD_RESET_URL" -u "admin:$local_admin_password" \
            -H "Content-Type: application/json" \
            -d "{
                    \"newPassword\": \"$OPS_PASSWORD\"
                }" 2>&1)
        http_status=$(echo "$response" | grep -Fi HTTP/ | awk '{print $2}')
        if [[ $http_status =~ ^2[0-9][0-9]$ ]]; then
                DEBUG_LOG "Ops Password reset successfully"
            else
                DEBUG_LOG "Ops Password reset Error: $response"
        fi
    fi

    DEBUG_LOG "Create Company Service user"
    if [ -n "$local_admin_password" ] && [ -n "$COMPANY_SERVICE_PASSWORD" ]; then
        response=$(curl -s -D - -o /dev/null -X POST "$HTTP_API_USER_URL" -u "admin:$local_admin_password" \
            -H "Content-Type: application/json" \
            -d "{
                    \"LoginName\": \"company-service\",
                    \"FullName\": \"Company Service\",
                    \"Password\": \"$COMPANY_SERVICE_PASSWORD\",
                    \"Groups\" : [\"company-service\"]
                }" 2>&1)
        http_status=$(echo "$response" | grep -Fi HTTP/ | awk '{print $2}')
        if [[ $http_status =~ ^2[0-9][0-9]$ ]]; then
            DEBUG_LOG "Company svc created successfully"
        else
            DEBUG_LOG "Company svc creation error: $response"
        fi
    fi

    DEBUG_LOG "Create Human Service user"
    if [ -n "$local_admin_password" ] && [ -n "$HUMAN_SERVICE_PASSWORD" ]; then
        response=$(curl -s -D - -o /dev/null -X POST "$HTTP_API_USER_URL" -u "admin:$local_admin_password" \
            -H "Content-Type: application/json" \
            -d "{
                    \"LoginName\": \"human-service\",
                    \"FullName\": \"human Service\",
                    \"Password\": \"$HUMAN_SERVICE_PASSWORD\",
                    \"Groups\" : [\"human-service\"]
                }" 2>&1)
        http_status=$(echo "$response" | grep -Fi HTTP/ | awk '{print $2}')
        if [[ $http_status =~ ^2[0-9][0-9]$ ]]; then
            DEBUG_LOG "Human svc  created successfully"
        else
            DEBUG_LOG "Human svc creation error: $response"
        fi
    fi

    DEBUG_LOG "Update user ACL"
    if [ -n "$local_admin_password" ]; then
        response=$(curl -s -D - -o /dev/null -X POST "$HTTP_STREAMS_SETTING_URL" -u "admin:$local_admin_password" \
            -H "Content-Type: application/vnd.eventstore.events+json" \
            -d "[{
                \"eventId\": \"7c314750-05e1-439f-b2eb-f5b0e019be72\",
                \"eventType\": \"update-default-acl\",
                \"data\": {
                    \"$userStreamAcl\" : {
                        \"$r\"  : [\"$admin\", \"$ops\", \"company-service\", \"human-service\"],
                        \"$w\"  : [\"$admin\", \"$ops\", \"company-service\", \"human-service\"],
                        \"$d\"  : [\"$admin\", \"$ops\"],
                        \"$mr\" : [\"$admin\", \"$ops\"],
                        \"$mw\" : [\"$admin\", \"$ops\"]
                    },
                    \"$systemStreamAcl\" : {
                        \"$r\"  : \"$admins\",
                        \"$w\"  : \"$admins\",
                        \"$d\"  : \"$admins\",
                        \"$mr\" : \"$admins\",
                        \"$mw\" : \"$admins\"
                    }
                }
            }]" 2>&1)
        http_status=$(echo "$response" | grep -Fi HTTP/ | awk '{print $2}')
        if [[ $http_status =~ ^2[0-9][0-9]$ ]]; then
            DEBUG_LOG "Default ACL successfully updated"
        else
            DEBUG_LOG "Update Default ACL Error: $response"
        fi
    fi
}

#SCRIPT

# Set Region
echo "Set Region to ap-southeast-2"
export AWS_DEFAULT_REGION="ap-southeast-2"

# Mount volumes
# TODO mount volumes for scaleset here, currently docker-compose is handling it

mkdir /mnt/volume1/configuration
mkdir /mnt/volume1/logs
mkdir /mnt/volume1/projections
mkdir /mnt/volume1/certs
mkdir /mnt/volume1/scripts

mkdir /mnt/volume2/data
mkdir /mnt/volume2/index

# Setup esdb node
echo "Installing Eventstore"
EVENTSTORE_SECRET_TOKEN=$(get_secret_value "eventstore-secret-token-secret")

#tzdata python dependency non interactive install fix:
export DEBIAN_FRONTEND=noninteractive
export TZ=Pacific/Auckland

curl -s https://$EVENTSTORE_SECRET_TOKEN:@packagecloud.io/install/repositories/EventStore/EventStore-Commercial/script.deb.sh | sudo bash
sudo apt-get install eventstore-commercial=24.2.0

sudo chsh -s /bin/bash eventstore
echo "Remove eventstore password"
sudo passwd -d eventstore

chown -R eventstore:root /mnt/volume1
chown -R eventstore:root /mnt/volume2

chmod -R 770 /mnt/volume1
chmod -R 770 /mnt/volume2

DEBUG_LOG "Fetching Secrets"
ADMIN_DEFAULT_PASSWORD="changeit"
ADMIN_PREVIOUS_PASSWORD=$(get_secret_value "esdb-admin-password" "AWSPREVIOUS")
ADMIN_CURRENT_PASSWORD=$(get_secret_value "esdb-admin-password")
OPS_PASSWORD=$(get_secret_value "esdb-ops-password")
COMPANY_SERVICE_PASSWORD=$(get_secret_value "esdb-company-service-password")
HUMAN_SERVICE_PASSWORD=$(get_secret_value "esdb-human-service-password")

DEBUG_LOG "Fetching Parameter Store Values"
CERTIFICATE_EMAIL=$(get_parameter_store_value "ec2-esdb-cert-email-config")
CHECK_VARIABLE "CERTIFICATE_EMAIL"

DOMAIN_NAME=$(get_parameter_store_value "ec2-esdb-cert-dns-config")
CHECK_VARIABLE "DOMAIN_NAME"

EVENTSTORE_CONFIG=$(get_parameter_store_value "ec2-esdb-config")
CHECK_VARIABLE "EVENTSTORE_CONFIG"

#TODO cloudwatch replacement config

if [ -n "$EVENTSTORE_CONFIG" ]; then
    DEBUG_LOG "Creating Eventstore Config"
    touch /mnt/volume1/configuration/eventstore.conf || DEBUG_LOG "Failed to create config file"
    echo "$EVENTSTORE_CONFIG" > /mnt/volume1/configuration/eventstore.conf
else
    DEBUG_LOG "Eventstore config is empty"
fi

DEBUG_LOG "Setting ULIMITS"
echo "eventstore soft nofile 50000" >> /etc/security/limits.conf
echo "eventstore hard nofile 50000" >> /etc/security/limits.conf

#TODO logging agent config, previously we set up cloudwatch here

DEBUG_LOG "Installing Certbot"
LOG_COMMAND add-apt-repository ppa:certbot/certbot -y
LOG_COMMAND apt-get install certbot python3-certbot-apache python3-certbot-dns-route53 -y

DEBUG_LOG "Getting IP Address"
IP_WITH_DOTS=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1)
CHECK_VARIABLE "IP_WITH_DOTS"

IP_WITH_DASHES=$(echo $IP_WITH_DOTS | sed 's/\./-/g')
CHECK_VARIABLE "IP_WITH_DASHES"

SUB_DOMAIN_NAME=$(echo "$DOMAIN_NAME" | awk '{gsub("esdbcluster.", ""); print}')
CHECK_VARIABLE "SUB_DOMAIN_NAME"

DEBUG_LOG "Configure Eventstore DNS"
cat <<EOF >> /mnt/volume1/configuration/eventstore.conf

# Network configuration
IntIp: $IP_WITH_DOTS
ExtIp: $IP_WITH_DOTS
IntHostAdvertiseAs: esdb-writenode-$IP_WITH_DASHES.$SUB_DOMAIN_NAME
EOF

DEBUG_LOG "Configure Eventstore Certs"
BUCKET="${project}-${account_type}-s3-esdb-cert-${azure_region_shortcode}-${subscription_name}"
PRIVATE_KEY="privkeyrsa.key"
FULLCHAIN="fullchain.pem"
CERT_EXIST=$(aws s3 ls "s3://$BUCKET/$PRIVATE_KEY")
if [ -z "$CERT_EXIST" ]; then
    DEBUG_LOG "Cert does not exist in $BUCKET"

    if ! sudo certbot certonly --dns-route53 --non-interactive --agree-tos --email "$CERTIFICATE_EMAIL" --cert-name "*.$SUB_DOMAIN_NAME" -d "*.$SUB_DOMAIN_NAME" -d "$SUB_DOMAIN_NAME"; then
        DEBUG_LOG "Cert acqrd failed"
    else
        DEBUG_LOG "Cert acqrd success"

        DEBUG_LOG "Creating Certs"
        cd /etc/letsencrypt/live/"*.$SUB_DOMAIN_NAME"/
        LOG_COMMAND openssl rsa -in privkey.pem -out privkey.key
        LOG_COMMAND openssl rsa -in privkey.key -traditional -out privkeyrsa.key

        DEBUG_LOG "Copying Certs to Volume"
        LOG_COMMAND sudo cp /etc/letsencrypt/live/"*.$SUB_DOMAIN_NAME"/cert.pem /mnt/volume1/certs/fullchain.pem
        LOG_COMMAND sudo cp /etc/letsencrypt/live/"*.$SUB_DOMAIN_NAME"/privkeyrsa.key /mnt/volume1/certs/privkeyrsa.key

        DEBUG_LOG "Copying Certs to S3"
        LOG_COMMAND aws s3 cp /mnt/volume1/certs/fullchain.pem "s3://$BUCKET/"
        LOG_COMMAND aws s3 cp /mnt/volume1/certs/privkeyrsa.key "s3://$BUCKET/"
    fi
else
    DEBUG_LOG "Cert exist in $BUCKET"
    LOG_COMMAND aws s3 cp "s3://$BUCKET/$FULLCHAIN" /mnt/volume1/certs/fullchain.pem
    LOG_COMMAND aws s3 cp "s3://$BUCKET/$PRIVATE_KEY" /mnt/volume1/certs/privkeyrsa.key
fi

LOG_COMMAND chown eventstore /mnt/volume1/certs/*
LOG_COMMAND chmod 600 /mnt/volume1/certs/*

#create script for scavenging
DEBUG_LOG "Creating Eventstore Scavenging Script"
touch /mnt/volume1/scripts/eventstore-db-scavenging.sh
cat <<EOF >/mnt/volume1/scripts/eventstore-db-scavenging.sh
#!/bin/bash

secret_id="${project}-${account_type}-esdb-ops-password-${azure_region_shortcode}-${subscription_name}"
OPS_SECRET=\$(aws ssm get-parameter --name "\$secret_id" --query "Parameter.Value" --output text --with-decryption)
OPS_PASSWORD=\$(aws secretsmanager get-secret-value --secret-id \$OPS_SECRET --query SecretString --output text)
if [ $? -ne 0 ]; then
    echo "Failed to get OPS Password from Secrets Manager for Scavenging function"
fi

if [ -n "\$OPS_PASSWORD" ]; then
    curl -i -d {} -X POST https://esdb-writenode-$IP_WITH_DASHES.$SUB_DOMAIN_NAME:2113/admin/scavenge -u "ops:\$OPS_PASSWORD"
fi
EOF

chmod +x /mnt/volume1/scripts/eventstore-db-scavenging.sh

DEBUG_LOG "Add cron job for scavenging"
RANDOM_HOUR=$((RANDOM % 24))
echo "0 $RANDOM_HOUR * * * ./mnt/volume1/scripts/eventstore-db-scavenging.sh" > /mnt/volume1/cronjob

#create script for cert renewal
DEBUG_LOG "Creating Eventstore Cert Renewal Script"
touch /mnt/volume1/scripts/eventstore-db-cert-renewal.sh
cat <<EOF >/mnt/volume1/scripts/eventstore-db-cert-renewal.sh
#!/bin/bash

if ! sudo certbot renew --dns-route53 --non-interactive --agree-tos --email "$CERTIFICATE_EMAIL" --cert-name "*.$SUB_DOMAIN_NAME"; then
    echo "Certificate renewal failed!" >&2
    exit 1
else
    cd /etc/letsencrypt/live/"*.$SUB_DOMAIN_NAME"/
    openssl rsa -in privkey.pem -out privkey.key
    openssl rsa -in privkey.key -traditional -out privkeyrsa.key

    sudo cp /etc/letsencrypt/live/"*.$SUB_DOMAIN_NAME"/cert.pem /mnt/volume1/certs/fullchain.pem
    sudo cp /etc/letsencrypt/live/"*.$SUB_DOMAIN_NAME"/privkeyrsa.key /mnt/volume1/certs/privkeyrsa.key

    chown eventstore *
    chmod 600 *

    systemctl restart eventstore
fi
EOF

LOG_COMMAND chmod +x /mnt/volume1/scripts/eventstore-db-cert-renewal.sh

DEBUG_LOG "Add cron job for cert renewal"
echo "0 0 1 */3 * /mnt/volume1/scripts/eventstore-db-cert-renewal.sh" >> /mnt/volume1/cronjob

LOG_COMMAND crontab -u eventstore /mnt/volume1/cronjob

DEBUG_LOG "Modify Eventstore Service File to include new config"
service_file="/lib/systemd/system/eventstore.service"
new_exec_start="ExecStart=/bin/bash -c 'echo $$$ > /run/eventstore/eventstore.pid; exec /usr/bin/eventstored --config /mnt/volume1/configuration/eventstore.conf'"
sed -i "s|^ExecStart=.*$|$new_exec_start|" "$service_file"
systemctl daemon-reload

DEBUG_LOG "Starting Eventstore Service"
systemctl start eventstore

if [ -z "$DOMAIN_NAME" ]; then
    DEBUG_LOG "DOMAIN_NAME is unset or set to the empty string"
else
    DEBUG_LOG "DOMAIN_NAME is set to $DOMAIN_NAME"
fi

RETRY_COUNT=0
ADMIN_AUTHENTICATED=false
MAX_RETRIES=3

HTTP_API_USER_URL="https://$DOMAIN_NAME:2113/users/"

sleep 3
while [ $RETRY_COUNT -lt $MAX_RETRIES ] && [ $ADMIN_AUTHENTICATED = false ]; do
    DEBUG_LOG "Trying to update users with default password"
    HTTP_RESPONSE=$(curl -s -D - -o /dev/null $HTTP_API_USER_URL -u "admin:$ADMIN_DEFAULT_PASSWORD")
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | grep -Fi HTTP/ | awk '{print $2}')
    DEBUG_LOG "http status is $HTTP_STATUS"
    if [[ $HTTP_STATUS =~ ^2[0-9][0-9]$ ]]; then
        DEBUG_LOG "Users API Endpoint is available: $HTTP_API_USER_URL"
        ADMIN_AUTHENTICATED=true
        update_users_and_acl $DOMAIN_NAME $ADMIN_DEFAULT_PASSWORD
        break
    else
        DEBUG_LOG "Failed to load Users API Endpoint: $HTTP_API_USER_URL. Status code: $HTTP_STATUS. Retrying..."
        RETRY_COUNT=$((RETRY_COUNT+1))
        sleep 3
    fi
done

RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ] && [ "$ADMIN_AUTHENTICATED" = "false" ]; do
    DEBUG_LOG "Trying to update users with previous password"
    HTTP_RESPONSE=$(curl -s -D - -o /dev/null $HTTP_API_USER_URL -u "admin:$ADMIN_PREVIOUS_PASSWORD")
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | grep -Fi HTTP/ | awk '{print $2}')
    if [[ $HTTP_STATUS =~ ^2[0-9][0-9]$ ]]; then
        DEBUG_LOG "Users API Endpoint is available: $HTTP_API_USER_URL"
        ADMIN_AUTHENTICATED=true
        update_users_and_acl $DOMAIN_NAME $ADMIN_PREVIOUS_PASSWORD
        break
    else
        DEBUG_LOG "Failed to load Users API Endpoint: $HTTP_API_USER_URL. Status code: $HTTP_STATUS. Retrying..."
        RETRY_COUNT=$((RETRY_COUNT+1))
        sleep 3
    fi
done

RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ] && [ "$ADMIN_AUTHENTICATED" = false ]; do
    DEBUG_LOG "Trying to update users with current password"
    HTTP_RESPONSE=$(curl -s -D - -o /dev/null $HTTP_API_USER_URL -u "admin:$ADMIN_CURRENT_PASSWORD")
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | grep -Fi HTTP/ | awk '{print $2}')
    if [[ $HTTP_STATUS =~ ^2[0-9][0-9]$ ]]; then
        DEBUG_LOG "Users API Endpoint is available: $HTTP_API_USER_URL"
        ADMIN_AUTHENTICATED=true
 	    update_users_and_acl $DOMAIN_NAME $ADMIN_CURRENT_PASSWORD
        break
    else
        DEBUG_LOG "Failed to load Users API Endpoint: $HTTP_API_USER_URL. Status code: $HTTP_STATUS. Retrying..."
        RETRY_COUNT=$((RETRY_COUNT+1))
        sleep 3
    fi
done