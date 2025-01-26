#!/bin/bash

# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

set -e
# Move to where the script is located
cd $(dirname $0)

# Credential Creation
MY_IP="157.143.5.86"
DIR=cert

# Dev Issuer Onboarding
ISSUER_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8000"
REGISTRY_BASE_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8010"
REGISTRY_REVOCATION_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8011"
REGISTRY_IDENTITY_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8012"
ADMIN_SERVICE_URL="https://${HOST_PREFIX:-localhost}:1337"
ADMIN_HEADER_API_KEY="x-api-key: tergum_dev_key"

create_dotenv() {
    echo "# .env managed by setup_environment.sh" > .env
    # Static .env settings
    # api keys
    echo "REGISTRY_REVOCATION_API_KEY=revocation_dev_key" >> .env
    echo "REGISTRY_BASE_API_KEY=base_dev_key" >> .env
    echo "REGISTRY_IDENTITY_API_KEY=identity_dev_key" >> .env


}

load_env_file() {
    set -o allexport
    source .env 
    set +o allexport
}

install_venv() {
    if [ ! -d ".venv/" ]; then
        echo 'Create venv'
        python3.11 -m venv .venv 
        echo 'install dev dependencies'
        .venv/bin/pip install poetry
        .venv/bin/poetry install --no-root
    fi
}

install_other_dependencies() {
    if [[ ! "$(command -v softhsm2-util)" ]]
    then
        echo "Installing SoftHSM"
        sudo apt update
        # Includes pkcs11-tool, which is used to generate the keys
        sudo apt install opensc -y
        # Software Hardware Security Module to emulate hsm access
        sudo apt install softhsm2 -y
    fi
}

set_log_level() {
    LOG_LEVEL="INFO"
    echo "LOG_LEVEL=$LOG_LEVEL" >> .env
}

set_debug_mode() {
    echo "ENABLE_DEBUG_MODE=True" >> .env
}

generate_local_dev_certs() {
    echo "######################################"
    echo "Generating certs for $1"
    echo "######################################"
    WORKDIR=$DIR/$1
    mkdir $WORKDIR
    # RSA
    openssl req -x509 -newkey rsa:4096 -keyout $WORKDIR/rsa_private.pem -out $WORKDIR/rsa_public.pem -sha256 -days 3650 -nodes -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,IP:$MY_IP"
    # Elliptic Curve
    # sect571r1 : NIST/SECG curve over a 571 bit binary field
    openssl ecparam -genkey -name secp521r1 -out $WORKDIR/ec_private.pem
    openssl ec -in $WORKDIR/ec_private.pem -pubout -out $WORKDIR/ec_public.pem
}


generate_all_certs() {
    if [ ! -d "$DIR/" ]; then
        mkdir $DIR   
        for d in admin issuer verifier registry_base registry_revocation wallet registry_identity
        do
            generate_local_dev_certs $d    
        done
    else
        echo "Certificates already present."
    fi

    echo "######################################"
    echo "All Done. Enjoy your certs!"
}

initialize_databases() {
    echo "Initializing databases..."
    
    # Initialize base registry database
    docker compose exec -T db_base psql -U postgres -c "CREATE DATABASE registry;" || true
    docker compose run --rm registry_base python3 -c "
    import common.db.postgres as db
    import common.config as conf
    config = conf.DBConfig()
    db.init_database(config)
    "
        
    # Initialize revocation registry database
    docker compose exec -T db_revocation psql -U postgres -c "CREATE DATABASE registry;" || true
    docker compose run --rm registry_revocation python3 -c "
    import common.db.postgres as db
    import common.config as conf
    config = conf.DBConfig()
    db.init_database(config)
    "

    # Initialize identity registry database
    docker compose exec -T db_identity psql -U postgres -c "CREATE DATABASE registry;" || true
    docker compose run --rm registry_identity python3 -c "
    import common.db.postgres as db
    import common.config as conf
    config = conf.DBConfig()
    db.init_database(config)
    "
        
    # Run alembic migrations
    echo "Running database migrations..."
    docker compose run --rm registry_base alembic upgrade head
    docker compose run --rm registry_revocation alembic upgrade head
    docker compose run --rm registry_identity alembic upgrade head
}

generate_hsm_certs() {
    echo "Generating a softhsm cert for the issuer"
    # Note: This requires the path in softhsm2.conf to be correct and the path to softhsm2.conf to be set
    # export SOFTHSM2_CONF=$(pwd)/softhsm2.conf
    if [[ -z "${SOFTHSM2_CONF}" ]]; then
        source hsm_environment_variables.sh
    fi
    echo "Using SOFTHSM2_CONF at $SOFTHSM2_CONF"
    # Copy shared objects library to project dir
    SOFTHSM_LOCATION=$(dpkg --search libsofthsm2.so | head -n 1 | cut -d " " -f 2)
    cp $SOFTHSM_LOCATION .
    # Write env variables
    echo "HSM_LIBRARY=$HSM_LIBRARY" >> .env
    echo "HSM_TOKEN=$HSM_TOKEN" >> .env
    echo "HSM_PIN=$HSM_PIN" >> .env
    echo "HSM_LABEL=$HSM_LABEL" >> .env
    echo "HSM_SIGNING_ALGORITHM=$HSM_SIGNING_ALGORITHM" >> .env
    if [ ! -d "$DIR/hsm" ]; then
        # Setup SoftHSM if not already set up
        mkdir $DIR/hsm
        # Initialize the slot
        softhsm2-util --init-token --slot 0 --label $HSM_TOKEN --pin $HSM_PIN --so-pin 4321
        #Generate the EC key
        pkcs11-tool --module=$SOFTHSM_LOCATION --token-label $HSM_TOKEN --pin $HSM_PIN --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp521r1 --usage-sign --label $HSM_LABEL
        # Extract the public key
        pkcs11-tool --module=$SOFTHSM_LOCATION --token-label $HSM_TOKEN --label $HSM_LABEL --read-object --type pubkey -o $DIR/issuer/hsm_ec521_pub.key
        # Convert the public key for the issuer
        # Note: This is only necessary for this script. 
        # The issuer extracts the public key itself from the HSM
        openssl ec -pubin -inform DER -in $DIR/issuer/hsm_ec521_pub.key -outform PEM -out $DIR/issuer/hsm_ec521_pub.pem
    fi
}

workaround_ci_permissions() {
    if [ ! -d "$DIR/issuer/hsm" ]; then
        chmod -R 777 ./cert # container user uid may not be the same as user id which then results in permission issues in the CI tests
    fi
}

# Modify wait_for_liveness to be more robust
wait_for_liveness() {
    local SERVICE_URL=$1
    local MAX_RETRIES=30
    local retry_count=0
    
    echo "Waiting for $SERVICE_URL to be ready..."
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        # First check if the service responds at all
        local STATUS_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" $SERVICE_URL/health/liveness)
        
        if [ "$STATUS_CODE" = "200" ] || [ "$STATUS_CODE" = "204" ]; then
            # If service responds, check health status
            local HEALTH_STATUS=$(curl -k -s $SERVICE_URL/health/readiness)
            if echo "$HEALTH_STATUS" | grep -q '"status":"HEALTHY"'; then
                echo "$SERVICE_URL is healthy"
                return 0
            fi
        fi
        
        retry_count=$((retry_count + 1))
        echo "Attempt $retry_count of $MAX_RETRIES - service not ready (status: $STATUS_CODE)"
        sleep 2
    done
    
    echo "Service $SERVICE_URL failed to become healthy after $MAX_RETRIES attempts"
    return 1
}

# Update start_admin_containers
start_admin_containers() {
    mkdir -p wallet_data
    
    echo "UID=$(id -u)" >> .env
    echo "GID=$(id -g)" >> .env
    
    echo "Starting database containers..."
    docker compose up -d db_base db_revocation db_identity
    sleep 5 # Give databases time to initialize
    
    echo "Initializing databases..."
    initialize_databases
    
    echo "Starting registry services..."
    docker compose up -d admin registry_base registry_revocation registry_identity
    
    echo "Waiting for services to be ready..."
    if ! wait_for_liveness $REGISTRY_BASE_SERVICE_URL; then
        echo "Registry Base failed to start" >&2
        return 1
    fi
    if ! wait_for_liveness $REGISTRY_REVOCATION_SERVICE_URL; then
        echo "Registry Revocation failed to start" >&2
        return 1
    fi
    if ! wait_for_liveness $REGISTRY_IDENTITY_SERVICE_URL; then
        echo "Registry Identity failed to start" >&2
        return 1
    fi
    
    echo "All admin services are ready!"
}

create_status_list_config() {
    # Creates a status list and returns the id
    ISSUER_ID=$1
    PURPOSE=$2

    STATUS_LIST_REGISTRATION=$(curl -X PUT $ADMIN_SERVICE_URL/issuer/$ISSUER_ID/status-list -k -H "$ADMIN_HEADER_API_KEY")
    STATUS_LIST_ID=$(echo $STATUS_LIST_REGISTRATION | jq -r '.id')
    echo "{\"status_list_id\": \"$STATUS_LIST_ID\", \"purpose\": \"$PURPOSE\"}"
}


onboard_dev_issuer() {
    # Onboarding Process
    # Represents the Registry Admin onboarding a new issuer
    B64_PK=$(base64 -w 0 $DIR/issuer/ec_public.pem)
    B64_HSM_PK=$(base64 -w 0 $DIR/issuer/hsm_ec521_pub.pem)
    DATA="[{\"key_type\": \"EC\", \"base64_encoded_key\": \"$B64_PK\"},{\"key_type\": \"EC\", \"base64_encoded_key\": \"$B64_HSM_PK\"}]"
    echo "Registering Public Key at Registry"
    REGISTRATION=$(curl -X PUT $ADMIN_SERVICE_URL/issuer -k -H "$ADMIN_HEADER_API_KEY" -H "Content-Type: application/json" -d "$DATA")
    ISSUER_ID=$(echo $REGISTRATION | jq -r '.id')   
    echo "New Issuer ID is $ISSUER_ID"
    echo "Creating Status Lists"
    REVOCATION_STATUS_LIST_CONFIG=$(create_status_list_config $ISSUER_ID revocation)
    SUSPENSION_STATUS_LIST_CONFIG=$(create_status_list_config $ISSUER_ID suspension)

    export ISSUER_ID=$ISSUER_ID
    export STATUS_LIST_CONFIG="[$REVOCATION_STATUS_LIST_CONFIG, $SUSPENSION_STATUS_LIST_CONFIG]"
    echo "ISSUER_ID=$ISSUER_ID" >> .env
    echo "STATUS_LIST_CONFIG=$STATUS_LIST_CONFIG" >> .env
}


configure_systems() {
    echo "Starting services..."
    docker compose up -d
    
    echo "Waiting for services to be ready..."
    ./wait-health.sh
    if [ $? -ne 0 ]; then
        echo "Services failed to start properly"
        exit 1
    fi
    
    echo "Configuring services..."
    ./config-services.sh
    if [ $? -ne 0 ]; then
        echo "Service configuration failed"
        exit 1
    fi
    
    echo "Configuration complete!"
}

bulid_images() {
    echo "Build docker images"
    docker compose build
    echo "done"
}

configure_pytest() {
    echo "[pytest]" > pytest.ini
    echo "env = " >> pytest.ini
    echo "    SOFTHSM2_CONF=$SOFTHSM2_CONF" >> pytest.ini
    echo "    HSM_LIBRARY=$HSM_LIBRARY" >> pytest.ini
    echo "    HSM_TOKEN=$HSM_TOKEN" >> pytest.ini
    echo "    HSM_PIN=$HSM_PIN" >> pytest.ini
    echo "    HSM_LABEL=$HSM_LABEL" >> pytest.ini
    echo "    HSM_SIGNING_ALGORITHM=$HSM_SIGNING_ALGORITHM" >> pytest.ini
    echo "    ISSUER_ID=$ISSUER_ID" >> pytest.ini
    # echo "    STATUS_LIST_CONFIG=$STATUS_LIST_CONFIG" >> pytest.ini
    # pytest-env doesn't load inis correctly and can not load a string looking like a json
    echo "    STATUS_LIST_CONFIG=[]" >> pytest.ini
    echo "    ENABLE_DEBUG_MODE=True" >> pytest.ini
}

echo "###########################"
echo "Setting environment to dev"
create_dotenv
set_log_level
set_debug_mode
load_env_file
echo "###########################"
echo "Installing python venv"
install_venv
install_other_dependencies
echo "###########################"
echo "Generating Key Material"
generate_all_certs
generate_hsm_certs
workaround_ci_permissions  
echo "###########################"
echo "Building Container Images"
bulid_images
echo "###########################"
echo "Starting Admin Containers"
start_admin_containers
echo "###########################"
echo "Onboarding the dev issuer"
onboard_dev_issuer
echo "###########################"
echo "Configuring Issuer"
configure_systems
echo "###########################"
echo "Creating pytest.ini"
configure_pytest
echo "###########################"
echo "All Done!"
