#!/bin/bash
# init-sequence.sh

set -e

echo "Starting initialization sequence..."

# Build libsecp256k1
echo "Building libsecp256k1..."
cd libsecp256k1
./autogen.sh
./configure --enable-module-recovery --enable-experimental --enable-module-generator
make
make install
cd ..

# Build Python extensions
echo "Building Python extensions..."
python3 setup.py build_ext --inplace

# Initialize databases
echo "Initializing databases..."

# Base Registry DB
echo "Setting up Base Registry database..."
docker-compose run --rm registry_base python3 -c "
import common.db.postgres as db
import common.config as conf
config = conf.DBConfig()
db.init_database(config)
"

# Revocation Registry DB
echo "Setting up Revocation Registry database..."
docker-compose run --rm registry_revocation python3 -c "
import common.db.postgres as db
import common.config as conf
config = conf.DBConfig()
db.init_database(config)
"

# Issuer DB  
echo "Setting up Issuer database..."
docker-compose run --rm issuer python3 -c "
import common.db.postgres as db
import common.config as conf
config = conf.DBConfig()
db.init_database(config)
"

# Verify database setup
echo "Verifying database setup..."
for service in registry_base registry_revocation issuer; do
    echo "Verifying $service database..."
    docker-compose run --rm $service python3 -c "
import common.db.postgres as db
import common.config as conf
config = conf.DBConfig()
assert db.verify_database_setup(config), 'Database verification failed'
"
done

# Start services
echo "Starting services..."
docker-compose up -d

# Wait for services
echo "Waiting for services to be ready..."
for port in 8000 8001 8010 8011 1337; do
    echo "Waiting for service on port $port..."
    while ! curl -k -s https://localhost:$port/health/liveness > /dev/null; do
        echo "Service on port $port not ready yet..."
        sleep 2
    done
    echo "Service on port $port is ready"
done

echo "Initialization complete!"
