#!/bin/bash
# troubleshoot.sh

check_certificates() {
    local cert_dir="cert"
    
    echo "Checking certificates..."
    
    # Check certificate directories exist
    for service in admin issuer verifier registry_base registry_revocation wallet; do
        if [ ! -d "$cert_dir/$service" ]; then
            echo "ERROR: Missing certificate directory for $service"
            return 1
        fi
        
        # Check key files
        if [ ! -f "$cert_dir/$service/ec_private.pem" ] || [ ! -f "$cert_dir/$service/ec_public.pem" ]; then
            echo "ERROR: Missing EC keys for $service"
            return 1
        fi
        
        if [ ! -f "$cert_dir/$service/rsa_private.pem" ] || [ ! -f "$cert_dir/$service/rsa_public.pem" ]; then
            echo "ERROR: Missing RSA keys for $service"
            return 1
        fi
    done
    
    # Check HSM specific files for issuer
    if [ ! -f "$cert_dir/issuer/hsm_ec521_pub.pem" ]; then
        echo "ERROR: Missing HSM public key for issuer"
        return 1
    fi
    
    echo "Certificate check passed"
    return 0
}

check_container_logs() {
    local service=$1
    
    echo "Checking logs for $service..."
    
    # Get container ID
    local container_id=$(docker ps -qf "name=$service")
    if [ -z "$container_id" ]; then
        echo "ERROR: Container for $service not found"
        return 1
    fi
    
    # Check logs for common errors
    if docker logs "$container_id" 2>&1 | grep -i "error\|exception\|failed"; then
        echo "Found errors in $service logs:"
        docker logs "$container_id" 2>&1 | grep -i "error\|exception\|failed"
        return 1
    fi
    
    echo "No errors found in $service logs"
    return 0
}

check_database_connections() {
    echo "Checking database connections..."
    
    for db in db_base db_revocation db_issuer; do
        local container_id=$(docker ps -qf "name=$db")
        if [ -z "$container_id" ]; then
            echo "ERROR: Database container $db not found"
            return 1
        fi
        
        # Check PostgreSQL is accepting connections
        if ! docker exec "$container_id" pg_isready -U postgres; then
            echo "ERROR: Database $db is not ready"
            return 1
        fi
    done
    
    echo "Database connections check passed"
    return 0
}

main() {
    echo "Starting troubleshooting..."
    
    local exit_code=0
    
    # Check certificates
    if ! check_certificates; then
        echo "Certificate check failed"
        exit_code=1
    fi
    
    # Check database connections
    if ! check_database_connections; then
        echo "Database connection check failed"
        exit_code=1
    fi
    
    # Check service logs
    for service in issuer verifier registry_base registry_revocation admin wallet; do
        if ! check_container_logs "$service"; then
            echo "Log check failed for $service"
            exit_code=1
        fi
    done
    
    if [ $exit_code -eq 0 ]; then
        echo "All checks passed"
    else
        echo "Some checks failed - see errors above"
    fi
    
    return $exit_code
}

main
