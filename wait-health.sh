#!/bin/bash

wait_for_service() {
    local service_url=$1
    local max_attempts=30
    local attempt=1
    local wait_time=2

    echo "Waiting for service at ${service_url}..."
    
    while [ $attempt -le $max_attempts ]; do
        # Try curl with -k to ignore SSL certificate validation
        response=$(curl -k -s -o /dev/null -w "%{http_code}" "${service_url}/health/liveness")
        
        if [ "$response" = "200" ]; then
            echo "Service at ${service_url} is ready!"
            return 0
        fi
        
        echo "Attempt $attempt of $max_attempts: Service not ready yet (status: ${response})"
        sleep $wait_time
        attempt=$((attempt + 1))
    done
    
    echo "Service at ${service_url} failed to become ready after $max_attempts attempts"
    return 1
}

# Wait for required services
services=(
    "https://localhost:8000"  # issuer
    "https://localhost:8010"  # registry_base
    "https://localhost:8011"  # registry_revocation
)

for service in "${services[@]}"; do
    if ! wait_for_service "$service"; then
        echo "Service startup failed"
        exit 1
    fi
done

echo "All services are ready!"