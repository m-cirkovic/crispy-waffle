#!/bin/bash

make_curl_request() {
    local url=$1
    local method=${2:-PATCH}  # Default to PATCH
    local data=$3
    local retries=3
    local attempt=1
    local wait_time=2

    while [ $attempt -le $retries ]; do
        if [ -n "$data" ]; then
            response=$(curl -k -s -X "$method" \
                -H "Content-Type: application/json" \
                -H "x-api-key: $API_KEY" \
                -d "$data" \
                "$url")
        else
            response=$(curl -k -s -X "$method" \
                -H "x-api-key: $API_KEY" \
                "$url")
        fi

        if [ $? -eq 0 ]; then
            echo "Request successful!"
            echo "Response: $response"
            return 0
        fi

        echo "Attempt $attempt failed. Retrying in $wait_time seconds..."
        sleep $wait_time
        attempt=$((attempt + 1))
    done

    echo "Failed after $retries attempts"
    return 1
}

# Configure issuer
echo "Configuring issuer..."

# Configure status list
echo "Configuring status list..."
make_curl_request "https://localhost:8000/admin/status-list"

# Configure metadata (using the test_system/files/issuer_metadata.json)
echo "Configuring metadata..."
if [ -f "test_system/files/issuer_metadata.json" ]; then
    make_curl_request "https://localhost:8000/oid4vc/admin/metadata" "POST" "@test_system/files/issuer_metadata.json"
else
    echo "Error: issuer_metadata.json not found!"
    exit 1
fi

echo "Configuration complete!"