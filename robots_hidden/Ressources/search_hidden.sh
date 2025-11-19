#!/bin/bash
BASE_URL="http://192.168.1.16/.hidden/"

function searchDirectory() {
    local url=$1

    # sleep 0.05
    
    content=$(curl -s "$url" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Extract all links from the HTML
    links=$(echo "$content" | grep -oP 'href="\K[^"]+')
    
    for link in $links; do
        # Skip the parent directory link
        if [[ "$link" == "../" ]] || [[ "$link" == ".." ]]; then
            continue
        fi
        
        full_url="${url}${link}"
        
        # Check if it's a directory (ends with /)
        if [[ "$link" == */ ]]; then
            # It's a directory, search it recursively
            searchDirectory "$full_url"
        else
            # It's a file, download its content
            file_content=$(curl -s "$full_url" 2>/dev/null)
            
            # Check if it contains a 64-character hex string (the flag)
            if [[ "$file_content" =~ [a-f0-9]{64} ]]; then
                echo ""
                echo "============================================================"
                echo "FLAG FOUND!"
                echo "URL: $full_url"
                echo "Content: $file_content"
                echo "============================================================"
                echo ""
            fi
        fi
    done
}

echo "Searching for flag in /.hidden/ directory..."
searchDirectory "$BASE_URL"
echo "Search complete!"