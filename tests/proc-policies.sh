#!/bin/bash

# cd to script
cd "$(dirname "$0")"

# Sort
#find policies -name "*.json" -exec jq --sort-keys . {} \; -exec sh -c 'jq --sort-keys . "$1" > tmp && mv tmp "$1"' _ {} \;

# Use Python to custom-sort the keys so "Id" is first, and then "Version", and then ...
for file in policies/*.json; do
    echo "Sorting keys in $file"
    python3 -c '
import json
import sys

def custom_sort_keys(d):
    # Sort keys with the following order:
    # * Id
    # * Version
    # * Statement
    # * Sid
    # * Effect
    # * Principal
    # * NotPrincipal
    # * Action
    # * NotAction
    # * Resource
    # * NotResource
    # * Condition
    sorted_keys = sorted(d.keys(), key=lambda k: (
        k != "Id",
        k != "Version",
        k != "Statement",
        k != "Sid",
        k != "Effect",
        k != "Principal",
        k != "NotPrincipal",
        k != "Action",
        k != "NotAction",
        k != "Resource",
        k != "NotResource",
        k != "Condition",
        k
    ))
    return {k: d[k] for k in sorted_keys}

with open(sys.argv[1]) as f:
    data = json.load(f)
sorted_data = custom_sort_keys(data)
# Also sort "Statement" if it exists (could be object or array of objects)
if "Statement" in sorted_data:
    if isinstance(sorted_data["Statement"], list):
        sorted_data["Statement"] = [custom_sort_keys(stmt) for stmt in sorted_data["Statement"]]
        # If length is 1, we can simplify it to a single object
        if len(sorted_data["Statement"]) == 1:
            sorted_data["Statement"] = sorted_data["Statement"][0]
    elif isinstance(sorted_data["Statement"], dict):
        sorted_data["Statement"] = custom_sort_keys(sorted_data["Statement"])
print(json.dumps(sorted_data, indent=2))
' "$file" > "${file%.json}.sorted.json"
    mv "${file%.json}.sorted.json" "$file"
done
