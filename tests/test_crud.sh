#!/bin/bash

# Base URL
BASE_URL="http://localhost:8080"

# Test variables
USERNAME="testuser"
PASSWORD="testpassword"
ITEM_NAME="apple"
QUANTITY=5

echo "Testing User Creation..."
curl -X POST "$BASE_URL/users?username=$USERNAME&password=$PASSWORD"

echo -e "\nTesting User Listing..."
curl -X GET "$BASE_URL/users"

echo -e "\nTesting Login to Get JWT..."
JWT=$(curl -s -X POST "$BASE_URL/login?username=$USERNAME&password=$PASSWORD")
echo "JWT: $JWT"

echo -e "\nTesting Add Item to Cart..."
curl -X POST "$BASE_URL/cart" \
     -H "Authorization: Bearer $JWT" \
     -d "item_name=$ITEM_NAME&quantity=$QUANTITY"

echo -e "\nTesting List Items in Cart..."
curl -X GET "$BASE_URL/cart" \
     -H "Authorization: Bearer $JWT"

echo -e "\nTesting Invalid Token..."
curl -X GET "$BASE_URL/cart" \
     -H "Authorization: Bearer invalidtoken"

echo -e "\nFinished Testing!"

