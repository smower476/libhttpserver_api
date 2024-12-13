#!/bin/bash
ADDRESS=localhost:8080
LOGIN=max
PASSWORD=secretsecret
NEW_PASSWORD=newsecret
# Delete user
curl -X POST http://$ADDRESS/delete-user -d "username=$LOGIN" 
printf "\n"

# Create user
curl -X POST http://$ADDRESS/add-user -d "username=$LOGIN&password=$PASSWORD"
printf "\n"

# Get JWT token
JWT=$(curl -X POST http://$ADDRESS/login -d "username=$LOGIN&password=$PASSWORD")
echo $JWT
printf "\n"

# Add to cart
curl -X POST http://$ADDRESS/add-to-cart -d "item_name=apple&quantity=2" -H "Authorization: Bearer $JWT"
printf "\n"

# Get cart
curl -X POST http://$ADDRESS/get-cart -H "Authorization: Bearer $JWT"
printf "\n"

# Update password
curl -X POST http://$ADDRESS/update-password -d "username=$LOGIN&new_password=$NEW_PASSWORD"
printf "\n"

# Delete user
curl -X POST http://$ADDRESS/delete-user -d "username=$LOGIN" 
printf "\n"
