#!/bin/bash
# deploy-app.sh - Automated deployment script for the Vulnerable Web App
# This script automates the process of building and deploying the application to Azure Container Instances

# Set variables
RG="vvdcdemo"
ACR_NAME="projectfacr"
CONTAINER_NAME="vulnerable-web-app"
IMAGE_NAME="$ACR_NAME.azurecr.io/$CONTAINER_NAME:latest"
TIMESTAMP=$(date +%s)
DNS_LABEL="vvdcdemo-${TIMESTAMP}" # Add timestamp to ensure uniqueness
SECRET_KEY=$(openssl rand -hex 16) # Generate a secure random key

# Print banner
echo "============================================================="
echo "  Vulnerable Web App Deployment to Azure Container Instances"
echo "============================================================="
echo ""
echo "This script will deploy the intentionally vulnerable web app"
echo "to Azure for educational purposes."
echo ""
echo "Using the following configuration:"
echo "- Resource Group: $RG"
echo "- Container Registry: $ACR_NAME.azurecr.io"
echo "- Container Name: $CONTAINER_NAME"
echo "- DNS Label: $DNS_LABEL (unique with timestamp)"
echo "- Secret Key: ${SECRET_KEY:0:4}...${SECRET_KEY:28:4} (truncated for security)"
echo ""
echo "This will take approximately 3-5 minutes to complete."
echo "============================================================="
echo ""

# Build the Docker image
echo "[1/6] Building Docker image..."
docker build -t $CONTAINER_NAME:latest -f Dockerfile.prod .

if [ $? -ne 0 ]; then
    echo "ERROR: Docker build failed. Please check your Dockerfile.prod and try again."
    exit 1
fi

# Login to Azure and ACR
echo "[2/6] Logging into Azure and ACR..."
az account show >/dev/null 2>&1
if [ $? -ne 0 ]; then
    az login
fi

az acr login --name $ACR_NAME
if [ $? -ne 0 ]; then
    echo "ERROR: Could not login to ACR. Please check your credentials and try again."
    exit 1
fi

# Tag and push the image
echo "[3/6] Tagging and pushing image to ACR..."
docker tag $CONTAINER_NAME:latest $IMAGE_NAME
docker push $IMAGE_NAME

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to push image to ACR. Please check your permissions and try again."
    exit 1
fi

# Get ACR credentials
echo "[4/6] Getting ACR credentials..."
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query "username" -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

# Create the container instance
echo "[5/6] Deploying container to ACI..."
az container create \
  --resource-group $RG \
  --name $CONTAINER_NAME \
  --image $IMAGE_NAME \
  --registry-username $ACR_USERNAME \
  --registry-password $ACR_PASSWORD \
  --dns-name-label $DNS_LABEL \
  --ports 5000 \
  --os-type Linux \
  --environment-variables \
    SECRET_KEY=$SECRET_KEY \
    FLASK_DEBUG=0 \
    ALLOW_PRIVESC=1 \
  --cpu 1 \
  --memory 1.5

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create container instance. Please check the error message above."
    exit 1
fi

# Get the FQDN
echo "[6/6] Getting access URL..."
FQDN=$(az container show --resource-group $RG --name $CONTAINER_NAME --query "ipAddress.fqdn" -o tsv)
REGION=$(az account show --query location -o tsv)

echo ""
echo "============================================================="
echo "    DEPLOYMENT COMPLETED SUCCESSFULLY!"
echo "============================================================="
echo ""
echo "Your vulnerable web app is now available at:"
echo "http://$FQDN:5000"
echo ""
echo "Run commands from the OWASP_Vulnerabilities_Runbook.md to demonstrate vulnerabilities."
echo ""
echo "For privilege escalation demo:"
echo "1. Upload reverse shell file (examples/azure_reverse_shell.php)"
echo "2. Access it at: http://$FQDN:5000/uploads/azure_reverse_shell.php"
echo "3. From the shell, run: sudo -l"
echo "4. Escalate to root using: sudo /tmp/backup_app.sh '; /bin/bash; echo'"
echo ""
echo "Remember to stop the container after your class demo:"
echo "az container stop --resource-group $RG --name $CONTAINER_NAME"
echo ""
echo "To start it again before your next class:"
echo "az container start --resource-group $RG --name $CONTAINER_NAME"
echo ""
echo "To check container status:"
echo "az container show --resource-group $RG --name $CONTAINER_NAME --query \"containers[0].instanceView.currentState.state\""
echo "=============================================================" 