# =====================================================================
# Combined Infrastructure Deployment Script
# Creates all Azure resources + Front Door configuration
# Be sure to run: az login
# Verify subscription: az account show
# =====================================================================

$ErrorActionPreference = "Stop"

# =====================================================================
# VARIABLES - Edit these for your environment
# =====================================================================

$environment = "prod"  # Options: dev, qa, prod, etc.

# Region settings
$location = "southafricanorth"
$staticWebAppLocation = "westeurope"

# Repository URLs
$frontEndRepositoryUrl = ""
$cmsRepositoryUrl = ""
$frontEndBranchName = "master"
$cmsBranchName = "master"

# Resource naming (all driven by $environment)
$prefix="ecpl"
$resourceGroupName = "$prefix-websites-rg-$environment"
$frontEndStaticWebAppName = "$prefix-frontend-$environment"
$cmsStaticWebAppName = "$prefix-cms-$environment"
$storageAccountName = "${prefix}storage$environment"
$appServicePlanName = "$prefix-appserviceplan-$environment"
$appServiceName = "$prefix-appservice-$environment"
$keyVaultName = "$prefix-keyvault-$environment"
$mysqlServerName = "${prefix}mysqlserver$environment"
$mysqlDatabaseName = "ecplsite"
$logAnalyticsWorkspaceName = "$prefix-loganalytics-$environment"
$appInsightsName = "$prefix-appinsights-$environment"
$mongoDbDatabaseName = "petitions"
$mySQLVersion="8.4"

# Storage containers
$containerName = "zvetest-3"
$docsStorageContainerName = "zvetest-3"

# this should preferably be the frontdoor URL with the custom domain. For now can set it to storage account
$docStorageURL="https://$storageAccountName.blob.core.windows.net/$docsStorageContainerName/"
# Front Door naming (SHARED across all environments - not environment-specific)
$frontDoorResourceGroup = ""
$frontDoorProfileName = ""
$acsResourceName=""
$acsResourceGroupName=""
$acsEmailResourceName = ""

# person who will get the email too. 
$acsPetitionsEmail=""
$recaptchaSecretKey = "" 
# SKUs and sizing
$staticwebSiteSku = "Standard"
$storageSku = "Standard_ZRS"
$appServicePlanSKU = "P0v3"
$workerCount = 2
$mysqlSku = "Standard_B1ms"



# Zone redundancy settings (only applied for prod environment)
$zoneRedundant = $true

# Enable WAF protection (set to $true to enable, $false to skip)
$WAF = $true

# MySQL credentials
$mysqlAdminUserName = ""
$mysqlAdminPassword = ""  # Replace with secure password or use Key Vault

# Front Door endpoint/origin/route names (environment-specific for shared Front Door)
$FD_ENDPOINT_STORAGE = "fd-endpoint-storage-$environment"
$FD_ENDPOINT_WEBMANAGER = "fd-endpoint-webmanager-$environment"
$FD_ENDPOINT_PUBLICSITE = "fd-endpoint-publicsite-$environment"
$FD_ENDPOINT_API = "fd-endpoint-api-$environment"

$OG_STORAGE = "og-storage-$environment"
$OG_WEBMANAGER = "og-webmanager-$environment"
$OG_PUBLICSITE = "og-publicsite-$environment"
$OG_API = "og-api-$environment"

$ORIGIN_STORAGE = "origin-storage-$environment"
$ORIGIN_WEBMANAGER = "origin-webmanager-$environment"
$ORIGIN_PUBLICSITE = "origin-publicsite-$environment"
$ORIGIN_API = "origin-api-$environment"

$ROUTE_STORAGE = "route-storage-$environment"
$ROUTE_WEBMANAGER = "route-webmanager-$environment"
$ROUTE_PUBLICSITE = "route-publicsite-$environment"
$ROUTE_API = "route-api-$environment"

# =====================================================================
# DETECT CURRENT IP ADDRESS (used for firewall rules)
# =====================================================================

$currentIp = $null
try {
    $currentIp = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip
} catch {
    try {
        $currentIp = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 5)
    } catch {
        try {
            $currentIp = (Invoke-RestMethod -Uri "https://icanhazip.com" -TimeoutSec 5).Trim()
        } catch {
            Write-Output "⚠ Could not determine public IP address automatically"
            $currentIp = "0.0.0.0"
        }
    }
}

if ($currentIp -eq "0.0.0.0") {
    Write-Output "ℹ Using 0.0.0.0 for firewall rules (allows Azure services only)"
} else {
    Write-Output "ℹ Detected current IP address: $currentIp"
}

# =====================================================================
# PART 1: CREATE CORE RESOURCES
# =====================================================================

Write-Output ""
Write-Output "=========================================="
Write-Output "PART 1: Creating Core Azure Resources"
Write-Output "Environment: $environment"
Write-Output "=========================================="
Write-Output ""

# Create resource group
$rgExists = az group exists --name $resourceGroupName --output tsv
if ($rgExists -eq "true") {
    Write-Output "⚠ Resource group '$resourceGroupName' already exists"
} else {
    az group create --name $resourceGroupName --location $location
    az group update --name $resourceGroupName 
    Write-Output "✓ Resource group '$resourceGroupName' created in '$location'"
}

# Create Static Web App 1 (Frontend)
$swa1Exists = az staticwebapp show --name $frontEndStaticWebAppName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($swa1Exists) {
    Write-Output "⚠ Static Web App '$frontEndStaticWebAppName' already exists"
} else {
    az staticwebapp create `
        --name $frontEndStaticWebAppName `
        --resource-group $resourceGroupName `
        --location $staticWebAppLocation `
        --source $frontEndRepositoryUrl `
        --sku $staticwebSiteSku `
        --login-with-ado `
        --branch $frontEndBranchName
    Write-Output "✓ Static Web App '$frontEndStaticWebAppName' created"
}

# Create Static Web App 2 (CMS)
$swa2Exists = az staticwebapp show --name $cmsStaticWebAppName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($swa2Exists) {
    Write-Output "⚠ Static Web App '$cmsStaticWebAppName' already exists"
} else {
    az staticwebapp create `
        --name $cmsStaticWebAppName `
        --resource-group $resourceGroupName `
        --location $staticWebAppLocation `
        --source $cmsRepositoryUrl `
        --sku $staticwebSiteSku `
        --login-with-ado `
        --branch $cmsBranchName
    Write-Output "✓ Static Web App '$cmsStaticWebAppName' created"
}

# Create Storage Account (with zone redundancy only if prod and zoneRedundant is true)
$storageExists = az storage account show --name $storageAccountName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($storageExists) {
    Write-Output "⚠ Storage account '$storageAccountName' already exists"
} else {
    if ($environment -eq "prod" -and $zoneRedundant) {
        $storageSku = "Standard_ZRS"
        Write-Output "Creating Storage Account with zone redundancy (prod environment)..."
    } else {
        $storageSku = "Standard_LRS"
        Write-Output "Creating Storage Account with locally redundant storage..."
    }

    az storage account create `
        --name $storageAccountName `
        --resource-group $resourceGroupName `
        --location $location `
        --allow-blob-public-access true `
        --https-only true `
        --public-network-access Enabled `
        --sku $storageSku `
        --kind StorageV2

    if ($environment -eq "prod" -and $zoneRedundant) {
        Write-Output "✓ Storage account '$storageAccountName' created with zone redundancy"
    } else {
        Write-Output "✓ Storage account '$storageAccountName' created with locally redundant storage"
    }
}

# Set CORS on storage account
az storage cors add `
    --methods DELETE GET HEAD MERGE POST OPTIONS PUT `
    --origins "*" `
    --services b `
    --account-name $storageAccountName `
    --max-age 2000 `
    --allowed-headers "*" `
    --exposed-headers "*"
Write-Output "✓ CORS configured on storage account"

# Create blob container
$containerExists = az storage container exists --name $containerName --account-name $storageAccountName --query "exists" --output tsv 2>$null
if ($containerExists -eq "true") {
    Write-Output "⚠ Blob container '$containerName' already exists"
} else {
    az storage container create `
        --name $containerName `
        --account-name $storageAccountName `
        --public-access blob
    Write-Output "✓ Blob container '$containerName' created"
}



# Create App Service Plan (with zone redundancy only if prod and zoneRedundant is true)
$aspExists = az appservice plan show --name $appServicePlanName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($aspExists) {
    Write-Output "⚠ App Service Plan '$appServicePlanName' already exists"
    if ($environment -eq "prod" -and $zoneRedundant) {
        Write-Output "✓ App Service Plan '$appServicePlanName' already exists with zone redundancy"
    } else {
        Write-Output "✓ App Service Plan '$appServicePlanName' already exists"
    }
} else {

    if ($environment -eq "prod" -and $zoneRedundant) {
            az appservice plan create `
        --name $appServicePlanName `
        --resource-group $resourceGroupName `
        --location $location `
        --sku $appServicePlanSKU `
        --is-linux `
       --zone-redundant `
        --number-of-workers $workerCount
    } else {
          az appservice plan create `
        --name $appServicePlanName `
        --resource-group $resourceGroupName `
        --location $location `
        --sku $appServicePlanSKU `
        --is-linux `
        --number-of-workers $workerCount
    }



    if ($environment -eq "prod" -and $zoneRedundant) {
        Write-Output "✓ App Service Plan '$appServicePlanName' created with zone redundancy"
    } else {
        Write-Output "✓ App Service Plan '$appServicePlanName' created"
    }
}



# Create App Service with system-managed identity
$appServiceExists = az webapp show --name $appServiceName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($appServiceExists) {
    Write-Output "⚠ App Service '$appServiceName' already exists"
} else {
    az webapp create `
        --name $appServiceName `
        --resource-group $resourceGroupName `
        --plan $appServicePlanName `
        --runtime "NODE:24-lts" `
        --assign-identity [system]
    Write-Output "✓ App Service '$appServiceName' created with system-managed identity"
}

# Get the App Service's managed identity principal ID
$appServiceIdentityId = az webapp identity show `
    --name $appServiceName `
    --resource-group $resourceGroupName `
    --query "principalId" `
    --output tsv
if ($appServiceIdentityId) {
    Write-Output "✓ App Service managed identity principal ID: $appServiceIdentityId"
} else {
    Write-Output "⚠ App Service identity not found - may need to enable manually"
}

# give the app service identity access to the storage account
az role assignment create `
    --role "Storage Blob Data Contributor" `
    --assignee $appServiceIdentityId `
    --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName"

# give current user access to storage account
$currentUserId = az ad signed-in-user show --query id --output tsv
az role assignment create `
    --role "Storage Blob Data Contributor" `
    --assignee $currentUserId `
    --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName"    

# Set CORS on App Service
az webapp cors add `
    --name $appServiceName `
    --resource-group $resourceGroupName `
    --allowed-origins "*"
Write-Output "✓ CORS configured on App Service"

# Create Key Vault
$kvExists = az keyvault show --name $keyVaultName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($kvExists) {
    Write-Output "⚠ Key Vault '$keyVaultName' already exists"
} else {
    az keyvault create `
        --name $keyVaultName `
        --resource-group $resourceGroupName `
        --location $location
    Write-Output "✓ Key Vault '$keyVaultName' created"
}

# Grant App Service managed identity access to Key Vault secrets
# Assign "Key Vault Secrets User" role to the App Service identity
az role assignment create `
    --role "Key Vault Secrets User" `
    --assignee $appServiceIdentityId `
    --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$keyVaultName"
Write-Output "✓ App Service granted access to Key Vault "

# grant current user full access to key vault
$currentUserId = az ad signed-in-user show --query id --output tsv

az role assignment create `
    --role "Key Vault Administrator" `
    --assignee $currentUserId `
    --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$keyVaultName"

# Store MySQL password in Key Vault
az keyvault secret set `
    --vault-name $keyVaultName `
    --name "MySQLAdminPassword" `
    --value $mysqlAdminPassword
Write-Output "✓ MySQL password stored in Key Vault"

# Create MySQL Flexible Server
$mysqlExists = az mysql flexible-server show --name $mysqlServerName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($mysqlExists) {
    Write-Output "⚠ MySQL Flexible Server '$mysqlServerName' already exists"
} else {
    Write-Output "ℹ Creating MySQL server with IP range: $currentIp-$currentIp"
    
    az mysql flexible-server create `
        --name $mysqlServerName `
        --resource-group $resourceGroupName `
        --location $location `
        --admin-user $mysqlAdminUserName `
        --admin-password $mysqlAdminPassword `
        --sku-name $mysqlSku `
        --zone 1 `
        --version $mySQLVersion `
        --public-access "$currentIp-$currentIp"
    Write-Output "✓ MySQL Flexible Server '$mysqlServerName' created"
}

# Add firewall rule for Azure services
$mysqlFwRuleExists = az mysql flexible-server firewall-rule show --name $mysqlServerName --resource-group $resourceGroupName --rule-name AllowAzureIPs --query "name" --output tsv 2>$null
if ($mysqlFwRuleExists) {
    Write-Output "⚠ MySQL firewall rule 'AllowAzureIPs' already exists"
} else {
    az mysql flexible-server firewall-rule create `
        --name $mysqlServerName `
        --resource-group $resourceGroupName `
        --rule-name AllowAzureIPs `
        --start-ip-address 0.0.0.0 `
        --end-ip-address 0.0.0.0
    Write-Output "✓ MySQL firewall rule added for Azure services"
}

# Create MySQL database
$mysqlDbExists = az mysql flexible-server db show --database-name $mysqlDatabaseName --resource-group $resourceGroupName --server-name $mysqlServerName --query "name" --output tsv 2>$null
if ($mysqlDbExists) {
    Write-Output "⚠ MySQL Database '$mysqlDatabaseName' already exists"
} else {
    az mysql flexible-server db create `
        --database-name $mysqlDatabaseName `
        --resource-group $resourceGroupName `
        --server-name $mysqlServerName
    Write-Output "✓ MySQL Database '$mysqlDatabaseName' created"
}

# Create Log Analytics Workspace
$lawExists = az monitor log-analytics workspace show --resource-group $resourceGroupName --workspace-name $logAnalyticsWorkspaceName --query "name" --output tsv 2>$null
if ($lawExists) {
    Write-Output "⚠ Log Analytics Workspace '$logAnalyticsWorkspaceName' already exists"
} else {
    az monitor log-analytics workspace create `
        --resource-group $resourceGroupName `
        --workspace-name $logAnalyticsWorkspaceName `
        --location $location
    Write-Output "✓ Log Analytics Workspace '$logAnalyticsWorkspaceName' created"
}

# Create Application Insights
$appInsightsExists = az monitor app-insights component show --app $appInsightsName --resource-group $resourceGroupName --query "name" --output tsv 2>$null
if ($appInsightsExists) {
    Write-Output "⚠ Application Insights '$appInsightsName' already exists"
} else {
    az monitor app-insights component create `
        --app $appInsightsName `
        --location $location `
        --resource-group $resourceGroupName `
        --workspace $logAnalyticsWorkspaceName
    Write-Output "✓ Application Insights '$appInsightsName' created"
}

# get the app insights instrumentation key
$appInsightsKey = az monitor app-insights component show `
    --app $appInsightsName `
    --resource-group $resourceGroupName `
    --query "instrumentationKey" `
    --output tsv
Write-Output "✓ Application Insights instrumentation key retrieved"

# Store Application Insights key in Key Vault
az keyvault secret set `
    --vault-name $keyVaultName `
    --name "ApplicationInsightsKey" `
    --value $appInsightsKey
Write-Output "✓ Application Insights key stored in Key Vault"

# Get storage connection string
$storageConnectionString = az storage account show-connection-string `
    --name $storageAccountName `
    --resource-group $resourceGroupName `
    --query connectionString `
    --output tsv

# Store storage connection string in Key Vault
az keyvault secret set `
    --vault-name $keyVaultName `
    --name "StorageConnectionString" `
    --value $storageConnectionString
Write-Output "✓ Storage connection string stored in Key Vault"

# Create MongoDB Cluster (Cosmos DB vCore)
$mongoClusterName = "$prefix-mongo-$environment"
$mongoAdminUser = ""
$mongoAdminPassword = ""  # Replace with secure password or use Key Vault

# Store MongoDB password in Key Vault
az keyvault secret set `
    --vault-name $keyVaultName `
    --name "MongoDBAdminPassword" `
    --value $mongoAdminPassword
Write-Output "✓ MongoDB password stored in Key Vault"

$mongoExists = az cosmosdb mongocluster show --cluster-name $mongoClusterName --resource-group $resourceGroupName --query "name" --output tsv 
if ($mongoExists) {
    Write-Output "⚠ MongoDB Cluster '$mongoClusterName' already exists"
} else {
    az cosmosdb mongocluster create `
        --cluster-name $mongoClusterName `
        --resource-group $resourceGroupName `
        --location $location `
        --administrator-login $mongoAdminUser `
        --administrator-login-password $mongoAdminPassword `
        --server-version "5.0" `
        --shard-node-tier "M30" `
        --shard-node-ha true `
        --shard-node-disk-size-gb 128 `
        --shard-node-count 1
    Write-Output "✓ MongoDB Cluster '$mongoClusterName' created"
}

# Add firewall rule for current IP (only if we have a valid IP, already detected at script start)
if ($currentIp -ne "0.0.0.0") {
$mongoFwRule1Exists = az cosmosdb mongocluster firewall rule show --cluster-name $mongoClusterName --resource-group $resourceGroupName --rule-name "AllowCurrentIP" --query "name" --output tsv 2>$null
if ($mongoFwRule1Exists) {
    Write-Output "⚠ MongoDB firewall rule 'AllowCurrentIP' already exists"
} else {
    az cosmosdb mongocluster firewall rule create `
        --cluster-name $mongoClusterName `
        --resource-group $resourceGroupName `
        --rule-name "AllowCurrentIP" `
        --start-ip-address $currentIp `
        --end-ip-address $currentIp
    Write-Output "✓ MongoDB firewall rule added for current IP: $currentIp"
}
} else {
    Write-Output "⚠ Skipping current IP firewall rule (IP could not be determined)"
}

# Add firewall rule for Azure services (0.0.0.0)
$mongoFwRule2Exists = az cosmosdb mongocluster firewall rule show --cluster-name $mongoClusterName --resource-group $resourceGroupName --rule-name "AllowAzureServices" --query "name" --output tsv 2>$null
if ($mongoFwRule2Exists) {
    Write-Output "⚠ MongoDB firewall rule 'AllowAzureServices' already exists"
} else {
    az cosmosdb mongocluster firewall rule create `
        --cluster-name $mongoClusterName `
        --resource-group $resourceGroupName `
        --rule-name "AllowAzureServices" `
        --start-ip-address "0.0.0.0" `
        --end-ip-address "0.0.0.0"
    Write-Output "✓ MongoDB firewall rule added for Azure services"
}

# Extract MongoDB connection string
$mongoClusterDetails = az cosmosdb mongocluster show `
    --cluster-name $mongoClusterName `
    --resource-group $resourceGroupName `
    --output json | ConvertFrom-Json

$mongoConnectionString = $mongoClusterDetails.properties.connectionString
Write-Output "✓ MongoDB connection string extracted"
Write-Output "MongoDB Connection String: $mongoConnectionString"

# replace the username and password placeholders in the connection string
$mongoConnectionString = $mongoConnectionString -replace "<user>", $mongoAdminUser
$mongoConnectionString = $mongoConnectionString -replace "<password>", $mongoAdminPassword
Write-Output "MongoDB Connection String: $mongoConnectionString"

# Optionally store connection string in Key Vault
# Pipe the value to avoid shell parsing issues with special characters like &
$mongoConnectionString | az keyvault secret set --vault-name $keyVaultName --name "MongoDBConnectionString" --value '@-'
Write-Output "✓ MongoDB connection string stored in Key Vault"

# get the details of azure communication services resource for email. the resource must exist.

$acsKeys = az communication list-key `
    --name $acsResourceName `
    --resource-group $acsResourceGroupName `
    --output json | ConvertFrom-Json
$acsConnectionString = $acsKeys.primaryConnectionString
Write-Output "✓ ACS connection string extracted"

# Store ACS connection string in Key Vault
$acsConnectionString | az keyvault secret set --vault-name $keyVaultName --name "ACSConnectionString" --value '@-'
Write-Output "✓ ACS connection string stored in Key Vault"

# get the email details from azure communication services resource for email. the resource must exist.


$acsEmailDetails= az communication email domain show --domain-name AzureManagedDomain --email-service-name $acsEmailResourceName -g $acsResourceGroupName -o json | ConvertFrom-Json
#extract fromSenderDomain from the details
$acsFromSenderDomain = $acsEmailDetails.fromSenderDomain
Write-Output "✓ ACS from sender domain extracted: $acsFromSenderDomain"
$acsFromEmail="DoNotReply"
$acsFromEmailFull="$acsFromEmail@$acsFromSenderDomain"
Write-Output "✓ ACS full from email: $acsFromEmailFull"

# Store recaptcha secret key in Key Vault
 # Replace with actual secret key
az keyvault secret set `
    --vault-name $keyVaultName `
    --name "ReCaptchaSecretKey" `
    --value $recaptchaSecretKey


# Configure App Service settings using Key Vault references for secrets
az webapp config appsettings set `
    --name $appServiceName `
    --resource-group $resourceGroupName `
    --settings `
        MYSQL_HOST="$mysqlServerName.mysql.database.azure.com" `
        MYSQL_DATABASE="$mysqlDatabaseName" `
        MYSQL_USER="$mysqlAdminUserName" `
        MYSQL_PASSWORD="@Microsoft.KeyVault(VaultName=$keyVaultName;SecretName=MySQLAdminPassword)" `
        MYSQL_PORT=3306 `
        MONGODB_URL="@Microsoft.KeyVault(VaultName=$keyVaultName;SecretName=MongoDBConnectionString)" `
        WEBSITES_PORT=8080 `
        DATABASE_NAME="$mongoDbDatabaseName" `
        WEBSITE_ZIP_PRESERVE_SYMLINKS=true `
        AZURE_STORAGE_BLOB_PREFIX="upcoming-events" `
        AZURE_STORAGE_CONTAINER="$containerName" `
        AZURE_STORAGE_FOLDER="upcoming-events" `
        BASE_URLS="http://localhost:3000"
        APPLICATION_INSIGHTS_CONNECTION_STRING="InstrumentationKey=@Microsoft.KeyVault(VaultName=$keyVaultName;SecretName=ApplicationInsightsKey)" `
        AZURE_STORAGE_CONNECTION_STRING="@Microsoft.KeyVault(VaultName=$keyVaultName;SecretName=StorageConnectionString)" `
        STORAGE_URL="https://$storageAccountName.blob.core.windows.net/" `
        DOCS_STORAGE_URL=$docStorageURL `
        ECPL_PETITIONS_EMAIL=$acsPetitionsEmail
        AZURE_STORAGE_FOLDER=upcoming-events  `
        ACS_CONNECTION_STRING="@Microsoft.KeyVault(VaultName=$keyVaultName;SecretName=ACSConnectionString)" `
        USE_ACS=true `
        AZURE_STORAGE_ACCOUNT_NAME="$storageAccountName" `
        USE_MANAGED_IDENTITY=true `
        RECAPTCHA_SECRET_KEY="@Microsoft.KeyVault(VaultName=$keyVaultName;SecretName=ReCaptchaSecretKey)" `
        ACS_FROM_EMAIL=$acsFromEmailFull

Write-Output "✓ App Service settings configured with Key Vault references"



# Configure MySQL parameters
az mysql flexible-server parameter set `
    --resource-group $resourceGroupName `
    --server-name $mysqlServerName `
    --name require_secure_transport `
    --value OFF
Write-Output "✓ MySQL require_secure_transport set to OFF"

az mysql flexible-server parameter set `
    --resource-group $resourceGroupName `
    --server-name $mysqlServerName `
    --name sql_mode `
    --value "ERROR_FOR_DIVISION_BY_ZERO,NO_ZERO_DATE,NO_ZERO_IN_DATE,STRICT_TRANS_TABLES"
Write-Output "✓ MySQL sql_mode configured"

az mysql flexible-server start `
    --resource-group $resourceGroupName `
    --name $mysqlServerName
Write-Output "✓ MySQL Server restarted"


Write-Output ""
Write-Output "=========================================="
Write-Output "PART 2: Extracting Resource Hostnames"
Write-Output "=========================================="
Write-Output ""

# Extract Static Web App 1 hostname
$SWA1_DEFAULT_HOSTNAME = az staticwebapp show `
    --name $frontEndStaticWebAppName `
    --resource-group $resourceGroupName `
    --query "defaultHostname" `
    --output tsv
Write-Output "✓ Frontend SWA hostname: $SWA1_DEFAULT_HOSTNAME"

# Extract Static Web App 2 hostname
$SWA2_DEFAULT_HOSTNAME = az staticwebapp show `
    --name $cmsStaticWebAppName `
    --resource-group $resourceGroupName `
    --query "defaultHostname" `
    --output tsv
Write-Output "✓ CMS SWA hostname: $SWA2_DEFAULT_HOSTNAME"

# Extract App Service hostname
$APPSVC_DEFAULT_HOSTNAME = az webapp show `
    --name $appServiceName `
    --resource-group $resourceGroupName `
    --query "defaultHostName" `
    --output tsv
Write-Output "✓ App Service hostname: $APPSVC_DEFAULT_HOSTNAME"

# Extract Storage blob endpoint
$BLOB_ENDPOINT = az storage account show `
    --name $storageAccountName `
    --resource-group $resourceGroupName `
    --query "primaryEndpoints.blob" `
    --output tsv
$BLOB_HOST = $BLOB_ENDPOINT -replace '^https?://', '' -replace '/$',''
Write-Output "✓ Storage blob host: $BLOB_HOST"

Write-Output ""
Write-Output "=========================================="
Write-Output "PART 3: Creating Front Door Configuration"
Write-Output "=========================================="
Write-Output ""

# Create Front Door resource group
$fdRgExists = az group exists --name $frontDoorResourceGroup --output tsv
if ($fdRgExists -eq "true") {
    Write-Output "⚠ Front Door resource group '$frontDoorResourceGroup' already exists"
} else {

    Write-Output "Please create FrontDoor resources"
}

# Create Front Door Profile
$fdProfileExists = az afd profile show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --query "name" --output tsv 2>$null
if ($fdProfileExists) {
    Write-Output "⚠ Front Door profile '$frontDoorProfileName' already exists"
} else {

    Write-Output "Please create FrontDoor resources"
}

# =====================================================================
# 2.5. WAF POLICY (CONDITIONAL)
# =====================================================================

if ($WAF) {
    $WAF_POLICY_NAME = "wafpolicy$environment"  # WAF policy names have restrictions
    
    Write-Output "Creating WAF Policy: $WAF_POLICY_NAME"
    
    # Check if WAF policy already exists and delete it
    $EXISTING_WAF = az network front-door waf-policy show `
        --resource-group $frontDoorResourceGroup `
        --name $WAF_POLICY_NAME `
        --query "name" -o tsv 2>$null
    
    if ($EXISTING_WAF) {
        Write-Output "Deleting existing WAF policy: $WAF_POLICY_NAME"
        az network front-door waf-policy delete `
            --resource-group $frontDoorResourceGroup `
            --name $WAF_POLICY_NAME
        Start-Sleep -Seconds 10
    }
    
    # Create WAF Policy for AFD Standard (note: managed rules only available with Premium)
    az network front-door waf-policy create `
        --resource-group $frontDoorResourceGroup `
        --name $WAF_POLICY_NAME `
        --sku Standard_AzureFrontDoor `
        --disabled false `
        --mode Prevention
    
    # Note: Managed rules are only available with Premium SKU
    # For Standard SKU, you can only use custom rules
    # If you need managed rules, change the Front Door profile to Premium_AzureFrontDoor
    
    Write-Output "✓ WAF Policy '$WAF_POLICY_NAME' created for AFD Standard"
    Write-Output "ℹ Note: Managed rules require Premium SKU. Only custom rules available with Standard."
} else {
    Write-Output "⚠ WAF protection disabled (WAF variable set to false)"
}

# Create Endpoints
$fdEndpoint1Exists = az afd endpoint show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_STORAGE --query "name" --output tsv 2>$null
if ($fdEndpoint1Exists) {
    Write-Output "⚠ Front Door endpoint '$FD_ENDPOINT_STORAGE' already exists"
} else {
    az afd endpoint create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_STORAGE `
        --enabled-state Enabled
    Write-Output "✓ Front Door endpoint '$FD_ENDPOINT_STORAGE' created"
}

$fdEndpoint2Exists = az afd endpoint show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_WEBMANAGER --query "name" --output tsv 2>$null
if ($fdEndpoint2Exists) {
    Write-Output "⚠ Front Door endpoint '$FD_ENDPOINT_WEBMANAGER' already exists"
} else {
    az afd endpoint create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_WEBMANAGER `
        --enabled-state Enabled
    Write-Output "✓ Front Door endpoint '$FD_ENDPOINT_WEBMANAGER' created"
}

$fdEndpoint3Exists = az afd endpoint show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_PUBLICSITE --query "name" --output tsv 2>$null
if ($fdEndpoint3Exists) {
    Write-Output "⚠ Front Door endpoint '$FD_ENDPOINT_PUBLICSITE' already exists"
} else {
    az afd endpoint create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_PUBLICSITE `
        --enabled-state Enabled
    Write-Output "✓ Front Door endpoint '$FD_ENDPOINT_PUBLICSITE' created"
}

$fdEndpoint4Exists = az afd endpoint show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_API --query "name" --output tsv 2>$null
if ($fdEndpoint4Exists) {
    Write-Output "⚠ Front Door endpoint '$FD_ENDPOINT_API' already exists"
} else {
    az afd endpoint create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_API `
        --enabled-state Enabled
    Write-Output "✓ Front Door endpoint '$FD_ENDPOINT_API' created"
}

# =====================================================================
# 3.5. SECURITY POLICY (CONDITIONAL WAF)
# =====================================================================

if ($WAF) {
    $SECURITY_POLICY_NAME = "securitypolicy$environment"
    
    Write-Output "Waiting for WAF policy to be ready..."
    Start-Sleep -Seconds 30
    
    # Get WAF Policy resource ID (full ARM resource ID)
    $WAF_POLICY_ID = az network front-door waf-policy show `
        --resource-group $frontDoorResourceGroup `
        --name $WAF_POLICY_NAME `
        --query "id" -o tsv
    
    if ($WAF_POLICY_ID) {
        Write-Output "WAF Policy ID: $WAF_POLICY_ID"
        Write-Output "Associating WAF policy with all endpoints..."
        
        # Get endpoint resource IDs (required for security policy)
        $ENDPOINT_STORAGE_ID = az afd endpoint show `
            --resource-group $frontDoorResourceGroup `
            --profile-name $frontDoorProfileName `
            --endpoint-name $FD_ENDPOINT_STORAGE `
            --query "id" -o tsv
            
        $ENDPOINT_WEBMANAGER_ID = az afd endpoint show `
            --resource-group $frontDoorResourceGroup `
            --profile-name $frontDoorProfileName `
            --endpoint-name $FD_ENDPOINT_WEBMANAGER `
            --query "id" -o tsv
            
        $ENDPOINT_PUBLICSITE_ID = az afd endpoint show `
            --resource-group $frontDoorResourceGroup `
            --profile-name $frontDoorProfileName `
            --endpoint-name $FD_ENDPOINT_PUBLICSITE `
            --query "id" -o tsv
            
        $ENDPOINT_API_ID = az afd endpoint show `
            --resource-group $frontDoorResourceGroup `
            --profile-name $frontDoorProfileName `
            --endpoint-name $FD_ENDPOINT_API `
            --query "id" -o tsv
        
        # Create Security Policy and associate with all endpoints using their IDs
        az afd security-policy create `
            --resource-group $frontDoorResourceGroup `
            --profile-name $frontDoorProfileName `
            --security-policy-name $SECURITY_POLICY_NAME `
            --domains "$ENDPOINT_STORAGE_ID" "$ENDPOINT_WEBMANAGER_ID" "$ENDPOINT_PUBLICSITE_ID" "$ENDPOINT_API_ID" `
            --waf-policy $WAF_POLICY_ID
        
        Write-Output "✓ Security Policy '$SECURITY_POLICY_NAME' created and associated with all endpoints"
        Write-Output "✓ WAF protection active on: Storage, Web Manager, Public Site, and API endpoints"
    } else {
        Write-Output "⚠ Could not retrieve WAF Policy ID - Security Policy creation skipped"
    }
} else {
    Write-Output "⚠ WAF security policy skipped (WAF variable set to false)"
}

# Create Origin Groups and Origins

# Storage Origin
$ogStorageExists = az afd origin-group show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_STORAGE --query "name" --output tsv 2>$null
if ($ogStorageExists) {
    Write-Output "⚠ Storage origin group '$OG_STORAGE' already exists"
} else {
    az afd origin-group create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_STORAGE `
        --probe-request-type GET `
        --probe-protocol Https `
        --probe-path "/" `
        --probe-interval-in-seconds 120 `
        --sample-size 4 `
        --successful-samples-required 3 `
        --additional-latency-in-milliseconds 0
    Write-Output "✓ Storage origin group created"
}

$originStorageExists = az afd origin show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_STORAGE --origin-name $ORIGIN_STORAGE --query "name" --output tsv 2>$null
if ($originStorageExists) {
    Write-Output "⚠ Storage origin '$ORIGIN_STORAGE' already exists"
} else {
    az afd origin create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_STORAGE `
        --origin-name $ORIGIN_STORAGE `
        --host-name $BLOB_HOST `
        --http-port 80 `
        --https-port 443 `
        --origin-host-header $BLOB_HOST `
        --priority 1 `
        --weight 100 `
        --enabled-state Enabled
    Write-Output "✓ Storage origin created"
}

# Web Manager (SWA1) Origin
$ogWebManagerExists = az afd origin-group show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_WEBMANAGER --query "name" --output tsv 2>$null
if ($ogWebManagerExists) {
    Write-Output "⚠ Web Manager origin group '$OG_WEBMANAGER' already exists"
} else {
    az afd origin-group create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_WEBMANAGER `
        --probe-request-type GET `
        --probe-protocol Https `
        --probe-path "/" `
        --probe-interval-in-seconds 120 `
        --sample-size 4 `
        --successful-samples-required 3 `
        --additional-latency-in-milliseconds 0
    Write-Output "✓ Web Manager origin group created"
}

$originWebManagerExists = az afd origin show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_WEBMANAGER --origin-name $ORIGIN_WEBMANAGER --query "name" --output tsv 2>$null
if ($originWebManagerExists) {
    Write-Output "⚠ Web Manager origin '$ORIGIN_WEBMANAGER' already exists"
} else {
    az afd origin create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_WEBMANAGER `
        --origin-name $ORIGIN_WEBMANAGER `
        --host-name $SWA1_DEFAULT_HOSTNAME `
        --http-port 80 `
        --https-port 443 `
        --origin-host-header $SWA1_DEFAULT_HOSTNAME `
        --priority 1 `
        --weight 100 `
        --enabled-state Enabled
    Write-Output "✓ Web Manager origin created"
}

# Public Site (SWA2) Origin
$ogPublicSiteExists = az afd origin-group show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_PUBLICSITE --query "name" --output tsv 2>$null
if ($ogPublicSiteExists) {
    Write-Output "⚠ Public Site origin group '$OG_PUBLICSITE' already exists"
} else {
    az afd origin-group create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_PUBLICSITE `
        --probe-request-type GET `
        --probe-protocol Https `
        --probe-path "/" `
        --probe-interval-in-seconds 120 `
        --sample-size 4 `
        --successful-samples-required 3 `
        --additional-latency-in-milliseconds 0
    Write-Output "✓ Public Site origin group created"
}

$originPublicSiteExists = az afd origin show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_PUBLICSITE --origin-name $ORIGIN_PUBLICSITE --query "name" --output tsv 2>$null
if ($originPublicSiteExists) {
    Write-Output "⚠ Public Site origin '$ORIGIN_PUBLICSITE' already exists"
} else {
    az afd origin create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_PUBLICSITE `
        --origin-name $ORIGIN_PUBLICSITE `
        --host-name $SWA2_DEFAULT_HOSTNAME `
        --http-port 80 `
        --https-port 443 `
        --origin-host-header $SWA2_DEFAULT_HOSTNAME `
        --priority 1 `
        --weight 100 `
        --enabled-state Enabled
    Write-Output "✓ Public Site origin created"
}

# API (App Service) Origin
$ogApiExists = az afd origin-group show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_API --query "name" --output tsv 2>$null
if ($ogApiExists) {
    Write-Output "⚠ API origin group '$OG_API' already exists"
} else {
    az afd origin-group create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_API `
        --probe-request-type GET `
        --probe-protocol Https `
        --probe-path "/" `
        --probe-interval-in-seconds 120 `
        --sample-size 4 `
        --successful-samples-required 3 `
        --additional-latency-in-milliseconds 0
    Write-Output "✓ API origin group created"
}

$originApiExists = az afd origin show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --origin-group-name $OG_API --origin-name $ORIGIN_API --query "name" --output tsv 2>$null
if ($originApiExists) {
    Write-Output "⚠ API origin '$ORIGIN_API' already exists"
} else {
    az afd origin create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --origin-group-name $OG_API `
        --origin-name $ORIGIN_API `
        --host-name $APPSVC_DEFAULT_HOSTNAME `
        --http-port 80 `
        --https-port 443 `
        --origin-host-header $APPSVC_DEFAULT_HOSTNAME `
        --priority 1 `
        --weight 100 `
        --enabled-state Enabled
    Write-Output "✓ API origin created"
}

# Create Routes

$STORAGE_ORIGIN_PATH = "/$docsStorageContainerName"

$routeStorageExists = az afd route show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_STORAGE --route-name $ROUTE_STORAGE --query "name" --output tsv 2>$null
if ($routeStorageExists) {
    Write-Output "⚠ Storage route '$ROUTE_STORAGE' already exists"
} else {
    az afd route create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_STORAGE `
        --route-name $ROUTE_STORAGE `
        --origin-group $OG_STORAGE `
        --patterns-to-match "/*" `
        --https-redirect Enabled `
        --supported-protocols Http Https `
        --forwarding-protocol MatchRequest `
        --link-to-default-domain Enabled `
        --origin-path $STORAGE_ORIGIN_PATH `
        --enable-caching true `
        --query-string-caching-behavior IgnoreQueryString
    Write-Output "✓ Storage route created with caching enabled"
}

$routeWebManagerExists = az afd route show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_WEBMANAGER --route-name $ROUTE_WEBMANAGER --query "name" --output tsv 2>$null
if ($routeWebManagerExists) {
    Write-Output "⚠ Web Manager route '$ROUTE_WEBMANAGER' already exists"
} else {
    az afd route create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_WEBMANAGER `
        --route-name $ROUTE_WEBMANAGER `
        --origin-group $OG_WEBMANAGER `
        --patterns-to-match "/*" `
        --https-redirect Enabled `
        --supported-protocols Http Https `
        --forwarding-protocol MatchRequest `
        --link-to-default-domain Enabled `
        --enable-caching true `
        --query-string-caching-behavior UseQueryString
    Write-Output "✓ Web Manager route created with caching enabled"
}

$routePublicSiteExists = az afd route show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_PUBLICSITE --route-name $ROUTE_PUBLICSITE --query "name" --output tsv 2>$null
if ($routePublicSiteExists) {
    Write-Output "⚠ Public Site route '$ROUTE_PUBLICSITE' already exists"
} else {
    az afd route create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_PUBLICSITE `
        --route-name $ROUTE_PUBLICSITE `
        --origin-group $OG_PUBLICSITE `
        --patterns-to-match "/*" `
        --https-redirect Enabled `
        --supported-protocols Http Https `
        --forwarding-protocol MatchRequest `
        --link-to-default-domain Enabled `
        --enable-caching true `
        --query-string-caching-behavior UseQueryString
    Write-Output "✓ Public Site route created with caching enabled"
}

$routeApiExists = az afd route show --resource-group $frontDoorResourceGroup --profile-name $frontDoorProfileName --endpoint-name $FD_ENDPOINT_API --route-name $ROUTE_API --query "name" --output tsv 2>$null
if ($routeApiExists) {
    Write-Output "⚠ API route '$ROUTE_API' already exists"
} else {
    az afd route create `
        --resource-group $frontDoorResourceGroup `
        --profile-name $frontDoorProfileName `
        --endpoint-name $FD_ENDPOINT_API `
        --route-name $ROUTE_API `
        --origin-group $OG_API `
        --patterns-to-match "/*" `
        --https-redirect Enabled `
        --supported-protocols Http Https `
        --forwarding-protocol MatchRequest `
        --link-to-default-domain Enabled `
        --enable-caching false
    Write-Output "✓ API route created with caching disabled"
}

Write-Output ""
Write-Output "=========================================="
Write-Output "PART 4: Locking Down App Service"
Write-Output "=========================================="
Write-Output ""

# Get Front Door FDID
$FRONTDOOR_FDID = az resource show `
    --resource-group $frontDoorResourceGroup `
    --name $frontDoorProfileName `
    --namespace Microsoft.Cdn `
    --resource-type Profiles `
    --query "properties.frontDoorId" `
    --output tsv

Write-Output "Front Door FDID: $FRONTDOOR_FDID"

if ($FRONTDOOR_FDID) {
    az webapp config access-restriction add `
        --resource-group $resourceGroupName `
        --name $appServiceName `
        --rule-name "Allow-This-FrontDoor" `
        --action Allow `
        --priority 100 `
        --service-tag AzureFrontDoor.Backend `
        --http-header "x-azure-fdid=$FRONTDOOR_FDID"

    az webapp config access-restriction set `
        --resource-group $resourceGroupName `
        --name $appServiceName `
        --default-action Deny

    Write-Output "✓ App Service access restricted to Front Door only"
} else {
    Write-Output "⚠ Could not retrieve Front Door FDID; App Service lock-down skipped"
}

Write-Output ""
Write-Output "=========================================="
Write-Output "DEPLOYMENT SUMMARY"
Write-Output "=========================================="
Write-Output ""

# Get Front Door endpoint hostnames
$FD_HOST_STORAGE = az afd endpoint show `
    --resource-group $frontDoorResourceGroup `
    --profile-name $frontDoorProfileName `
    --endpoint-name $FD_ENDPOINT_STORAGE `
    --query "hostName" `
    --output tsv

$FD_HOST_WEBMANAGER = az afd endpoint show `
    --resource-group $frontDoorResourceGroup `
    --profile-name $frontDoorProfileName `
    --endpoint-name $FD_ENDPOINT_WEBMANAGER `
    --query "hostName" `
    --output tsv

$FD_HOST_PUBLICSITE = az afd endpoint show `
    --resource-group $frontDoorResourceGroup `
    --profile-name $frontDoorProfileName `
    --endpoint-name $FD_ENDPOINT_PUBLICSITE `
    --query "hostName" `
    --output tsv

$FD_HOST_API = az afd endpoint show `
    --resource-group $frontDoorResourceGroup `
    --profile-name $frontDoorProfileName `
    --endpoint-name $FD_ENDPOINT_API `
    --query "hostName" `
    --output tsv

Write-Output "Environment: $environment"
Write-Output ""
Write-Output "Core Resources:"
Write-Output "  Resource Group:     $resourceGroupName"
Write-Output "  Frontend SWA:       $frontEndStaticWebAppName ($SWA1_DEFAULT_HOSTNAME)"
Write-Output "  CMS SWA:            $cmsStaticWebAppName ($SWA2_DEFAULT_HOSTNAME)"
Write-Output "  App Service:        $appServiceName ($APPSVC_DEFAULT_HOSTNAME)"
Write-Output "  Storage Account:    $storageAccountName"
Write-Output "  MySQL Server:       $mysqlServerName.mysql.database.azure.com"
Write-Output "  Key Vault:          $keyVaultName"
Write-Output ""
Write-Output "Front Door Endpoints:"
Write-Output "  Storage:       https://$FD_HOST_STORAGE"
Write-Output "  Web Manager:   https://$FD_HOST_WEBMANAGER"
Write-Output "  Public Site:   https://$FD_HOST_PUBLICSITE"
Write-Output "  API:           https://$FD_HOST_API"
Write-Output ""
Write-Output "✓ Deployment complete!"


# to be done
# copy files to storage account
# restore the database from a dump file if provided
# setup custom domains and SSL certificates
