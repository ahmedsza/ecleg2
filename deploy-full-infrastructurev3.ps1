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
try {
    $rgExists = az group exists --name $resourceGroupName --output tsv 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to check if resource group exists. Ensure you are logged in with 'az login'"
    }
    
    if ($rgExists -eq "true") {
        Write-Output "⚠ Resource group '$resourceGroupName' already exists"
    } else {
        $createResult = az group create --name $resourceGroupName --location $location 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create resource group: $createResult"
        }
        Write-Output "✓ Resource group '$resourceGroupName' created in '$location'"
    }
} catch {
    Write-Error "Error managing resource group: $_"
    throw
}

# Create Static Web App 1 (Frontend)
try {
    Write-Output "Checking if Static Web App '$frontEndStaticWebAppName' exists..."
    
    $swa1Exists = az staticwebapp show `
        --name $frontEndStaticWebAppName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if Static Web App exists. Exit code: $LASTEXITCODE"
    }
    
    if ($swa1Exists) {
        Write-Output "⚠ Static Web App '$frontEndStaticWebAppName' already exists"
        
        # Verify it's in correct location
        $swaLocation = az staticwebapp show `
            --name $frontEndStaticWebAppName `
            --resource-group $resourceGroupName `
            --query "location" `
            --output tsv 2>$null
        
        if ($swaLocation -ne $staticWebAppLocation) {
            Write-Output "⚠ Warning: Existing SWA is in '$swaLocation', expected '$staticWebAppLocation'"
        }
    } else {
        Write-Output "Creating Static Web App '$frontEndStaticWebAppName'..."
        
        # Validate prerequisites
        if ([string]::IsNullOrWhiteSpace($frontEndRepositoryUrl)) {
            throw "Frontend repository URL is not set. Please configure `$frontEndRepositoryUrl variable."
        }
        
        if ([string]::IsNullOrWhiteSpace($frontEndBranchName)) {
            throw "Frontend branch name is not set. Please configure `$frontEndBranchName variable."
        }
        
        $createResult = az staticwebapp create `
            --name $frontEndStaticWebAppName `
            --resource-group $resourceGroupName `
            --location $staticWebAppLocation `
            --source $frontEndRepositoryUrl `
            --sku $staticwebSiteSku `
            --login-with-ado `
            --branch $frontEndBranchName 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Static Web App '$frontEndStaticWebAppName'. Error: $createResult"
        }
        
        Write-Output "✓ Static Web App '$frontEndStaticWebAppName' created successfully"
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyCreate = az staticwebapp show `
            --name $frontEndStaticWebAppName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyCreate) {
            Write-Output "⚠ Warning: Could not verify Static Web App creation"
        }
    }
} catch {
    Write-Error "Error managing Static Web App '$frontEndStaticWebAppName': $_"
    throw
}

# Create Static Web App 2 (CMS)
# Create Static Web App 2 (CMS)
try {
    Write-Output "Checking if Static Web App '$cmsStaticWebAppName' exists..."
    
    $swa2Exists = az staticwebapp show `
        --name $cmsStaticWebAppName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if Static Web App exists. Exit code: $LASTEXITCODE"
    }
    
    if ($swa2Exists) {
        Write-Output "⚠ Static Web App '$cmsStaticWebAppName' already exists"
        
        # Verify it's in correct location
        $swaLocation = az staticwebapp show `
            --name $cmsStaticWebAppName `
            --resource-group $resourceGroupName `
            --query "location" `
            --output tsv 2>$null
        
        if ($swaLocation -ne $staticWebAppLocation) {
            Write-Output "⚠ Warning: Existing SWA is in '$swaLocation', expected '$staticWebAppLocation'"
        }
    } else {
        Write-Output "Creating Static Web App '$cmsStaticWebAppName'..."
        
        # Validate prerequisites
        if ([string]::IsNullOrWhiteSpace($cmsRepositoryUrl)) {
            throw "CMS repository URL is not set. Please configure `$cmsRepositoryUrl variable."
        }
        
        if ([string]::IsNullOrWhiteSpace($cmsBranchName)) {
            throw "CMS branch name is not set. Please configure `$cmsBranchName variable."
        }
        
        $createResult = az staticwebapp create `
            --name $cmsStaticWebAppName `
            --resource-group $resourceGroupName `
            --location $staticWebAppLocation `
            --source $cmsRepositoryUrl `
            --sku $staticwebSiteSku `
            --login-with-ado `
            --branch $cmsBranchName 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Static Web App '$cmsStaticWebAppName'. Error: $createResult"
        }
        
        Write-Output "✓ Static Web App '$cmsStaticWebAppName' created successfully"
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyCreate = az staticwebapp show `
            --name $cmsStaticWebAppName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyCreate) {
            Write-Output "⚠ Warning: Could not verify Static Web App creation"
        }
    }
} catch {
    Write-Error "Error managing Static Web App '$cmsStaticWebAppName': $_"
    throw
}

# Create Storage Account (with zone redundancy only if prod and zoneRedundant is true)
try {
    Write-Output "Checking if Storage Account '$storageAccountName' exists..."
    
    $storageExists = az storage account show `
        --name $storageAccountName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if Storage Account exists. Exit code: $LASTEXITCODE"
    }
    
    if ($storageExists) {
        Write-Output "⚠ Storage account '$storageAccountName' already exists"
        
        # Verify SKU configuration
        $currentSku = az storage account show `
            --name $storageAccountName `
            --resource-group $resourceGroupName `
            --query "sku.name" `
            --output tsv 2>$null
        
        if ($LASTEXITCODE -ne 0) {
            Write-Output "⚠ Warning: Could not verify Storage Account SKU"
        } else {
            $expectedSku = if ($environment -eq "prod" -and $zoneRedundant) { "Standard_ZRS" } else { "Standard_LRS" }
            if ($currentSku -ne $expectedSku) {
                Write-Output "⚠ Warning: Existing Storage Account SKU is '$currentSku', expected '$expectedSku'"
            }
        }
    } else {
        # Determine SKU based on environment and zone redundancy setting
        if ($environment -eq "prod" -and $zoneRedundant) {
            $storageSku = "Standard_ZRS"
            Write-Output "Creating Storage Account with zone redundancy (prod environment)..."
        } else {
            $storageSku = "Standard_LRS"
            Write-Output "Creating Storage Account with locally redundant storage..."
        }

        # Validate storage account name (3-24 chars, lowercase alphanumeric only)
        if ($storageAccountName -notmatch '^[a-z0-9]{3,24}$') {
            throw "Invalid storage account name '$storageAccountName'. Must be 3-24 lowercase alphanumeric characters."
        }

        $createResult = az storage account create `
            --name $storageAccountName `
            --resource-group $resourceGroupName `
            --location $location `
            --allow-blob-public-access true `
            --https-only true `
            --public-network-access Enabled `
            --sku $storageSku `
            --kind StorageV2 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Storage Account '$storageAccountName'. Error: $createResult"
        }

        if ($environment -eq "prod" -and $zoneRedundant) {
            Write-Output "✓ Storage account '$storageAccountName' created with zone redundancy"
        } else {
            Write-Output "✓ Storage account '$storageAccountName' created with locally redundant storage"
        }
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyCreate = az storage account show `
            --name $storageAccountName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyCreate) {
            Write-Output "⚠ Warning: Could not verify Storage Account creation"
        }
    }
} catch {
    Write-Error "Error managing Storage Account '$storageAccountName': $_"
    throw
}

# Set CORS on storage account
try {
    Write-Output "Configuring CORS on storage account..."
    
    $corsResult = az storage cors add `
        --methods DELETE GET HEAD MERGE POST OPTIONS PUT `
        --origins "*" `
        --services b `
        --account-name $storageAccountName `
        --max-age 2000 `
        --allowed-headers "*" `
        --exposed-headers "*" 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure CORS on Storage Account. Error: $corsResult"
    }
    
    Write-Output "✓ CORS configured on storage account"
} catch {
    Write-Error "Error configuring CORS on Storage Account '$storageAccountName': $_"
    throw
}

# Create blob container
try {
    Write-Output "Checking if blob container '$containerName' exists..."
    
    $containerExists = az storage container exists `
        --name $containerName `
        --account-name $storageAccountName `
        --query "exists" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to check if blob container exists. Exit code: $LASTEXITCODE"
    }
    
    if ($containerExists -eq "true") {
        Write-Output "⚠ Blob container '$containerName' already exists"
        
        # Verify public access level
        $publicAccess = az storage container show `
            --name $containerName `
            --account-name $storageAccountName `
            --query "properties.publicAccess" `
            --output tsv 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $publicAccess -ne "blob") {
            Write-Output "⚠ Warning: Container public access is '$publicAccess', expected 'blob'"
        }
    } else {
        Write-Output "Creating blob container '$containerName'..."
        
        # Validate container name (3-63 chars, lowercase alphanumeric and hyphens)
        if ($containerName -notmatch '^[a-z0-9]([a-z0-9\-]{1,61}[a-z0-9])?$') {
            throw "Invalid container name '$containerName'. Must be 3-63 lowercase alphanumeric characters and hyphens."
        }
        
        $createResult = az storage container create `
            --name $containerName `
            --account-name $storageAccountName `
            --public-access blob 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create blob container '$containerName'. Error: $createResult"
        }
        
        Write-Output "✓ Blob container '$containerName' created"
        
        # Verify creation
        Start-Sleep -Seconds 3
        $verifyContainer = az storage container exists `
            --name $containerName `
            --account-name $storageAccountName `
            --query "exists" `
            --output tsv 2>$null
        
        if ($verifyContainer -ne "true") {
            Write-Output "⚠ Warning: Could not verify blob container creation"
        }
    }
} catch {
    Write-Error "Error managing blob container '$containerName': $_"
    throw
}



# Create App Service Plan (with zone redundancy only if prod and zoneRedundant is true)
try {
    Write-Output "Checking if App Service Plan '$appServicePlanName' exists..."
    
    $aspExists = az appservice plan show `
        --name $appServicePlanName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if App Service Plan exists. Exit code: $LASTEXITCODE"
    }
    
    if ($aspExists) {
        Write-Output "⚠ App Service Plan '$appServicePlanName' already exists"
        
        # Verify SKU and zone redundancy configuration
        $planDetails = az appservice plan show `
            --name $appServicePlanName `
            --resource-group $resourceGroupName `
            --query "{sku:sku.name, zoneRedundant:zoneRedundant}" `
            --output json 2>$null | ConvertFrom-Json
        
        if ($LASTEXITCODE -ne 0) {
            Write-Output "⚠ Warning: Could not verify App Service Plan configuration"
        } else {
            if ($planDetails.sku -ne $appServicePlanSKU) {
                Write-Output "⚠ Warning: Existing plan SKU is '$($planDetails.sku)', expected '$appServicePlanSKU'"
            }
            if ($environment -eq "prod" -and $zoneRedundant -and -not $planDetails.zoneRedundant) {
                Write-Output "⚠ Warning: Existing plan is not zone redundant (expected for prod environment)"
            }
        }
    } else {
        Write-Output "Creating App Service Plan '$appServicePlanName'..."
        
        # Validate worker count
        if ($workerCount -lt 1 -or $workerCount -gt 20) {
            throw "Invalid worker count '$workerCount'. Must be between 1 and 20."
        }
        
        if ($environment -eq "prod" -and $zoneRedundant) {
            Write-Output "Creating with zone redundancy (prod environment)..."
            
            $createResult = az appservice plan create `
                --name $appServicePlanName `
                --resource-group $resourceGroupName `
                --location $location `
                --sku $appServicePlanSKU `
                --is-linux `
                --zone-redundant `
                --number-of-workers $workerCount 2>&1
            
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create zone-redundant App Service Plan '$appServicePlanName'. Error: $createResult"
            }
            
            Write-Output "✓ App Service Plan '$appServicePlanName' created with zone redundancy"
        } else {
            $createResult = az appservice plan create `
                --name $appServicePlanName `
                --resource-group $resourceGroupName `
                --location $location `
                --sku $appServicePlanSKU `
                --is-linux `
                --number-of-workers $workerCount 2>&1
            
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create App Service Plan '$appServicePlanName'. Error: $createResult"
            }
            
            Write-Output "✓ App Service Plan '$appServicePlanName' created"
        }
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyPlan = az appservice plan show `
            --name $appServicePlanName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyPlan) {
            Write-Output "⚠ Warning: Could not verify App Service Plan creation"
        }
    }
} catch {
    Write-Error "Error managing App Service Plan '$appServicePlanName': $_"
    throw
}

# Create App Service with system-managed identity
try {
    Write-Output "Checking if App Service '$appServiceName' exists..."
    
    $appServiceExists = az webapp show `
        --name $appServiceName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if App Service exists. Exit code: $LASTEXITCODE"
    }
    
    if ($appServiceExists) {
        Write-Output "⚠ App Service '$appServiceName' already exists"
        
        # Verify runtime configuration
        $runtime = az webapp config show `
            --name $appServiceName `
            --resource-group $resourceGroupName `
            --query "linuxFxVersion" `
            --output tsv 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $runtime -notmatch "NODE\|24") {
            Write-Output "⚠ Warning: Existing App Service runtime is '$runtime', expected 'NODE|24-lts'"
        }
    } else {
        Write-Output "Creating App Service '$appServiceName' with system-managed identity..."
        
        $createResult = az webapp create `
            --name $appServiceName `
            --resource-group $resourceGroupName `
            --plan $appServicePlanName `
            --runtime "NODE:24-lts" `
            --assign-identity [system] 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create App Service '$appServiceName'. Error: $createResult"
        }
        
        Write-Output "✓ App Service '$appServiceName' created with system-managed identity"
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyApp = az webapp show `
            --name $appServiceName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyApp) {
            Write-Output "⚠ Warning: Could not verify App Service creation"
        }
    }
} catch {
    Write-Error "Error managing App Service '$appServiceName': $_"
    throw
}

# Get the App Service's managed identity principal ID
try {
    Write-Output "Retrieving App Service managed identity principal ID..."
    
    $appServiceIdentityId = az webapp identity show `
        --name $appServiceName `
        --resource-group $resourceGroupName `
        --query "principalId" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve App Service managed identity. Exit code: $LASTEXITCODE"
    }
    
    if ([string]::IsNullOrWhiteSpace($appServiceIdentityId)) {
        throw "App Service managed identity principal ID is empty. Identity may not be enabled."
    }
    
    # Validate GUID format
    if ($appServiceIdentityId -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
        throw "Invalid managed identity principal ID format: '$appServiceIdentityId'"
    }
    
    Write-Output "✓ App Service managed identity principal ID: $appServiceIdentityId"
} catch {
    Write-Error "Error retrieving App Service managed identity: $_"
    Write-Output "⚠ You may need to manually enable system-assigned identity on the App Service"
    throw
}

# Give the app service identity access to the storage account
try {
    Write-Output "Granting App Service managed identity access to Storage Account..."
    
    # Validate that we have a valid identity ID
    if ([string]::IsNullOrWhiteSpace($appServiceIdentityId)) {
        throw "App Service identity ID is empty. Cannot assign role."
    }
    
    # Get subscription ID
    $subscriptionId = az account show --query id --output tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($subscriptionId)) {
        throw "Failed to retrieve subscription ID. Ensure you are logged in with 'az login'"
    }
    
    # Construct storage account scope
    $storageScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName"
    
    # Check if role assignment already exists
    $existingRole = az role assignment list `
        --assignee $appServiceIdentityId `
        --scope $storageScope `
        --role "Storage Blob Data Contributor" `
        --query "[].id" `
        --output tsv 2>$null
    
    if ($existingRole) {
        Write-Output "⚠ App Service already has 'Storage Blob Data Contributor' role on Storage Account"
    } else {
        $roleResult = az role assignment create `
            --role "Storage Blob Data Contributor" `
            --assignee $appServiceIdentityId `
            --scope $storageScope 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to assign role to App Service identity. Error: $roleResult"
        }
        
        Write-Output "✓ App Service granted 'Storage Blob Data Contributor' role on Storage Account"
    }
} catch {
    Write-Error "Error granting App Service access to Storage Account: $_"
    throw
}

# Give current user access to storage account
try {
    Write-Output "Granting current user access to Storage Account..."
    
    $currentUserId = az ad signed-in-user show --query id --output tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($currentUserId)) {
        throw "Failed to retrieve current user ID. Ensure you are logged in with proper permissions."
    }
    
    # Validate GUID format
    if ($currentUserId -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
        throw "Invalid user ID format: '$currentUserId'"
    }
    
    Write-Output "Current user ID: $currentUserId"
    
    # Get subscription ID (already validated above, but include for clarity)
    $subscriptionId = az account show --query id --output tsv 2>$null
    $storageScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName"
    
    # Check if role assignment already exists
    $existingUserRole = az role assignment list `
        --assignee $currentUserId `
        --scope $storageScope `
        --role "Storage Blob Data Contributor" `
        --query "[].id" `
        --output tsv 2>$null
    
    if ($existingUserRole) {
        Write-Output "⚠ Current user already has 'Storage Blob Data Contributor' role on Storage Account"
    } else {
        $userRoleResult = az role assignment create `
            --role "Storage Blob Data Contributor" `
            --assignee $currentUserId `
            --scope $storageScope 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to assign role to current user. Error: $userRoleResult"
        }
        
        Write-Output "✓ Current user granted 'Storage Blob Data Contributor' role on Storage Account"
    }
} catch {
    Write-Error "Error granting current user access to Storage Account: $_"
    throw
}

# Set CORS on App Service
try {
    Write-Output "Configuring CORS on App Service..."
    
    # Check current CORS configuration
    $currentCors = az webapp cors show `
        --name $appServiceName `
        --resource-group $resourceGroupName `
        --query "allowedOrigins" `
        --output json 2>$null | ConvertFrom-Json
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve current CORS configuration for App Service '$appServiceName'"
    }
    
    # Check if wildcard already configured
    if ($currentCors -contains "*") {
        Write-Output "⚠ CORS already configured with wildcard (*) on App Service"
    } else {
        $corsResult = az webapp cors add `
            --name $appServiceName `
            --resource-group $resourceGroupName `
            --allowed-origins "*" 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to configure CORS on App Service '$appServiceName'. Error: $corsResult"
        }
        
        Write-Output "✓ CORS configured on App Service"
    }
} catch {
    Write-Error "Error configuring CORS on App Service '$appServiceName': $_"
    throw
}

# Create Key Vault
try {
    Write-Output "Checking if Key Vault '$keyVaultName' exists..."
    
    # Validate Key Vault name (3-24 chars, alphanumeric and hyphens, must start with letter)
    if ($keyVaultName -notmatch '^[a-zA-Z][a-zA-Z0-9\-]{1,22}[a-zA-Z0-9]$') {
        throw "Invalid Key Vault name '$keyVaultName'. Must be 3-24 characters, start with letter, alphanumeric and hyphens only."
    }
    
    $kvExists = az keyvault show `
        --name $keyVaultName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if Key Vault exists. Exit code: $LASTEXITCODE"
    }
    
    if ($kvExists) {
        Write-Output "⚠ Key Vault '$keyVaultName' already exists"
        
        # Verify location
        $kvLocation = az keyvault show `
            --name $keyVaultName `
            --resource-group $resourceGroupName `
            --query "location" `
            --output tsv 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $kvLocation -ne $location) {
            Write-Output "⚠ Warning: Existing Key Vault is in '$kvLocation', expected '$location'"
        }
    } else {
        Write-Output "Creating Key Vault '$keyVaultName'..."
        
        $createKvResult = az keyvault create `
            --name $keyVaultName `
            --resource-group $resourceGroupName `
            --location $location `
            --enable-rbac-authorization true 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Key Vault '$keyVaultName'. Error: $createKvResult"
        }
        
        Write-Output "✓ Key Vault '$keyVaultName' created"
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyKv = az keyvault show `
            --name $keyVaultName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyKv) {
            Write-Output "⚠ Warning: Could not verify Key Vault creation"
        }
    }
} catch {
    Write-Error "Error managing Key Vault '$keyVaultName': $_"
    throw
}

# Grant App Service managed identity access to Key Vault secrets
try {
    Write-Output "Granting App Service managed identity access to Key Vault..."
    
    # Get subscription ID
    $subscriptionId = az account show --query id --output tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($subscriptionId)) {
        throw "Failed to retrieve subscription ID"
    }
    
    # Construct Key Vault scope
    $kvScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$keyVaultName"
    
    # Check if role assignment already exists
    $existingKvRole = az role assignment list `
        --assignee $appServiceIdentityId `
        --scope $kvScope `
        --role "Key Vault Secrets User" `
        --query "[].id" `
        --output tsv 2>$null
    
    if ($existingKvRole) {
        Write-Output "⚠ App Service already has 'Key Vault Secrets User' role"
    } else {
        $kvRoleResult = az role assignment create `
            --role "Key Vault Secrets User" `
            --assignee $appServiceIdentityId `
            --scope $kvScope 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to assign Key Vault role to App Service identity. Error: $kvRoleResult"
        }
        
        Write-Output "✓ App Service granted access to Key Vault"
    }
} catch {
    Write-Error "Error granting App Service access to Key Vault: $_"
    throw
}

# Grant current user full access to key vault
try {
    Write-Output "Granting current user administrator access to Key Vault..."
    
    # Current user ID already retrieved and validated above
    if ([string]::IsNullOrWhiteSpace($currentUserId)) {
        $currentUserId = az ad signed-in-user show --query id --output tsv 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($currentUserId)) {
            throw "Failed to retrieve current user ID"
        }
    }
    
    # Get subscription ID
    $subscriptionId = az account show --query id --output tsv 2>$null
    $kvScope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$keyVaultName"
    
    # Check if role assignment already exists
    $existingAdminRole = az role assignment list `
        --assignee $currentUserId `
        --scope $kvScope `
        --role "Key Vault Administrator" `
        --query "[].id" `
        --output tsv 2>$null
    
    if ($existingAdminRole) {
        Write-Output "⚠ Current user already has 'Key Vault Administrator' role"
    } else {
        $adminRoleResult = az role assignment create `
            --role "Key Vault Administrator" `
            --assignee $currentUserId `
            --scope $kvScope 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to assign Key Vault Administrator role. Error: $adminRoleResult"
        }
        
        Write-Output "✓ Current user granted 'Key Vault Administrator' role"
    }
    
    # Wait for RBAC propagation
    Write-Output "Waiting for RBAC permissions to propagate..."
    Start-Sleep -Seconds 15
} catch {
    Write-Error "Error granting current user access to Key Vault: $_"
    throw
}

# Store MySQL password in Key Vault
try {
    Write-Output "Storing MySQL password in Key Vault..."
    
    # Validate password is not empty
    if ([string]::IsNullOrWhiteSpace($mysqlAdminPassword)) {
        throw "MySQL admin password is empty. Cannot store in Key Vault."
    }
    
    # Check if secret already exists
    $existingSecret = az keyvault secret show `
        --vault-name $keyVaultName `
        --name "MySQLAdminPassword" `
        --query "name" `
        --output tsv 2>$null
    
    if ($existingSecret) {
        Write-Output "⚠ MySQL password secret already exists in Key Vault"
        Write-Output "  Updating existing secret..."
    }
    
    $secretResult = az keyvault secret set `
        --vault-name $keyVaultName `
        --name "MySQLAdminPassword" `
        --value $mysqlAdminPassword 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to store MySQL password in Key Vault. Error: $secretResult"
    }
    
    Write-Output "✓ MySQL password stored in Key Vault"
    
    # Verify secret was created
    Start-Sleep -Seconds 2
    $verifySecret = az keyvault secret show `
        --vault-name $keyVaultName `
        --name "MySQLAdminPassword" `
        --query "name" `
        --output tsv 2>$null
    
    if (-not $verifySecret) {
        Write-Output "⚠ Warning: Could not verify secret creation in Key Vault"
    }
} catch {
    Write-Error "Error storing MySQL password in Key Vault: $_"
    Write-Output "⚠ You may need to manually store the password or check RBAC permissions"
    throw
}

# Create MySQL Flexible Server
# Create MySQL Flexible Server
try {
    Write-Output "Checking if MySQL Flexible Server '$mysqlServerName' exists..."
    
    # Validate MySQL server name (3-63 chars, lowercase alphanumeric and hyphens, must start with letter)
    if ($mysqlServerName -notmatch '^[a-z][a-z0-9\-]{1,61}[a-z0-9]$') {
        throw "Invalid MySQL server name '$mysqlServerName'. Must be 3-63 lowercase alphanumeric characters and hyphens, starting with a letter."
    }
    
    # Validate admin username
    if ([string]::IsNullOrWhiteSpace($mysqlAdminUserName)) {
        throw "MySQL admin username is not set. Please configure `$mysqlAdminUserName variable."
    }
    
    # Validate admin password
    if ([string]::IsNullOrWhiteSpace($mysqlAdminPassword)) {
        throw "MySQL admin password is not set. Please configure `$mysqlAdminPassword variable."
    }
    
    $mysqlExists = az mysql flexible-server show `
        --name $mysqlServerName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if MySQL Flexible Server exists. Exit code: $LASTEXITCODE"
    }
    
    if ($mysqlExists) {
        Write-Output "⚠ MySQL Flexible Server '$mysqlServerName' already exists"
        
        # Verify server configuration
        $serverDetails = az mysql flexible-server show `
            --name $mysqlServerName `
            --resource-group $resourceGroupName `
            --query "{sku:sku.name, version:version, location:location}" `
            --output json 2>$null | ConvertFrom-Json
        
        if ($LASTEXITCODE -ne 0) {
            Write-Output "⚠ Warning: Could not verify MySQL server configuration"
        } else {
            if ($serverDetails.sku -ne $mysqlSku) {
                Write-Output "⚠ Warning: Existing MySQL SKU is '$($serverDetails.sku)', expected '$mysqlSku'"
            }
            if ($serverDetails.version -ne $mySQLVersion) {
                Write-Output "⚠ Warning: Existing MySQL version is '$($serverDetails.version)', expected '$mySQLVersion'"
            }
            if ($serverDetails.location -ne $location) {
                Write-Output "⚠ Warning: Existing MySQL server is in '$($serverDetails.location)', expected '$location'"
            }
        }
    } else {
        Write-Output "Creating MySQL Flexible Server '$mysqlServerName'..."
        Write-Output "ℹ Using IP range for initial firewall: $currentIp-$currentIp"
        
        # Validate SKU format
        if ($mysqlSku -notmatch '^(Standard|Burstable)_[A-Z0-9]+$') {
            throw "Invalid MySQL SKU format '$mysqlSku'. Expected format: Standard_B1ms, Burstable_B1s, etc."
        }
        
        $createResult = az mysql flexible-server create `
            --name $mysqlServerName `
            --resource-group $resourceGroupName `
            --location $location `
            --admin-user $mysqlAdminUserName `
            --admin-password $mysqlAdminPassword `
            --sku-name $mysqlSku `
            --zone 1 `
            --version $mySQLVersion `
            --public-access "$currentIp-$currentIp" 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create MySQL Flexible Server '$mysqlServerName'. Error: $createResult"
        }
        
        Write-Output "✓ MySQL Flexible Server '$mysqlServerName' created"
        
        # Verify creation
        Start-Sleep -Seconds 10
        $verifyServer = az mysql flexible-server show `
            --name $mysqlServerName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyServer) {
            Write-Output "⚠ Warning: Could not verify MySQL server creation"
        }
    }
} catch {
    Write-Error "Error managing MySQL Flexible Server '$mysqlServerName': $_"
    throw
}

# Add firewall rule for Azure services
try {
    Write-Output "Configuring MySQL firewall rule for Azure services..."
    
    $mysqlFwRuleExists = az mysql flexible-server firewall-rule show `
        --name $mysqlServerName `
        --resource-group $resourceGroupName `
        --rule-name AllowAzureIPs `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if MySQL firewall rule exists. Exit code: $LASTEXITCODE"
    }
    
    if ($mysqlFwRuleExists) {
        Write-Output "⚠ MySQL firewall rule 'AllowAzureIPs' already exists"
    } else {
        $fwRuleResult = az mysql flexible-server firewall-rule create `
            --name $mysqlServerName `
            --resource-group $resourceGroupName `
            --rule-name AllowAzureIPs `
            --start-ip-address 0.0.0.0 `
            --end-ip-address 0.0.0.0 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create MySQL firewall rule 'AllowAzureIPs'. Error: $fwRuleResult"
        }
        
        Write-Output "✓ MySQL firewall rule added for Azure services"
        
        # Verify firewall rule creation
        Start-Sleep -Seconds 3
        $verifyFwRule = az mysql flexible-server firewall-rule show `
            --name $mysqlServerName `
            --resource-group $resourceGroupName `
            --rule-name AllowAzureIPs `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyFwRule) {
            Write-Output "⚠ Warning: Could not verify MySQL firewall rule creation"
        }
    }
} catch {
    Write-Error "Error managing MySQL firewall rule: $_"
    throw
}

# Create MySQL database
try {
    Write-Output "Checking if MySQL Database '$mysqlDatabaseName' exists..."
    
    # Validate database name (1-64 chars, alphanumeric, underscores, must not start with number)
    if ($mysqlDatabaseName -notmatch '^[a-zA-Z_][a-zA-Z0-9_]{0,63}$') {
        throw "Invalid MySQL database name '$mysqlDatabaseName'. Must be 1-64 characters, alphanumeric and underscores, cannot start with a number."
    }
    
    $mysqlDbExists = az mysql flexible-server db show `
        --database-name $mysqlDatabaseName `
        --resource-group $resourceGroupName `
        --server-name $mysqlServerName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if MySQL database exists. Exit code: $LASTEXITCODE"
    }
    
    if ($mysqlDbExists) {
        Write-Output "⚠ MySQL Database '$mysqlDatabaseName' already exists"
        
        # Verify database charset and collation
        $dbDetails = az mysql flexible-server db show `
            --database-name $mysqlDatabaseName `
            --resource-group $resourceGroupName `
            --server-name $mysqlServerName `
            --query "{charset:charset, collation:collation}" `
            --output json 2>$null | ConvertFrom-Json
        
        if ($LASTEXITCODE -eq 0 -and $dbDetails) {
            Write-Output "  Database charset: $($dbDetails.charset)"
            Write-Output "  Database collation: $($dbDetails.collation)"
        }
    } else {
        Write-Output "Creating MySQL Database '$mysqlDatabaseName'..."
        
        $createDbResult = az mysql flexible-server db create `
            --database-name $mysqlDatabaseName `
            --resource-group $resourceGroupName `
            --server-name $mysqlServerName 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create MySQL database '$mysqlDatabaseName'. Error: $createDbResult"
        }
        
        Write-Output "✓ MySQL Database '$mysqlDatabaseName' created"
        
        # Verify database creation
        Start-Sleep -Seconds 5
        $verifyDb = az mysql flexible-server db show `
            --database-name $mysqlDatabaseName `
            --resource-group $resourceGroupName `
            --server-name $mysqlServerName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyDb) {
            Write-Output "⚠ Warning: Could not verify MySQL database creation"
        }
    }
} catch {
    Write-Error "Error managing MySQL database '$mysqlDatabaseName': $_"
    throw
}

# Create Log Analytics Workspace
# Create Log Analytics Workspace
try {
    Write-Output "Checking if Log Analytics Workspace '$logAnalyticsWorkspaceName' exists..."
    
    # Validate workspace name (4-63 chars, alphanumeric and hyphens, must start/end with alphanumeric)
    if ($logAnalyticsWorkspaceName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9\-]{2,61}[a-zA-Z0-9]$') {
        throw "Invalid Log Analytics Workspace name '$logAnalyticsWorkspaceName'. Must be 4-63 characters, alphanumeric and hyphens, start/end with alphanumeric."
    }
    
    $lawExists = az monitor log-analytics workspace show `
        --resource-group $resourceGroupName `
        --workspace-name $logAnalyticsWorkspaceName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if Log Analytics Workspace exists. Exit code: $LASTEXITCODE"
    }
    
    if ($lawExists) {
        Write-Output "⚠ Log Analytics Workspace '$logAnalyticsWorkspaceName' already exists"
        
        # Verify location
        $lawLocation = az monitor log-analytics workspace show `
            --resource-group $resourceGroupName `
            --workspace-name $logAnalyticsWorkspaceName `
            --query "location" `
            --output tsv 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $lawLocation -ne $location) {
            Write-Output "⚠ Warning: Existing workspace is in '$lawLocation', expected '$location'"
        }
    } else {
        Write-Output "Creating Log Analytics Workspace '$logAnalyticsWorkspaceName'..."
        
        $createLawResult = az monitor log-analytics workspace create `
            --resource-group $resourceGroupName `
            --workspace-name $logAnalyticsWorkspaceName `
            --location $location 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Log Analytics Workspace '$logAnalyticsWorkspaceName'. Error: $createLawResult"
        }
        
        Write-Output "✓ Log Analytics Workspace '$logAnalyticsWorkspaceName' created"
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyLaw = az monitor log-analytics workspace show `
            --resource-group $resourceGroupName `
            --workspace-name $logAnalyticsWorkspaceName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyLaw) {
            Write-Output "⚠ Warning: Could not verify Log Analytics Workspace creation"
        }
    }
} catch {
    Write-Error "Error managing Log Analytics Workspace '$logAnalyticsWorkspaceName': $_"
    throw
}

# Create Application Insights
try {
    Write-Output "Checking if Application Insights '$appInsightsName' exists..."
    
    # Validate Application Insights name (1-260 chars, alphanumeric, underscores, hyphens, periods, parentheses)
    if ($appInsightsName -notmatch '^[a-zA-Z0-9_\-\.\(\)]{1,260}$') {
        throw "Invalid Application Insights name '$appInsightsName'. Must be 1-260 characters, alphanumeric, underscores, hyphens, periods, parentheses."
    }
    
    $appInsightsExists = az monitor app-insights component show `
        --app $appInsightsName `
        --resource-group $resourceGroupName `
        --query "name" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3) {
        throw "Failed to check if Application Insights exists. Exit code: $LASTEXITCODE"
    }
    
    if ($appInsightsExists) {
        Write-Output "⚠ Application Insights '$appInsightsName' already exists"
        
        # Verify configuration
        $appInsightsDetails = az monitor app-insights component show `
            --app $appInsightsName `
            --resource-group $resourceGroupName `
            --query "{location:location, workspaceResourceId:workspaceResourceId}" `
            --output json 2>$null | ConvertFrom-Json
        
        if ($LASTEXITCODE -eq 0 -and $appInsightsDetails) {
            if ($appInsightsDetails.location -ne $location) {
                Write-Output "⚠ Warning: Existing Application Insights is in '$($appInsightsDetails.location)', expected '$location'"
            }
            if (-not $appInsightsDetails.workspaceResourceId) {
                Write-Output "⚠ Warning: Existing Application Insights is not linked to a Log Analytics workspace"
            }
        }
    } else {
        Write-Output "Creating Application Insights '$appInsightsName'..."
        
        # Verify Log Analytics Workspace exists before creating App Insights
        $lawVerify = az monitor log-analytics workspace show `
            --resource-group $resourceGroupName `
            --workspace-name $logAnalyticsWorkspaceName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $lawVerify) {
            throw "Log Analytics Workspace '$logAnalyticsWorkspaceName' does not exist. Cannot create Application Insights."
        }
        
        $createAppInsightsResult = az monitor app-insights component create `
            --app $appInsightsName `
            --location $location `
            --resource-group $resourceGroupName `
            --workspace $logAnalyticsWorkspaceName 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create Application Insights '$appInsightsName'. Error: $createAppInsightsResult"
        }
        
        Write-Output "✓ Application Insights '$appInsightsName' created"
        
        # Verify creation
        Start-Sleep -Seconds 5
        $verifyAppInsights = az monitor app-insights component show `
            --app $appInsightsName `
            --resource-group $resourceGroupName `
            --query "name" `
            --output tsv 2>$null
        
        if (-not $verifyAppInsights) {
            Write-Output "⚠ Warning: Could not verify Application Insights creation"
        }
    }
} catch {
    Write-Error "Error managing Application Insights '$appInsightsName': $_"
    throw
}

# Get Application Insights instrumentation key
try {
    Write-Output "Retrieving Application Insights instrumentation key..."
    
    $appInsightsKey = az monitor app-insights component show `
        --app $appInsightsName `
        --resource-group $resourceGroupName `
        --query "instrumentationKey" `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve Application Insights instrumentation key. Exit code: $LASTEXITCODE"
    }
    
    if ([string]::IsNullOrWhiteSpace($appInsightsKey)) {
        throw "Application Insights instrumentation key is empty"
    }
    
    # Validate GUID format
    if ($appInsightsKey -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
        throw "Invalid Application Insights instrumentation key format: '$appInsightsKey'"
    }
    
    Write-Output "✓ Application Insights instrumentation key retrieved"
} catch {
    Write-Error "Error retrieving Application Insights instrumentation key: $_"
    throw
}

# Store Application Insights key in Key Vault
try {
    Write-Output "Storing Application Insights key in Key Vault..."
    
    # Check if secret already exists
    $existingAISecret = az keyvault secret show `
        --vault-name $keyVaultName `
        --name "ApplicationInsightsKey" `
        --query "name" `
        --output tsv 2>$null
    
    if ($existingAISecret) {
        Write-Output "⚠ Application Insights key secret already exists in Key Vault"
        Write-Output "  Updating existing secret..."
    }
    
    $aiSecretResult = az keyvault secret set `
        --vault-name $keyVaultName `
        --name "ApplicationInsightsKey" `
        --value $appInsightsKey 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to store Application Insights key in Key Vault. Error: $aiSecretResult"
    }
    
    Write-Output "✓ Application Insights key stored in Key Vault"
    
    # Verify secret was created
    Start-Sleep -Seconds 2
    $verifyAISecret = az keyvault secret show `
        --vault-name $keyVaultName `
        --name "ApplicationInsightsKey" `
        --query "name" `
        --output tsv 2>$null
    
    if (-not $verifyAISecret) {
        Write-Output "⚠ Warning: Could not verify Application Insights key secret in Key Vault"
    }
} catch {
    Write-Error "Error storing Application Insights key in Key Vault: $_"
    throw
}

# Get Storage Account connection string
try {
    Write-Output "Retrieving Storage Account connection string..."
    
    $storageConnectionString = az storage account show-connection-string `
        --name $storageAccountName `
        --resource-group $resourceGroupName `
        --query connectionString `
        --output tsv 2>$null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve Storage Account connection string. Exit code: $LASTEXITCODE"
    }
    
    if ([string]::IsNullOrWhiteSpace($storageConnectionString)) {
        throw "Storage Account connection string is empty"
    }
    
    # Validate connection string format (should contain AccountName and AccountKey)
    if ($storageConnectionString -notmatch 'AccountName=' -or $storageConnectionString -notmatch 'AccountKey=') {
        throw "Invalid Storage Account connection string format"
    }
    
    Write-Output "✓ Storage Account connection string retrieved"
} catch {
    Write-Error "Error retrieving Storage Account connection string: $_"
    throw
}

# Store Storage Account connection string in Key Vault
try {
    Write-Output "Storing Storage Account connection string in Key Vault..."
    
    # Check if secret already exists
    $existingStorageSecret = az keyvault secret show `
        --vault-name $keyVaultName `
        --name "StorageConnectionString" `
        --query "name" `
        --output tsv 2>$null
    
    if ($existingStorageSecret) {
        Write-Output "⚠ Storage connection string secret already exists in Key Vault"
        Write-Output "  Updating existing secret..."
    }
    
    $storageSecretResult = az keyvault secret set `
        --vault-name $keyVaultName `
        --name "StorageConnectionString" `
        --value $storageConnectionString 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to store Storage connection string in Key Vault. Error: $storageSecretResult"
    }
    
    Write-Output "✓ Storage connection string stored in Key Vault"
    
    # Verify secret was created
    Start-Sleep -Seconds 2
    $verifyStorageSecret = az keyvault secret show `
        --vault-name $keyVaultName `
        --name "StorageConnectionString" `
        --query "name" `
        --output tsv 2>$null
    
    if (-not $verifyStorageSecret) {
        Write-Output "⚠ Warning: Could not verify Storage connection string secret in Key Vault"
    }
} catch {
    Write-Error "Error storing Storage connection string in Key Vault: $_"
    throw
}

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
