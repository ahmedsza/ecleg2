# =====================================================================
# Azure Front Door setup (PowerShell using az CLI) WITHOUT custom domains
# Apps:
#  - Blob storage container
#  - Static Web App 1
#  - Static Web App 2
#  - App Service API (locked so it only accepts traffic from this Front Door)
# =====================================================================

# -----------------------------
# VARIABLES (FILL THESE IN)
# -----------------------------

# Resource group where Front Door + Storage live
$RG_FRONTDOOR        = "frontdoor-rg"         # e.g. rg-frontdoor
$LOCATION_FRONTDOOR  = "southafricanorth"                 # e.g. eastus

# Front Door profile name (Standard/Premium profile)
$FD_PROFILE_NAME     = "fd-shared-profile"          # e.g. fd-shared-profile

$environment = "qa"

# Enable WAF protection (set to $true to enable, $false to skip)
$WAF = $true

# Storage account (blob) for direct exposure
$STORAGE_ACCOUNT_NAME   = "ahmsecplstorage$environment"  # e.g. mystorageacct
$STORAGE_CONTAINER_NAME = "zvetest-3"        # e.g. public

# Static Web App 1 default hostname (from Azure portal)
$WEBMANAGER_DEFAULT_HOSTNAME  = "polite-ground-0b8f74703.3.azurestaticapps.net" # e.g. app1.graystone123.azurestaticapps.net

# Static Web App 2 default hostname (from Azure portal)
$PUBLICSITE_DEFAULT_HOSTNAME  = "calm-wave-04545e203.3.azurestaticapps.net" # e.g. app2.orangepearl456.azurestaticapps.net

# App Service (API) default hostname (from Azure portal)
$APPSVC_DEFAULT_HOSTNAME = "ahmsecpl-appservice-qa.azurewebsites.net" # e.g. myapi.azurewebsites.net


# App Service identity (for access restrictions)
$APPSVC_RG      = "ahms-ecpl-websites-rg-$environment"           # e.g. rg-apps (can be same as $RG_FRONTDOOR)
$APPSVC_NAME    = "ahmsecpl-appservice-$environment"         # e.g. myapi
$STORAGE_RG    = "ahms-ecpl-websites-rg-$environment"   # assuming storage is in same RG as Front Door
# -----------------------------
# DERIVED NAMES (CAN KEEP)
# -----------------------------

$FD_ENDPOINT_STORAGE = "fd-endpoint-storage-$environment"
$FD_ENDPOINT_WEBMANAGER  = "fd-endpoint-webmanager-$environment"
$FD_ENDPOINT_PUBLICSITE  = "fd-endpoint-publicsite-$environment"
$FD_ENDPOINT_API = "fd-endpoint-api-$environment"

$OG_STORAGE = "og-storage-$environment"
$OG_WEBMANAGER  = "og-webmanager-$environment"
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
# 1. RG FOR FRONT DOOR
# =====================================================================

az group create `
  --name $RG_FRONTDOOR `
  --location $LOCATION_FRONTDOOR

# =====================================================================
# 2. FRONT DOOR PROFILE
# =====================================================================

az afd profile create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --sku Standard_AzureFrontDoor 
  
# =====================================================================
# 2.5. WAF POLICY (CONDITIONAL)
# =====================================================================

if ($WAF) {
    $WAF_POLICY_NAME = "waf-policy-$environment"
    
    Write-Host "Creating WAF Policy: $WAF_POLICY_NAME"
    
    # Create WAF Policy
    az network front-door waf-policy create `
        --resource-group $RG_FRONTDOOR `
        --name $WAF_POLICY_NAME `
        --sku Standard_AzureFrontDoor `
        --mode Prevention
    
    # Enable managed rule sets (OWASP protection)
    az network front-door waf-policy managed-rules add `
        --policy-name $WAF_POLICY_NAME `
        --resource-group $RG_FRONTDOOR `
        --type Microsoft_DefaultRuleSet `
        --version 2.1 `
        --action Block
    
    # Enable bot protection
    az network front-door waf-policy managed-rules add `
        --policy-name $WAF_POLICY_NAME `
        --resource-group $RG_FRONTDOOR `
        --type Microsoft_BotManagerRuleSet `
        --version 1.0 `
        --action Block
    
    # Add rate limiting rule (100 requests per minute per IP)
    az network front-door waf-policy rule create `
        --policy-name $WAF_POLICY_NAME `
        --resource-group $RG_FRONTDOOR `
        --name "RateLimitRule" `
        --priority 100 `
        --rule-type RateLimitRule `
        --action Block `
        --rate-limit-threshold 100 `
        --rate-limit-duration-in-minutes 1 `
        --match-condition RemoteAddr IPMatch Any
    
    Write-Host "✓ WAF Policy '$WAF_POLICY_NAME' created with OWASP, bot protection, and rate limiting"
} else {
    Write-Host "⚠ WAF protection disabled (WAF variable set to false)"
}


# =====================================================================
# 3. ENDPOINTS
# =====================================================================

az afd endpoint create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_STORAGE `
  --enabled-state Enabled 
  
  
az afd endpoint create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_WEBMANAGER `
  --enabled-state Enabled 
  
az afd endpoint create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_PUBLICSITE `
  --enabled-state Enabled 


az afd endpoint create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_API `
  --enabled-state Enabled 
  
# =====================================================================
# 3.5. SECURITY POLICY (CONDITIONAL WAF)
# =====================================================================

if ($WAF) {
    $SECURITY_POLICY_NAME = "security-policy-$environment"
    
    # Get WAF Policy ID
    $WAF_POLICY_ID = az network front-door waf-policy show `
        --resource-group $RG_FRONTDOOR `
        --name $WAF_POLICY_NAME `
        --query "id" -o tsv
    
    Write-Host "Associating WAF policy with all endpoints..."
    
    # Create Security Policy and associate with all endpoints
    az afd security-policy create `
        --resource-group $RG_FRONTDOOR `
        --profile-name $FD_PROFILE_NAME `
        --security-policy-name $SECURITY_POLICY_NAME `
        --domains "$FD_ENDPOINT_STORAGE.azurefd.net" "$FD_ENDPOINT_WEBMANAGER.azurefd.net" "$FD_ENDPOINT_PUBLICSITE.azurefd.net" "$FD_ENDPOINT_API.azurefd.net" `
        --waf-policy $WAF_POLICY_ID
    
    Write-Host "✓ Security Policy '$SECURITY_POLICY_NAME' created and associated with all endpoints"
    Write-Host "✓ WAF protection active on: Storage, Web Manager, Public Site, and API endpoints"
} else {
    Write-Host "⚠ WAF security policy skipped (WAF variable set to false)"
}

# =====================================================================================================================================
# 4. ORIGINS
# =====================================================================

# 4.1 Storage origin (blob)

$BLOB_ENDPOINT = az storage account show `
  --name $STORAGE_ACCOUNT_NAME `
  --resource-group $STORAGE_RG `
  --query "primaryEndpoints.blob" -o tsv

$BLOB_HOST = $BLOB_ENDPOINT -replace '^https?://', '' -replace '/$',''


Write-Host "Blob endpoint: $BLOB_ENDPOINT"
Write-Host "Blob host:     $BLOB_HOST"

az afd origin-group create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_STORAGE `
  --probe-request-type GET `
  --probe-protocol Https `
  --probe-path "/" `
  --probe-interval-in-seconds 120 `
  --sample-size 4 `
  --successful-samples-required 3 `
  --additional-latency-in-milliseconds 0 

az afd origin create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_STORAGE `
  --origin-name $ORIGIN_STORAGE `
  --host-name $BLOB_HOST `
  --http-port 80 `
  --https-port 443 `
  --origin-host-header $BLOB_HOST `
  --priority 1 `
  --weight 100 `
  --enabled-state Enabled 

# Map root of storage endpoint to the container
$STORAGE_ORIGIN_PATH = "/$STORAGE_CONTAINER_NAME"

# 4.2 WEBMANAGER origin

$WEBMANAGER_HOST = $WEBMANAGER_DEFAULT_HOSTNAME

az afd origin-group create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_WEBMANAGER `
  --probe-request-type GET `
  --probe-protocol Https `
  --probe-path "/" `
  --probe-interval-in-seconds 120 `
  --sample-size 4 `
  --successful-samples-required 3 `
  --additional-latency-in-milliseconds 0 | Out-Null

az afd origin create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_WEBMANAGER `
  --origin-name $ORIGIN_WEBMANAGER `
  --host-name $WEBMANAGER_HOST `
  --http-port 80 `
  --https-port 443 `
  --origin-host-header $WEBMANAGER_HOST `
  --priority 1 `
  --weight 100 `
  --enabled-state Enabled | Out-Null

# 4.3 PUBLICSITE origin

$PUBLICSITE_HOST = $PUBLICSITE_DEFAULT_HOSTNAME

az afd origin-group create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_PUBLICSITE `
  --probe-request-type GET `
  --probe-protocol Https `
  --probe-path "/" `
  --probe-interval-in-seconds 120 `
  --sample-size 4 `
  --successful-samples-required 3 `
  --additional-latency-in-milliseconds 0 

az afd origin create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_PUBLICSITE `
  --origin-name $ORIGIN_PUBLICSITE `
  --host-name $PUBLICSITE_HOST `
  --http-port 80 `
  --https-port 443 `
  --origin-host-header $PUBLICSITE_HOST `
  --priority 1 `
  --weight 100 `
  --enabled-state Enabled 

# 4.4 API (App Service) origin

$API_HOST = $APPSVC_DEFAULT_HOSTNAME  # e.g. myapi.azurewebsites.net

az afd origin-group create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_API `
  --probe-request-type GET `
  --probe-protocol Https `
  --probe-path "/" `
  --probe-interval-in-seconds 120 `
  --sample-size 4 `
  --successful-samples-required 3 `
  --additional-latency-in-milliseconds 0 

az afd origin create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --origin-group-name $OG_API `
  --origin-name $ORIGIN_API `
  --host-name $API_HOST `
  --http-port 80 `
  --https-port 443 `
  --origin-host-header $API_HOST `
  --priority 1 `
  --weight 100 `
  --enabled-state Enabled

# =====================================================================
# 5. ROUTES
# =====================================================================

# Storage route
az afd route create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
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
  --query-string-caching-behavior IgnoreQueryString `
  --cache-duration P7D 
  
# WEBMANAGER route
az afd route create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_WEBMANAGER `
  --route-name $ROUTE_WEBMANAGER `
  --origin-group $OG_WEBMANAGER `
  --patterns-to-match "/*" `
  --https-redirect Enabled `
  --supported-protocols Http Https `
  --forwarding-protocol MatchRequest `
  --link-to-default-domain Enabled `
  --enable-caching true `
  --query-string-caching-behavior UseQueryString `
  --cache-duration PT1H 
 
# PUBLICSITE route
az afd route create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_PUBLICSITE `
  --route-name $ROUTE_PUBLICSITE `
  --origin-group $OG_PUBLICSITE `
  --patterns-to-match "/*" `
  --https-redirect Enabled `
  --supported-protocols Http Https `
  --forwarding-protocol MatchRequest `
  --link-to-default-domain Enabled `
  --enable-caching true `
  --query-string-caching-behavior UseQueryString `
  --cache-duration PT1H 
  
# API route
az afd route create `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_API `
  --route-name $ROUTE_API `
  --origin-group $OG_API `
  --patterns-to-match "/*" `
  --https-redirect Enabled `
  --supported-protocols Http Https `
  --forwarding-protocol MatchRequest `
  --link-to-default-domain Enabled `
  --enable-caching false 

# =====================================================================
# 6. SHOW FRONT DOOR ENDPOINT HOSTNAMES
# =====================================================================

$FD_HOST_STORAGE = az afd endpoint show `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_STORAGE `
  --query "hostName" -o tsv

$FD_HOST_WEBMANAGER = az afd endpoint show `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_WEBMANAGER `
  --query "hostName" -o tsv

$FD_HOST_PUBLICSITE = az afd endpoint show `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_PUBLICSITE `
  --query "hostName" -o tsv

$FD_HOST_API = az afd endpoint show `
  --resource-group $RG_FRONTDOOR `
  --profile-name $FD_PROFILE_NAME `
  --endpoint-name $FD_ENDPOINT_API `
  --query "hostName" -o tsv

Write-Host ""
Write-Host "Front Door endpoints created:"
Write-Host "  Storage: $FD_HOST_STORAGE"
Write-Host "  WEBMANAGER:    $FD_HOST_WEBMANAGER"
Write-Host "  PUBLICSITE:    $FD_HOST_PUBLICSITE"
Write-Host "  API:     $FD_HOST_API"
Write-Host ""
Write-Host "Example URLs:"
Write-Host "  https://$FD_HOST_STORAGE/ (-> blob container $STORAGE_CONTAINER_NAME)"
Write-Host "  https://$FD_HOST_WEBMANAGER/"
Write-Host "  https://$FD_HOST_PUBLICSITE/"
Write-Host "  https://$FD_HOST_API/"

# =====================================================================
# 7. GET FRONT DOOR FDID (Standard/Premium) AND LOCK APP SERVICE
# =====================================================================

# Get FDID from Microsoft.Cdn/profiles (properties.frontDoorId)
$FRONTDOOR_FDID = az resource show `
  -g $RG_FRONTDOOR `
  -n $FD_PROFILE_NAME `
  --namespace Microsoft.Cdn `
  --resource-type Profiles `
  --query "properties.frontDoorId" -o tsv

Write-Host ""
Write-Host "Front Door FDID: $FRONTDOOR_FDID"

if ($FRONTDOOR_FDID) {
    az webapp config access-restriction add `
      --resource-group $APPSVC_RG `
      --name $APPSVC_NAME `
      --rule-name "Allow-This-FrontDoor" `
      --action Allow `
      --priority 100 `
      --service-tag AzureFrontDoor.Backend `
      --http-header "x-azure-fdid=$FRONTDOOR_FDID"

    az webapp config access-restriction set `
      --resource-group $APPSVC_RG `
      --name $APPSVC_NAME `
      --default-action Deny

    Write-Host ""
    Write-Host "App Service access restrictions configured:"
    Write-Host "  App: $APPSVC_NAME (RG: $APPSVC_RG)"
    Write-Host "  Allowed: AzureFrontDoor.Backend with x-azure-fdid = $FRONTDOOR_FDID"
    Write-Host "  Default action: Deny"
    Write-Host "Direct access to https://$APPSVC_NAME.azurewebsites.net should now be blocked except via this Front Door."
} else {
    Write-Host ""
    Write-Host "Could not retrieve FRONTDOOR_FDID from Microsoft.Cdn/profiles; skipping App Service lock-down."
}
