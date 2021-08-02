# Pre-requisites
if ((Get-Module -ListAvailable -Name "AzureAD") -eq $null) { 
    Install-Module "AzureAD" -Scope CurrentUser 
} 
Import-Module AzureAD

Connect-AzureAD -TenantId "cc7743d2-9026-44df-ba0e-33f87ebba062"

New-AzureADServicePrincipal -AppId bbb94529-53a3-4be5-a069-7eaf2712b826 -DisplayName "Verifiable Credential Request Service"