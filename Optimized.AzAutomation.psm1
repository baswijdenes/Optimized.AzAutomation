#region main
function Get-KeyVaultCredential {
    <#
    .SYNOPSIS
    Use this to get secrets from the KeyVault.

    .DESCRIPTION
    Function gets an AccessToken for the managed Identity by using: New-ManagedIdentityAccessToken
    
    .PARAMETER Username
    Username should be the same name as the secretname in the KeyVault.
    
    .PARAMETER KeyVault
    Default is Azure Automation Variable KeyVaultName.  

    .PARAMETER SecretOnly
    By Default the function gives back the Credentials as a Credential. 
    By using SecretOnly it will return the secret as plain text.
    
    .EXAMPLE
    Get-KeyVaultCredential -UserName 'KeyVaultSecretName' -KeyVault 'KeyVaultName'

    Get-KeyVaultCredential -UserName 'KeyVaultSecretName' -KeyVault 'KeyVaultName' -SecretOnly
    
    .NOTES
    Author: Bas Wijdenes
    #>
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        $Username,
        [parameter(mandatory = $true)]
        $KeyVault,
        [parameter(mandatory = $false)]
        [switch]
        $SecretOnly
    )
    begin {
        Write-Verbose "Get-KeyVaultCredential: begin: Getting Authorization token with internal cmdlet: New-ManagedIdentityAccessToken"
        $Headers = New-ManagedIdentityAccessToken -Resource 'https://vault.azure.net'
        Write-Verbose "Get-KeyVaultCredential: begin: Headers: $Headers"
    }
    process {
        $KeyVaultSplatting = @{
            Uri     = 'https://{0}.vault.azure.net/secrets/{1}?api-version=2016-10-01' -f $PSBoundParameters.KeyVault, $PSBoundParameters.Username
            Method  = 'Get'
            Headers = $Headers
        }
        if ($PSBoundParameters.SecretOnly -ne $true) {
            $Password = (Invoke-RestMethod @KeyVaultSplatting).value | ConvertTo-SecureString -AsPlainText -Force
            $Credential = [PSCredential]::new($PSBoundParameters.Username, $Password)
        }
        else {
            Write-Verbose "Get-KeyVaultCredential: process: SecretOnly -eq $($PSBoundParameters.SecretOnly) | Secret is returned in PlainText"
            $Credential = (Invoke-RestMethod @KeyVaultSplatting).value
        }
    }
    end {
        return $Credential
    }
}
#endregion main
#region internal
function New-ManagedIdentityAccessToken {
    <#
    .DESCRIPTION
    Resources:
    'https://vault.azure.net'
    'https://management.azure.com'
    'https://storage.azure.com/'
    
    .PARAMETER Resource
    The Resource to get the AccessToken from.    

    .NOTES
    Author: Bas Wijdenes
    #>
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        $Resource
    )
    begin {
        Write-Verbose "New-ManagedIdentityAccessToken: begin: Building Headers & Body"
        $URL = $env:IDENTITY_ENDPOINT  
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
        $Headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
        $Headers.Add("Metadata", "True") 
        $Body = @{resource = $PSBoundParameters.Resource }
        Write-Verbose "New-ManagedIdentityAccessToken: begin: URL: $URL | Headers: $Headers | Body: $Body"
    }
    process {
        Write-Verbose "New-ManagedIdentityAccessToken: process: Requesting Access Token from $Resource"
        $AccessToken = Invoke-RestMethod $URL -Method 'POST' -Headers $Headers -ContentType 'application/x-www-form-urlencoded' -Body $Body 
        $Headers = @{
            Authorization = "Bearer $($AccessToken.access_token)"
        }
    }
    end {
        return $Headers
    }
}
#endregion internal