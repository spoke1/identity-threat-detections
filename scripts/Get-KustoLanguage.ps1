<#
.SYNOPSIS
    Downloads the Kusto.Language parser (Microsoft.Azure.Kusto.Language) used to
    validate the detection queries and returns the path of the assembly.

.DESCRIPTION
    Kusto.Language is the open-source KQL parser and semantic analyser that also
    powers the query editors of Azure Data Explorer and Log Analytics. The
    package version and its SHA-256 checksum are pinned. The download is
    verified before it is extracted, and the result is cached in .tools/.

.PARAMETER Destination
    Cache folder. Default: .tools/ in the repository root.

.EXAMPLE
    $dll = .\scripts\Get-KustoLanguage.ps1

    Downloads the pinned version once and returns the path of Kusto.Language.dll.

.NOTES
    Author : Ramón Lotz
    Version: 1.0.0
#>
#Requires -Version 7.2
[CmdletBinding()]
[OutputType([string])]
param(
    [string]$Destination = (Join-Path -Path $PSScriptRoot -ChildPath '../.tools')
)

$ErrorActionPreference = 'Stop'

$packageVersion = '12.4.1'
$packageSha256 = '154c176ac9c1c4ae9cf0bc53b74354c9d35798ff587f81fe6e0005028a0a1961'

$folder = Join-Path -Path $Destination -ChildPath "Kusto.Language.$packageVersion"
$dll = Join-Path -Path $folder -ChildPath 'lib/net6.0/Kusto.Language.dll'
if (Test-Path -LiteralPath $dll) { return (Resolve-Path -LiteralPath $dll).Path }

New-Item -ItemType Directory -Path $folder -Force | Out-Null
$package = Join-Path -Path $folder -ChildPath 'package.nupkg'
Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.Azure.Kusto.Language/$packageVersion" -OutFile $package

$actual = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $packageSha256) {
    Remove-Item -LiteralPath $folder -Recurse -Force
    throw "Checksum mismatch for Microsoft.Azure.Kusto.Language $packageVersion. Expected $packageSha256, got $actual."
}

Expand-Archive -LiteralPath $package -DestinationPath $folder -Force
(Resolve-Path -LiteralPath $dll).Path
