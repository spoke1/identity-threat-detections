<#
.SYNOPSIS
    Converts the detection YAML files into Microsoft Sentinel scheduled analytics
    rules (dist/sentinel-rules.json) and renders the ATT&CK coverage page
    (docs/coverage.md).

.DESCRIPTION
    The YAML files are the source of truth. This script turns them into the
    property bag of the Microsoft.SecurityInsights/alertRules resource, which
    deploy/sentinel-rules.bicep deploys to a workspace.

    Mapping details:
      - queryFrequency and queryPeriod (5m, 1h, 1d) become ISO 8601 durations.
      - The generally available alert rule API accepts ATT&CK techniques only
        (T1098), not sub-techniques. The parent techniques go into
        "techniques", the exact sub-techniques into the rule description.
      - Repository-specific fields (falsePositives, triage, preventiveControls,
        references) are appended to the description, so analysts see them in
        the incident.

    With -Check, nothing is written. The script fails when the committed files
    differ from what the YAML files produce.

.PARAMETER Path
    Folder with the detection YAML files. Default: detections/

.PARAMETER OutputPath
    Target file for the rules. Default: dist/sentinel-rules.json

.PARAMETER CoveragePath
    Target file for the coverage page. Default: docs/coverage.md

.PARAMETER TechniquePath
    ATT&CK technique names. Default: schemas/attack-techniques.json

.PARAMETER Check
    Verifies that the committed output is up to date instead of writing it.

.EXAMPLE
    .\scripts\Build-SentinelRules.ps1

    Regenerates dist/sentinel-rules.json and docs/coverage.md.

.EXAMPLE
    .\scripts\Build-SentinelRules.ps1 -Check

    Fails if the committed output is out of date (used in CI).

.NOTES
    Requires the powershell-yaml module.

    Author : Ramón Lotz
    Version: 1.0.0
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$Path = (Join-Path -Path $PSScriptRoot -ChildPath '../detections'),

    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath '../dist/sentinel-rules.json'),

    [string]$CoveragePath = (Join-Path -Path $PSScriptRoot -ChildPath '../docs/coverage.md'),

    [string]$TechniquePath = (Join-Path -Path $PSScriptRoot -ChildPath '../schemas/attack-techniques.json'),

    [switch]$Check
)

#region Functions

function ConvertTo-IsoDuration {
    <#
    .SYNOPSIS
        Converts a Sentinel YAML duration (5m, 1h, 14d) to ISO 8601 (PT5M, PT1H, P14D).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Duration)

    if ($Duration -notmatch '^(\d+)([mhd])$') { throw "Invalid duration '$Duration'. Use a number followed by m, h or d." }
    $value = $Matches[1]
    switch ($Matches[2]) {
        'm' { "PT${value}M" }
        'h' { "PT${value}H" }
        'd' { "P${value}D" }
    }
}

function Get-ParentTechnique {
    <#
    .SYNOPSIS
        Returns the unique parent techniques of a list of techniques and sub-techniques.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string[]]$Technique)

    [string[]]@($Technique | ForEach-Object { ($_ -split '\.')[0] } | Select-Object -Unique)
}

function Format-RuleDescription {
    <#
    .SYNOPSIS
        Builds the rule description shown in the Sentinel portal and in incidents.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Detection)

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(([string]$Detection.description).Trim())
    $lines.Add('')
    $lines.Add("MITRE ATT&CK: $(@($Detection.relevantTechniques) -join ', ')")
    $lines.Add('')
    $lines.Add('False positives:')
    foreach ($item in $Detection.falsePositives) { $lines.Add("- $item") }
    $lines.Add('')
    $lines.Add('Triage:')
    foreach ($item in $Detection.triage) { $lines.Add("- $item") }
    $lines.Add('')
    $lines.Add('Preventive controls:')
    foreach ($item in $Detection.preventiveControls) { $lines.Add("- $item") }
    $lines.Add('')
    $lines.Add("Source: identity-threat-detections $($Detection.detectionId) v$($Detection.version)")
    $lines -join "`n"
}

function ConvertTo-SentinelRule {
    <#
    .SYNOPSIS
        Converts one detection into the name and property bag of a scheduled analytics rule.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Detection)

    $operators = @{ gt = 'GreaterThan'; lt = 'LessThan'; eq = 'Equal'; ne = 'NotEqual' }
    $entityMappings = @(foreach ($mapping in $Detection.entityMappings) {
            [ordered]@{
                entityType    = [string]$mapping.entityType
                fieldMappings = @(foreach ($field in $mapping.fieldMappings) {
                        [ordered]@{ identifier = [string]$field.identifier; columnName = [string]$field.columnName }
                    })
            }
        })

    [ordered]@{
        name       = [string]$Detection.id
        properties = [ordered]@{
            displayName           = "$($Detection.detectionId) $($Detection.name)"
            description           = Format-RuleDescription -Detection $Detection
            severity              = [string]$Detection.severity
            enabled               = $true
            query                 = ([string]$Detection.query).TrimEnd()
            queryFrequency        = ConvertTo-IsoDuration -Duration $Detection.queryFrequency
            queryPeriod           = ConvertTo-IsoDuration -Duration $Detection.queryPeriod
            triggerOperator       = $operators[[string]$Detection.triggerOperator]
            triggerThreshold      = [int]$Detection.triggerThreshold
            suppressionEnabled    = $false
            suppressionDuration   = 'PT5H'
            tactics               = [string[]]@($Detection.tactics)
            # Wrapped in @(), so a single technique stays an array in the JSON output.
            techniques            = [string[]]@(Get-ParentTechnique -Technique @($Detection.relevantTechniques))
            entityMappings        = $entityMappings
            eventGroupingSettings = [ordered]@{ aggregationKind = 'AlertPerResult' }
            incidentConfiguration = [ordered]@{
                createIncident        = $true
                groupingConfiguration = [ordered]@{
                    enabled              = $false
                    reopenClosedIncident = $false
                    lookbackDuration     = 'PT5H'
                    matchingMethod       = 'AllEntities'
                }
            }
        }
    }
}

function Format-CoverageReport {
    <#
    .SYNOPSIS
        Renders the ATT&CK coverage page: techniques, detections and preventive controls.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Detection,
        [Parameter(Mandatory)][System.Collections.IDictionary]$TechniqueName
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# ATT&CK coverage')
    $lines.Add('')
    $lines.Add('Generated from the detection files by `scripts/Build-SentinelRules.ps1`. Do not edit by hand.')
    $lines.Add('')
    $lines.Add('## By technique')
    $lines.Add('')
    $lines.Add('| Technique | Detections | Preventive controls |')
    $lines.Add('|---|---|---|')

    $techniques = @($Detection | ForEach-Object { $_.relevantTechniques } | Sort-Object -Unique)
    foreach ($technique in $techniques) {
        $matching = @($Detection | Where-Object { @($_.relevantTechniques) -contains $technique } | Sort-Object -Property { $_.detectionId })
        $url = "https://attack.mitre.org/techniques/$($technique.Replace('.', '/'))/"
        $detections = ($matching | ForEach-Object { "$($_.detectionId) $($_.name)" }) -join '<br>'
        $controls = (@($matching | ForEach-Object { $_.preventiveControls } | Select-Object -Unique)) -join '<br>'
        $lines.Add("| [$technique]($url) $($TechniqueName[$technique]) | $detections | $controls |")
    }

    $lines.Add('')
    $lines.Add('## By detection')
    $lines.Add('')
    $lines.Add('| Detection | Severity | Data | Tactics | Techniques |')
    $lines.Add('|---|---|---|---|---|')
    foreach ($d in ($Detection | Sort-Object -Property { $_.detectionId })) {
        $data = (@($d.requiredDataConnectors | ForEach-Object { $_.dataTypes } | Select-Object -Unique)) -join ', '
        $lines.Add("| $($d.detectionId) $($d.name) | $($d.severity) | $data | $(@($d.tactics) -join ', ') | $(@($d.relevantTechniques) -join ', ') |")
    }

    $lines -join "`n"
}

function Write-Utf8File {
    <#
    .SYNOPSIS
        Writes text as UTF-8 without BOM, with LF line endings and a final newline.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    if ($PSCmdlet.ShouldProcess($Path, 'Write file')) {
        New-Item -ItemType Directory -Path (Split-Path -Path $Path -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($Path, ($Content -replace "`r`n", "`n").TrimEnd("`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    }
}

#endregion Functions

# When the script is dot-sourced (for example by the Pester tests), only load the functions.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'

Import-Module powershell-yaml

$detections = @(Get-ChildItem -LiteralPath $Path -Recurse -Filter '*.yaml' | ForEach-Object {
        Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Yaml -Ordered
    } | Sort-Object -Property { $_.detectionId })

$techniqueName = [ordered]@{}
foreach ($t in (Get-Content -LiteralPath $TechniquePath -Raw | ConvertFrom-Json).techniques.PSObject.Properties) {
    $techniqueName[$t.Name] = $t.Value
}

$rulesJson = ConvertTo-Json -InputObject @($detections | ForEach-Object { ConvertTo-SentinelRule -Detection $_ }) -Depth 20
$coverage = Format-CoverageReport -Detection $detections -TechniqueName $techniqueName

if ($Check) {
    $outdated = @()
    $currentRules = if (Test-Path -LiteralPath $OutputPath) { Get-Content -LiteralPath $OutputPath -Raw } else { '' }
    if (($currentRules -replace "`r`n", "`n").TrimEnd() -ne ($rulesJson -replace "`r`n", "`n").TrimEnd()) { $outdated += $OutputPath }
    $currentCoverage = if (Test-Path -LiteralPath $CoveragePath) { Get-Content -LiteralPath $CoveragePath -Raw } else { '' }
    if (($currentCoverage -replace "`r`n", "`n").TrimEnd() -ne ($coverage -replace "`r`n", "`n").TrimEnd()) { $outdated += $CoveragePath }
    if ($outdated.Count -gt 0) {
        throw "Generated files are out of date: $($outdated -join ', '). Run scripts/Build-SentinelRules.ps1 and commit the result."
    }
    Write-Information "Generated files are up to date ($($detections.Count) detections)." -InformationAction Continue
    return
}

Write-Utf8File -Path $OutputPath -Content $rulesJson
Write-Utf8File -Path $CoveragePath -Content $coverage
Write-Information "Built $($detections.Count) rules: $OutputPath, $CoveragePath" -InformationAction Continue
