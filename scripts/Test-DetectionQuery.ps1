<#
.SYNOPSIS
    Validates the KQL query of every detection against the Log Analytics table
    schemas: syntax, unknown tables, columns and functions, and type errors.

.DESCRIPTION
    Uses the Kusto.Language parser and semantic analyser with the schemas in
    schemas/log-analytics.json. A query that references a column that does not
    exist, calls a function with wrong arguments or compares incompatible types
    fails here instead of in the Sentinel portal.

    Prints one line per detection and exits with code 1 if any query has errors.

.PARAMETER Path
    Folder with the detection YAML files. Default: detections/

.PARAMETER SchemaPath
    Table and function schemas. Default: schemas/log-analytics.json

.EXAMPLE
    .\scripts\Test-DetectionQuery.ps1

    Validates all detection queries.

.NOTES
    Requires the powershell-yaml module. Kusto.Language is downloaded on first
    use by Get-KustoLanguage.ps1 (pinned version, checksum verified).

    Author : Ramón Lotz
    Version: 1.0.0
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$Path = (Join-Path -Path $PSScriptRoot -ChildPath '../detections'),

    [string]$SchemaPath = (Join-Path -Path $PSScriptRoot -ChildPath '../schemas/log-analytics.json')
)

#region Functions

function Initialize-KustoLanguage {
    <#
    .SYNOPSIS
        Loads the Kusto.Language assembly once per session.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$AssemblyPath)

    if (-not ('Kusto.Language.KustoCode' -as [type])) {
        Add-Type -Path $AssemblyPath
    }
}

function ConvertTo-KustoType {
    <#
    .SYNOPSIS
        Maps a Log Analytics column type name to a Kusto.Language scalar type.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    switch ($Name.ToLowerInvariant()) {
        'string' { [Kusto.Language.Symbols.ScalarTypes]::String }
        'datetime' { [Kusto.Language.Symbols.ScalarTypes]::DateTime }
        'dynamic' { [Kusto.Language.Symbols.ScalarTypes]::Dynamic }
        'int' { [Kusto.Language.Symbols.ScalarTypes]::Int }
        'long' { [Kusto.Language.Symbols.ScalarTypes]::Long }
        'bool' { [Kusto.Language.Symbols.ScalarTypes]::Bool }
        'real' { [Kusto.Language.Symbols.ScalarTypes]::Real }
        'guid' { [Kusto.Language.Symbols.ScalarTypes]::Guid }
        'timespan' { [Kusto.Language.Symbols.ScalarTypes]::TimeSpan }
        default { throw "Unknown column type '$Name'." }
    }
}

function ConvertTo-KustoGlobalState {
    <#
    .SYNOPSIS
        Builds a Kusto.Language global state with the tables and functions of the schema file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Schema)

    $symbols = [System.Collections.Generic.List[Kusto.Language.Symbols.Symbol]]::new()

    foreach ($table in $Schema.tables.PSObject.Properties) {
        $columns = [Kusto.Language.Symbols.ColumnSymbol[]]@(foreach ($column in $table.Value.PSObject.Properties) {
                [Kusto.Language.Symbols.ColumnSymbol]::new($column.Name, (ConvertTo-KustoType -Name $column.Value))
            })
        $symbols.Add([Kusto.Language.Symbols.TableSymbol]::new($table.Name, $columns))
    }

    foreach ($function in $Schema.functions.PSObject.Properties) {
        $columns = [Kusto.Language.Symbols.ColumnSymbol[]]@(foreach ($column in $function.Value.columns.PSObject.Properties) {
                [Kusto.Language.Symbols.ColumnSymbol]::new($column.Name, (ConvertTo-KustoType -Name $column.Value))
            })
        $parameters = [Kusto.Language.Symbols.Parameter[]]@(foreach ($p in $function.Value.parameters.PSObject.Properties) {
                [Kusto.Language.Symbols.Parameter]::new($p.Name, (ConvertTo-KustoType -Name $p.Value))
            })
        $result = [Kusto.Language.Symbols.TableSymbol]::new($columns)
        $symbols.Add([Kusto.Language.Symbols.FunctionSymbol]::new($function.Name, [Kusto.Language.Symbols.TypeSymbol]$result, $parameters))
    }

    $database = [Kusto.Language.Symbols.DatabaseSymbol]::new('sentinel', $symbols.ToArray())
    [Kusto.Language.GlobalState]::Default.WithDatabase($database)
}

function Test-KqlQuery {
    <#
    .SYNOPSIS
        Parses and analyses a query and returns its errors and output columns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][object]$GlobalState
    )

    $code = [Kusto.Language.KustoCode]::ParseAndAnalyze($Query, $GlobalState)
    $errors = @(foreach ($d in $code.GetDiagnostics()) {
            if ($d.Severity -ne 'Error') { continue }
            $line = ($Query.Substring(0, [Math]::Min($d.Start, $Query.Length)) -split "`n").Count
            "line ${line}: $($d.Message)"
        })
    $columns = @()
    if ($code.ResultType -is [Kusto.Language.Symbols.TableSymbol]) {
        $columns = @($code.ResultType.Columns | ForEach-Object { $_.Name })
    }

    [PSCustomObject]@{
        Errors  = $errors
        Columns = $columns
    }
}

#endregion Functions

# When the script is dot-sourced (for example by the Pester tests), only load the functions.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'

Import-Module powershell-yaml
Initialize-KustoLanguage -AssemblyPath (& (Join-Path -Path $PSScriptRoot -ChildPath 'Get-KustoLanguage.ps1'))
$globalState = ConvertTo-KustoGlobalState -Schema (Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json)

$results = foreach ($file in (Get-ChildItem -LiteralPath $Path -Recurse -Filter '*.yaml' | Sort-Object -Property Name)) {
    $detection = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Yaml
    $result = Test-KqlQuery -Query $detection.query -GlobalState $globalState
    [PSCustomObject]@{
        Detection = $detection.detectionId
        Result    = if ($result.Errors.Count -eq 0) { 'OK' } else { 'Error' }
        Detail    = $result.Errors -join '; '
    }
}

$results | Format-Table -AutoSize -Wrap
$failed = @($results | Where-Object Result -EQ 'Error').Count
if ($failed -gt 0) {
    Write-Error -Message "$failed detection queries have errors." -ErrorAction Continue
    exit 1
}
Write-Information "All $(@($results).Count) detection queries are valid." -InformationAction Continue
