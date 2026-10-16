#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }, powershell-yaml

# Validates every detection: metadata, Sentinel constraints, ATT&CK references,
# and the KQL query against the Log Analytics table schemas.

BeforeDiscovery {
    $root = Join-Path -Path $PSScriptRoot -ChildPath '../detections'
    $detections = foreach ($file in (Get-ChildItem -Path $root -Recurse -Filter '*.yaml' | Sort-Object -Property Name)) {
        @{ Name = $file.BaseName; Path = $file.FullName; Folder = $file.Directory.Name }
    }
}

BeforeAll {
    Import-Module powershell-yaml
    . (Join-Path -Path $PSScriptRoot -ChildPath '../scripts/Test-DetectionQuery.ps1')
    Initialize-KustoLanguage -AssemblyPath (& (Join-Path -Path $PSScriptRoot -ChildPath '../scripts/Get-KustoLanguage.ps1'))

    $schema = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath '../schemas/log-analytics.json') -Raw | ConvertFrom-Json
    $globalState = ConvertTo-KustoGlobalState -Schema $schema
    $tables = @($schema.tables.PSObject.Properties.Name)
    $techniqueNames = (Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath '../schemas/attack-techniques.json') -Raw | ConvertFrom-Json).techniques

    $requiredKeys = 'id', 'detectionId', 'name', 'description', 'severity', 'requiredDataConnectors', 'queryFrequency', 'queryPeriod',
    'triggerOperator', 'triggerThreshold', 'tactics', 'relevantTechniques', 'query', 'entityMappings', 'falsePositives', 'triage',
    'preventiveControls', 'references', 'version', 'kind'

    # Tactic names accepted by the Microsoft Sentinel alert rule API.
    $sentinelTactics = 'Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution', 'Persistence', 'PrivilegeEscalation',
    'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection', 'Exfiltration', 'CommandAndControl', 'Impact'

    # Entity identifiers used in this repository, per entity type.
    $entityIdentifiers = @{
        Account = 'Name', 'FullName', 'NTDomain', 'DnsDomain', 'UPNSuffix', 'Sid', 'AadTenantId', 'AadUserId', 'ObjectGuid'
        Host    = 'HostName', 'FullName', 'DnsDomain', 'NTDomain', 'NetBiosName', 'AzureID', 'OMSAgentID'
        IP      = 'Address'
    }
    $connectorTables = @{
        AzureActiveDirectory  = 'SigninLogs', 'AuditLogs'
        SecurityEvents        = 'SecurityEvent'
        WindowsSecurityEvents = 'SecurityEvent'
    }

    function ConvertTo-Minutes {
        param([string]$Duration)
        $value = [int]($Duration -replace '[mhd]$', '')
        switch -Regex ($Duration) { 'm$' { $value } 'h$' { $value * 60 } 'd$' { $value * 1440 } }
    }
}

Describe '<Name>' -ForEach $detections {
    BeforeAll {
        $raw = Get-Content -LiteralPath $Path -Raw
        $d = $raw | ConvertFrom-Yaml -Ordered
        $analysis = Test-KqlQuery -Query $d.query -GlobalState $globalState
    }

    Context 'Metadata' {
        It 'has all required fields and no unknown fields' {
            foreach ($key in $requiredKeys) { $d.Contains($key) | Should -BeTrue -Because "'$key' is required" }
            foreach ($key in $d.Keys) { $key | Should -BeIn $requiredKeys }
        }

        It 'has a GUID as id' {
            [guid]::TryParse([string]$d.id, [ref][guid]::Empty) | Should -BeTrue
        }

        It 'is named after its detection ID and stored in the folder of its platform' {
            $d.detectionId | Should -Match '^ITD-[EA]\d{3}$'
            $Name | Should -BeLike "$($d.detectionId)-*"
            $expectedFolder = if ($d.detectionId -like 'ITD-E*') { 'entra-id' } else { 'active-directory' }
            $Folder | Should -Be $expectedFolder
        }

        It 'has a short name and a description' {
            # The build prefixes the detection ID, so keep the name itself short.
            ([string]$d.name).Length | Should -BeLessOrEqual 90
            ([string]$d.description).Trim().Length | Should -BeGreaterThan 50
        }

        It 'uses a valid severity, kind and version' {
            $d.severity | Should -BeIn 'Informational', 'Low', 'Medium', 'High'
            $d.kind | Should -Be 'Scheduled'
            $d.version | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'documents false positives, triage steps, preventive controls and references' {
            @($d.falsePositives).Count | Should -BeGreaterThan 0
            @($d.triage).Count | Should -BeGreaterThan 1
            @($d.preventiveControls).Count | Should -BeGreaterThan 0
            foreach ($reference in $d.references) { $reference | Should -Match '^https://' }
        }
    }

    Context 'Sentinel constraints' {
        It 'uses durations within the scheduled rule limits' {
            $frequency = ConvertTo-Minutes -Duration $d.queryFrequency
            $period = ConvertTo-Minutes -Duration $d.queryPeriod
            $d.queryFrequency | Should -Match '^\d+[mhd]$'
            $d.queryPeriod | Should -Match '^\d+[mhd]$'
            $frequency | Should -BeGreaterOrEqual 5
            $frequency | Should -BeLessOrEqual (14 * 1440)
            $period | Should -BeGreaterOrEqual $frequency
            $period | Should -BeLessOrEqual (14 * 1440)
        }

        It 'uses a valid trigger' {
            $d.triggerOperator | Should -BeIn 'gt', 'lt', 'eq', 'ne'
            [int]$d.triggerThreshold | Should -BeGreaterOrEqual 0
        }

        It 'uses Sentinel tactic names' {
            @($d.tactics).Count | Should -BeGreaterThan 0
            foreach ($tactic in $d.tactics) { $tactic | Should -BeIn $sentinelTactics }
            @($d.tactics | Select-Object -Unique).Count | Should -Be @($d.tactics).Count
        }

        It 'maps entities to columns of the query result' {
            @($d.entityMappings).Count | Should -BeGreaterThan 0
            @($d.entityMappings).Count | Should -BeLessOrEqual 10
            foreach ($mapping in $d.entityMappings) {
                $entityIdentifiers.Keys | Should -Contain $mapping.entityType
                @($mapping.fieldMappings).Count | Should -BeLessOrEqual 3
                foreach ($field in $mapping.fieldMappings) {
                    $field.identifier | Should -BeIn $entityIdentifiers[$mapping.entityType]
                    $field.columnName | Should -BeIn $analysis.Columns -Because "entity column '$($field.columnName)' must be in the query output"
                }
            }
        }

        It 'declares exactly the tables the query reads' {
            $declared = @($d.requiredDataConnectors | ForEach-Object { $_.dataTypes } | Sort-Object -Unique)
            $used = @($tables | Where-Object { $d.query -match "\b$_\b" } | Sort-Object -Unique)
            $declared | Should -Be $used
            foreach ($connector in $d.requiredDataConnectors) {
                $connectorTables.Keys | Should -Contain $connector.connectorId
                foreach ($table in $connector.dataTypes) { $table | Should -BeIn $connectorTables[$connector.connectorId] }
            }
        }
    }

    Context 'MITRE ATT&CK' {
        It 'references techniques in the ATT&CK ID format that are in the technique catalog' {
            @($d.relevantTechniques).Count | Should -BeGreaterThan 0
            foreach ($technique in $d.relevantTechniques) {
                $technique | Should -Match '^T\d{4}(\.\d{3})?$'
                $techniqueNames.PSObject.Properties.Name | Should -Contain $technique
            }
        }

        It 'links the ATT&CK page of every technique' {
            foreach ($technique in $d.relevantTechniques) {
                $d.references | Should -Contain "https://attack.mitre.org/techniques/$($technique.Replace('.', '/'))/"
            }
        }
    }

    Context 'Query' {
        It 'parses and analyses without errors against the table schemas' {
            $analysis.Errors | Should -BeNullOrEmpty
        }

        It 'returns a table result' {
            $analysis.Columns.Count | Should -BeGreaterThan 0
        }

        It 'contains no tenant-specific identifiers' {
            # Only schema GUIDs of AD extended rights are allowed in queries.
            $allowed = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'
            foreach ($id in ([regex]::Matches($d.query, '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}') | ForEach-Object { $_.Value.ToLowerInvariant() })) {
                $id | Should -BeIn $allowed
            }
            $d.query | Should -Not -Match 'S-1-5-21-\d+-\d+-\d+'
        }
    }
}

Describe 'Detection set' {
    BeforeAll {
        $all = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath '../detections') -Recurse -Filter '*.yaml' |
                ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Yaml })
        $readme = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath '../README.md') -Raw
    }

    It 'has unique ids, detection IDs and names' {
        foreach ($key in 'id', 'detectionId', 'name') {
            $values = @($all | ForEach-Object { $_[$key] })
            @($values | Sort-Object -Unique).Count | Should -Be $values.Count -Because "$key must be unique"
        }
    }

    It 'lists every detection in the README' {
        foreach ($d in $all) { $readme | Should -Match ([regex]::Escape($d.detectionId)) }
    }

    It 'catalogs only techniques that a detection uses' {
        $used = @($all | ForEach-Object { $_.relevantTechniques } | Sort-Object -Unique)
        @($techniqueNames.PSObject.Properties.Name | Sort-Object) | Should -Be $used
    }
}
