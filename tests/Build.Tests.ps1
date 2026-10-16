#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }, powershell-yaml

BeforeDiscovery {
    $scripts = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath '../scripts') -Filter '*.ps1'
}

Describe '<_.Name> (static checks)' -ForEach $scripts {
    BeforeAll {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
        $help = $ast.GetHelpContent()
    }

    It 'parses without errors' {
        $parseErrors | Should -BeNullOrEmpty
    }

    It 'has comment-based help with synopsis, description and examples' {
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Description | Should -Not -BeNullOrEmpty
        $help.Examples.Count | Should -BeGreaterThan 0
    }

    It 'documents every parameter' {
        $documented = $help.Parameters.Keys | ForEach-Object { $_.ToUpperInvariant() }
        foreach ($parameter in $ast.ParamBlock.Parameters) {
            $parameter.Name.VariablePath.UserPath.ToUpperInvariant() | Should -BeIn $documented
        }
    }
}

Describe 'Build-SentinelRules.ps1' {
    BeforeAll {
        Import-Module powershell-yaml
        . (Join-Path -Path $PSScriptRoot -ChildPath '../scripts/Build-SentinelRules.ps1')
        $root = Join-Path -Path $PSScriptRoot -ChildPath '..'
        $detection = Get-Content -Path (Join-Path -Path $root -ChildPath 'detections/entra-id/ITD-E002-CredentialAddedToApplication.yaml') -Raw | ConvertFrom-Yaml -Ordered
        $rule = ConvertTo-SentinelRule -Detection $detection
    }

    It 'converts durations to ISO 8601' {
        ConvertTo-IsoDuration -Duration '5m' | Should -Be 'PT5M'
        ConvertTo-IsoDuration -Duration '1h' | Should -Be 'PT1H'
        ConvertTo-IsoDuration -Duration '14d' | Should -Be 'P14D'
        { ConvertTo-IsoDuration -Duration '1w' } | Should -Throw '*Invalid duration*'
    }

    It 'reduces sub-techniques to unique parent techniques' {
        Get-ParentTechnique -Technique 'T1098.001', 'T1098.003', 'T1528' | Should -Be @('T1098', 'T1528')
    }

    It 'uses the detection GUID as rule name and prefixes the display name with the detection ID' {
        $rule.name | Should -Be $detection.id
        $rule.properties.displayName | Should -Be "ITD-E002 $($detection.name)"
    }

    It 'maps the trigger and the schedule to the API format' {
        $rule.properties.triggerOperator | Should -Be 'GreaterThan'
        $rule.properties.queryFrequency | Should -Be 'PT1H'
        $rule.properties.suppressionEnabled | Should -BeFalse
    }

    It 'keeps single techniques and tactics as arrays in the JSON output' {
        $json = $rule | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $json.properties.techniques.GetType().IsArray | Should -BeTrue
        $json.properties.techniques | Should -Be @('T1098')
    }

    It 'adds sub-techniques, triage and preventive controls to the description' {
        $rule.properties.description | Should -Match 'MITRE ATT&CK: T1098\.001'
        $rule.properties.description | Should -Match 'Triage:'
        $rule.properties.description | Should -Match 'Preventive controls:'
        $rule.properties.description | Should -Match 'Source: identity-threat-detections ITD-E002 v1\.0\.0'
    }

    It 'has committed dist/sentinel-rules.json and docs/coverage.md that match the detection files' {
        { & (Join-Path -Path $root -ChildPath 'scripts/Build-SentinelRules.ps1') -Check } | Should -Not -Throw
    }
}
