// Deploys the detections of this repository as Microsoft Sentinel scheduled analytics rules.
// The rules are generated from the YAML files by scripts/Build-SentinelRules.ps1.
targetScope = 'resourceGroup'

metadata name = 'Identity threat detections for Microsoft Sentinel'
metadata description = 'Scheduled analytics rules for identity attacks on Microsoft Entra ID and Active Directory.'

@description('Name of the Log Analytics workspace that has Microsoft Sentinel enabled.')
param workspaceName string

@description('Creates the rules enabled. Use false to review and tune them in the portal before they raise incidents.')
param enableRules bool = true

var rules = loadJsonContent('../dist/sentinel-rules.json')

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource analyticsRules 'Microsoft.SecurityInsights/alertRules@2025-06-01' = [
  for rule in rules: {
    scope: workspace
    name: rule.name
    kind: 'Scheduled'
    properties: {
      ...rule.properties
      enabled: enableRules
    }
  }
]

@description('Number of analytics rules deployed.')
output ruleCount int = length(rules)
