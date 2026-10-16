@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # The scripts are run interactively by operators; coloured console output is intended.
        'PSAvoidUsingWriteHost'
    )
}
