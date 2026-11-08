@{
    # Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    # Default rules plus the Windows PowerShell 5.1 compatibility rules.
    # Triage 2026-11-06 (PSScriptAnalyzer 1.25.0): the excluded rules below are style choices, not bugs.
    #   PSAvoidUsingWriteHost            - interactive console tools; colored text for the user, data goes to files.
    #   PSAvoidUsingPositionalParameters - New-DDAction 'Type' 'Target' 'Detail' is positional by design.
    #   PSUseSingularNouns               - renaming tested helpers (Get-DCObservations ...) would churn the API.
    # PSUseShouldProcessForStateChangingFunctions stays ON (it guards DD.Repair.ps1); the two in-memory
    # builders New-DDFinding / New-DDAction suppress it in place.
    # PSUseCompatibleSyntax needs the PowerShell 7 parser; under 5.1 the parser itself is the syntax check.
    IncludeDefaultRules = $true
    ExcludeRules        = @('PSAvoidUsingWriteHost', 'PSAvoidUsingPositionalParameters', 'PSUseSingularNouns')
    Rules               = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework') }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework') }
    }
}
