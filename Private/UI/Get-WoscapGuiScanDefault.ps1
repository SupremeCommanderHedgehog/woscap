function Get-WoscapGuiScanDefault {
    <#
        Reads Invoke-WoscapScan's own parameter defaults from its AST so the GUI never
        holds a hard-coded copy that could drift. Returns @{ ThrottleLimit = <int> }.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $ast = (Get-Command Invoke-WoscapScan).ScriptBlock.Ast
    $throttle = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.ParameterAst] -and
            $node.Name.VariablePath.UserPath -eq 'ThrottleLimit'
    }, $true) | Select-Object -First 1
    @{ ThrottleLimit = [int]$throttle.DefaultValue.SafeGetValue() }
}
