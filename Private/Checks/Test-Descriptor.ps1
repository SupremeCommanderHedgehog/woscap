function Test-Descriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Descriptor)

    $expected = if ($Descriptor.ContainsKey('Expected')) { $Descriptor.Expected } else { $null }
    try {
        $observed = $null
        switch ($Descriptor.Type) {
            'Registry' {
                $observed = Get-RegValue -Path $Descriptor.Path -Name $Descriptor.Name
            }
            'SecEdit' {
                $section = if ($Descriptor.ContainsKey('Section')) { $Descriptor.Section } else { 'System Access' }
                $observed = Get-SecEditSetting -Name $Descriptor.Name -Section $section
            }
            'UserRight' {
                $observedSids = @(Get-UserRight -Privilege $Descriptor.Privilege | ForEach-Object { $_ -replace '^\*', '' })
                $expectedSids = @()
                foreach ($principal in @($expected)) {
                    $sid = Resolve-PrincipalSid -Name $principal
                    if ([string]::IsNullOrEmpty($sid)) {
                        return [pscustomobject]@{ Result = 'Error'; Observed = ($observedSids -join ','); Expected = "unresolved principal: $principal" }
                    }
                    $expectedSids += $sid
                }
                $pass = Compare-WoscapValue -Operator $Descriptor.Operator -Observed $observedSids -Expected $expectedSids
                return [pscustomobject]@{
                    Result   = if ($pass) { 'Pass' } else { 'Fail' }
                    Observed = ($observedSids -join ',')
                    Expected = ($expectedSids -join ',')
                }
            }
            'AuditPolicy' {
                $observed = Get-AuditPolicy -Subcategory $Descriptor.Subcategory
            }
            'Service' {
                $property = if ($Descriptor.ContainsKey('Property')) { $Descriptor.Property } else { 'StartMode' }
                $observed = (Get-ServiceState -Name $Descriptor.Name).$property
            }
            'ScriptBlock' {
                $sbResult = & $Descriptor.Script
                $sbStatus = [string]$sbResult
                if ($sbStatus -notin @('Pass','Fail','NA','NotReviewed','Error')) { $sbStatus = 'Error' }
                return [pscustomobject]@{ Result = $sbStatus; Observed = $sbResult; Expected = $null }
            }
            default {
                return [pscustomobject]@{ Result = 'Error'; Observed = $null; Expected = $expected }
            }
        }
        $pass = Compare-WoscapValue -Operator $Descriptor.Operator -Observed $observed -Expected $expected
        [pscustomobject]@{
            Result   = if ($pass) { 'Pass' } else { 'Fail' }
            Observed = $observed
            Expected = $expected
        }
    } catch {
        [pscustomobject]@{ Result = 'Error'; Observed = "$_"; Expected = $expected }
    }
}
