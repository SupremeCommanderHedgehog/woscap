function Test-WoscapIntegerValue {
    <#
    .SYNOPSIS
        Whether a value is a .NET integer type, as registry kind rules count it.
    .DESCRIPTION
        The single integer test shared by the required-kind resolver, the
        registry applicability gates, the descriptor schema and the remediation
        planner, so one Expected or gate value classifies the same everywhere.
        Integer types are Int16, Int32, Int64, UInt16, UInt32, UInt64, Byte and
        SByte. Strings that look numeric, booleans and floating-point numbers
        are not integers. Range (for example Int32 for a REG_DWORD write) is the
        caller's concern.
    .PARAMETER Value
        The value to classify. $null is not an integer.
    .EXAMPLE
        Test-WoscapIntegerValue 4
        Returns $true.
    .EXAMPLE
        Test-WoscapIntegerValue '4'
        Returns $false: a string is never an integer here.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Position = 0)] [AllowNull()] [object] $Value)
    $Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [sbyte] -or
    $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [uint16] -or $Value -is [byte]
}
