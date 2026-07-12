function Export-WoscapCklb {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Result,
        [Parameter(Mandatory)] [string] $Path
    )
    if (@($Result).Count -eq 0) { throw 'Export-WoscapCklb: no results to export.' }
    $first    = $Result[0]
    $stigUuid = (New-Guid).Guid

    $rules = foreach ($r in $Result) {
        $comments = if ($r.Comments) { $r.Comments } else { '' }
        [ordered]@{
            group_id        = [string]$r.GroupId
            rule_id         = [string]$r.RuleId
            rule_version    = [string]$r.StigId
            group_title     = [string]$r.GroupTitle   # SRG (XCCDF Group title); empty when the group has none
            rule_title      = [string]$r.Title
            severity        = [string]$r.Severity
            weight          = '10.0'
            classification  = 'Unclassified'
            discussion      = [string]$r.Discussion
            check_content   = [string]$r.CheckText
            fix_text        = [string]$r.FixText
            false_positives = ''
            false_negatives = ''
            documentable    = 'false'
            ccis            = @($r.Cci)
            legacy_ids      = @()
            status          = ConvertTo-CklbStatus -Status $r.Status
            overrides       = @{}
            comments        = $comments
            finding_details = [string]$r.FindingDetails
            uuid            = (New-Guid).Guid
            stig_uuid       = $stigUuid
        }
    }

    $version = if ($first.BenchmarkVersion) { [string]$first.BenchmarkVersion } else { '1' }
    $cklb = [ordered]@{
        title        = "$($first.Benchmark) - woscap"
        id           = (New-Guid).Guid
        active       = $false
        mode         = 1
        has_path     = $true
        target_data  = [ordered]@{
            target_type     = 'Computing'
            host_name       = [string]$first.Host
            ip_address      = ''
            mac_address     = ''
            fqdn            = ''
            comments        = ''
            role            = 'None'
            is_web_database = $false
            technology_area = ''
            web_db_site     = ''
            web_db_instance = ''
        }
        stigs = @(
            [ordered]@{
                stig_name            = [string]$first.Benchmark
                display_name         = [string]$first.Benchmark
                stig_id              = ([string]$first.Benchmark -replace '\s', '_')
                release_info         = "Version: $version"
                version              = $version
                uuid                 = $stigUuid
                reference_identifier = ''
                size                 = @($Result).Count
                rules                = @($rules)
            }
        )
        cklb_version = '1.0'
    }

    Write-WoscapText -Text (ConvertTo-Json -InputObject $cklb -Depth 12) -Path $Path
}
