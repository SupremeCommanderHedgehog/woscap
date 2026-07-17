BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-readarc-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null

    # good.zip: one *_Manual-xccdf.xml entry
    $good = Join-Path $script:Tmp 'goodsrc'; New-Item -ItemType Directory -Path $good | Out-Null
    Set-Content -Path (Join-Path $good 'U_Test_Manual-xccdf.xml') -Value '<Benchmark>hi</Benchmark>'
    $script:GoodZip = Join-Path $script:Tmp 'good.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($good, $script:GoodZip)

    # none.zip: no manual xccdf entry
    $none = Join-Path $script:Tmp 'nonesrc'; New-Item -ItemType Directory -Path $none | Out-Null
    Set-Content -Path (Join-Path $none 'readme.txt') -Value 'nothing here'
    $script:NoneZip = Join-Path $script:Tmp 'none.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($none, $script:NoneZip)

    # multi.zip: two manual xccdf entries
    $multi = Join-Path $script:Tmp 'multisrc'; New-Item -ItemType Directory -Path $multi | Out-Null
    Set-Content -Path (Join-Path $multi 'A_Manual-xccdf.xml') -Value '<Benchmark/>'
    Set-Content -Path (Join-Path $multi 'B_Manual-xccdf.xml') -Value '<Benchmark/>'
    $script:MultiZip = Join-Path $script:Tmp 'multi.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($multi, $script:MultiZip)
}
AfterAll {
    Remove-Module woscap -Force -ErrorAction SilentlyContinue
    Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Read-WoscapStigArchive' {
    It 'returns the manual XCCDF file name and text' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            $r = Read-WoscapStigArchive -ZipPath $Zip
            $r.FileName | Should -Be 'U_Test_Manual-xccdf.xml'
            $r.Xml      | Should -Match 'Benchmark'
        }
    }
    It 'throws when the archive has no *_Manual-xccdf.xml entry' {
        InModuleScope woscap -Parameters @{ Zip = $script:NoneZip } {
            { Read-WoscapStigArchive -ZipPath $Zip } | Should -Throw -ExpectedMessage '*no *Manual-xccdf.xml*'
        }
    }
    It 'throws when the archive has multiple manual XCCDF entries' {
        InModuleScope woscap -Parameters @{ Zip = $script:MultiZip } {
            { Read-WoscapStigArchive -ZipPath $Zip } | Should -Throw -ExpectedMessage '*multiple*'
        }
    }
}
