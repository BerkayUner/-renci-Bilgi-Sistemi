# Ogrenci_Bilgi_Sistem

# ==========================================
# CONFIG
# ==========================================
$RootPath = "D:\YedekPcFiles"
$ExportCsv = "D:\Permission_Audit_YedekPcFiles.csv"

# ==========================================
# FUNCTION: Group Members Getir (AD + Local)
# ==========================================
function Get-GroupMembersSafe {
    param (
        [string]$Identity
    )

    $membersList = @()

    try {
        # AD Group ise
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $adGroup = Get-ADGroup -Identity $Identity -ErrorAction SilentlyContinue
            if ($adGroup) {
                $members = Get-ADGroupMember -Identity $Identity -Recursive -ErrorAction SilentlyContinue
                $membersList = $members | Select-Object -ExpandProperty Name
                return ($membersList -join "; ")
            }
        }
    } catch {}

    try {
        # Local Group ise
        $localMembers = Get-LocalGroupMember -Group $Identity -ErrorAction SilentlyContinue
        if ($localMembers) {
            $membersList = $localMembers | Select-Object -ExpandProperty Name
            return ($membersList -join "; ")
        }
    } catch {}

    return "N/A"
}

# ==========================================
# SHARE LISTESI (Server Üzerindeki Tüm Shareler)
# ==========================================
$shares = Get-SmbShare | Where-Object { $_.Path -like "$RootPath*" }

# ==========================================
# TÜM KLASÖRLERİ ÇEK (Recursive)
# ==========================================
$folders = Get-ChildItem -Path $RootPath -Directory -Recurse -ErrorAction SilentlyContinue

# Root klasörü de dahil edelim
$folders = @((Get-Item $RootPath)) + $folders

$result = @()

foreach ($folder in $folders) {

    Write-Host "Processing: $($folder.FullName)" -ForegroundColor Cyan

    # NTFS ACL
    try {
        $acl = Get-Acl -Path $folder.FullName
    } catch {
        Write-Warning "ACL okunamadı: $($folder.FullName)"
        continue
    }

    # Bu klasöre bağlı share var mı?
    $relatedShares = $shares | Where-Object { $folder.FullName -like "$($_.Path)*" }

    if (-not $relatedShares) {
        $relatedShares = @([PSCustomObject]@{
            Name = "No Share"
            Path = $folder.FullName
        })
    }

    foreach ($share in $relatedShares) {

        # Share Permissions
        try {
            $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        } catch {
            $shareAccess = @()
        }

        if (-not $shareAccess) {
            $shareAccess = @([PSCustomObject]@{
                AccountName = "N/A"
                AccessControlType = "N/A"
                AccessRight = "N/A"
            })
        }

        foreach ($ace in $acl.Access) {

            $identity = $ace.IdentityReference.Value

            # Group Members çöz
            $groupMembers = Get-GroupMembersSafe -Identity $identity

            foreach ($sa in $shareAccess) {
                $result += [PSCustomObject]@{
                    FolderPath        = $folder.FullName
                    ShareName         = $share.Name
                    SharePath         = $share.Path
                    ShareAccount      = $sa.AccountName
                    ShareAccessRight  = $sa.AccessRight
                    NTFS_Identity     = $identity
                    NTFS_Rights       = $ace.FileSystemRights
                    NTFS_AccessType   = $ace.AccessControlType
                    IsInherited       = $ace.IsInherited
                    GroupMembers      = $groupMembers
                }
            }
        }
    }
}

# ==========================================
# EXPORT
# ==========================================
$result | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8

Write-Host "--------------------------------------" -ForegroundColor Green
Write-Host "TAMAMLANDI!" -ForegroundColor Green
Write-Host "CSV Rapor: $ExportCsv" -ForegroundColor Yellow
Write-Host "Toplam Kayıt: $($result.Count)" -ForegroundColor Yellow
