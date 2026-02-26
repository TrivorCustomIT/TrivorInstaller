function Show-Banner {

    Clear-Host
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

    $ascii = @"
     _______ _____  _______      ______  _____  
    |__   __|  __ \|_   _\ \    / / __ \|  __ \ 
       | |  | |__) | | |  \ \  / / |  | | |__) |
       | |  |  _  /  | |   \ \/ /| |  | |  _  / 
       | |  | | \ \ _| |_   \  / | |__| | | \ \ 
       |_|  |_|  \_\_____|   \/   \____/|_|  \_\
                                             
"@

    Write-Host ""
    Write-Host "===================================================="
    Write-Host "              TRIVOR INSTALLER V3.21               "
    Write-Host "===================================================="
    Write-Host ""
    Write-Host $ascii -ForegroundColor Cyan
    Write-Host ""
    Write-Host "===================================================="
    Write-Host "     Developed by Fernando Oliveira                 "
    Write-Host "     GitHub: github.com/nandinhooliveira            "
    Write-Host "===================================================="
    Write-Host ""
}
