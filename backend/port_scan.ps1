# Port scan script to test attack detection
$ports = 21,22,23,80,443,445,3389,8080,8443,3306,5432,6379,27017
foreach ($port in $ports) {
    $result = Test-NetConnection -ComputerName 192.168.31.37 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Host "Port $port : $result"
    Start-Sleep -Milliseconds 200
}
