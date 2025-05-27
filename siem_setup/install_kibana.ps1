# Script cài đặt Kibana cho SIEM
# Chạy với quyền Administrator

Write-Host "=== Cài đặt Kibana ===" -ForegroundColor Green

# Tạo thư mục làm việc
$workDir = "C:\ELK\kibana"
if (!(Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force
}
Set-Location $workDir

# Download Kibana
$kibanaVersion = "8.12.0"
$kibanaUrl = "https://artifacts.elastic.co/downloads/kibana/kibana-$kibanaVersion-windows-x86_64.zip"
$kibanaZip = "kibana-$kibanaVersion-windows-x86_64.zip"

Write-Host "Downloading Kibana..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $kibanaUrl -OutFile $kibanaZip -UseBasicParsing
    Write-Host "Download completed!" -ForegroundColor Green
} catch {
    Write-Host "Download failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Giải nén
Write-Host "Extracting Kibana..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $kibanaZip -DestinationPath . -Force
    $extractedDir = "kibana-$kibanaVersion"
    if (Test-Path $extractedDir) {
        Rename-Item $extractedDir "kibana"
    }
    Remove-Item $kibanaZip
    Write-Host "Extraction completed!" -ForegroundColor Green
} catch {
    Write-Host "Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Cấu hình Kibana
$configFile = "$workDir\kibana\config\kibana.yml"
$kibanaConfig = @"
# Kibana Configuration for NIDS SIEM

# Server configuration
server.port: 5601
server.host: "localhost"
server.name: "nids-siem-kibana"

# Elasticsearch connection
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.requestTimeout: 90000
elasticsearch.shardTimeout: 30000

# Security (disable for development)
elasticsearch.ssl.verificationMode: none
xpack.security.enabled: false

# Performance settings
elasticsearch.pingTimeout: 1500
elasticsearch.requestHeadersWhitelist: [ authorization ]

# Logging
logging.level: info
logging.quiet: false

# Dashboard settings
kibana.index: ".kibana-nids"
"@

$kibanaConfig | Out-File -FilePath $configFile -Encoding UTF8

Write-Host "Kibana installation completed!" -ForegroundColor Green
Write-Host "Location: $workDir\kibana" -ForegroundColor Cyan
Write-Host "Access URL: http://localhost:5601" -ForegroundColor Yellow
Write-Host "Next: Start services and configure dashboards" -ForegroundColor Yellow
