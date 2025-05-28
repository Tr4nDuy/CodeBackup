# Script cài đặt Logstash
Write-Host "Đang cài đặt Logstash..." -ForegroundColor Green

# Tạo thư mục ELK
$elkDir = "C:\ELK"
New-Item -ItemType Directory -Force -Path "$elkDir\logstash"

# Download Logstash
$lsVersion = "8.11.0"
$lsUrl = "https://artifacts.elastic.co/downloads/logstash/logstash-$lsVersion-windows-x86_64.zip"
$lsZip = "$elkDir\logstash-$lsVersion.zip"

Write-Host "Downloading Logstash $lsVersion..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $lsUrl -OutFile $lsZip

# Giải nén
Write-Host "Extracting Logstash..." -ForegroundColor Yellow
Expand-Archive -Path $lsZip -DestinationPath "$elkDir\logstash" -Force

# Tạo thư mục pipeline
$pipelineDir = "$elkDir\logstash\logstash-$lsVersion\config\pipelines.d"
New-Item -ItemType Directory -Force -Path $pipelineDir

# Tạo thư mục configuration tùy chỉnh
$configDir = "$elkDir\logstash\logstash-$lsVersion\config"

# Cấu hình JVM cho bộ nhớ thấp
$jvmOptionsFile = "$elkDir\logstash\logstash-$lsVersion\config\jvm.options"
if (Test-Path $jvmOptionsFile) {
    # Sao lưu file cấu hình
    Copy-Item -Path $jvmOptionsFile -Destination "$jvmOptionsFile.bak"
    
    # Thay đổi cấu hình bộ nhớ
    (Get-Content $jvmOptionsFile) -replace "-Xms1g", "-Xms256m" | Set-Content $jvmOptionsFile
    (Get-Content $jvmOptionsFile) -replace "-Xmx1g", "-Xmx512m" | Set-Content $jvmOptionsFile
}

# Tạo cấu hình pipeline cho NIDS
$pipelineContent = @"
input {
  udp {
    port => 5514
    type => "syslog"
    codec => "json"
  }
}

filter {
  if [event_type] == "network_detection" {
    date {
      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss.SSSSSS" ]
      target => "@timestamp"
    }
    
    mutate {
      add_field => {
        "[@metadata][index]" => "nids-logs-%{+YYYY.MM.dd}"
      }
    }
    
    # Risk level classification
    if [risk_level] and [risk_level] > 7 {
      mutate { add_tag => ["high_risk"] }
    } else if [risk_level] and [risk_level] > 4 {
      mutate { add_tag => ["medium_risk"] }
    } else {
      mutate { add_tag => ["low_risk"] }
    }
    
    # Zone-based tagging
    if [network_zone] {
      mutate { add_tag => ["%{[network_zone]}"] }
    }
    
    # Attack detection
    if [is_attack] == true {
      mutate { add_tag => ["attack_detected"] }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][index]}"
  }
  
  # Debug output to console - remove in production
  stdout { codec => rubydebug }
  
  # Write to file for backup
  file {
    path => "C:/ELK/logs/logstash_output_%{+YYYY_MM_dd}.log"
    codec => json_lines
  }
}
"@

# Lưu cấu hình pipeline
$pipelineFile = "$pipelineDir\nids-pipeline.conf"
Set-Content -Path $pipelineFile -Value $pipelineContent

Write-Host "Logstash đã được cài đặt tại: $elkDir\logstash\logstash-$lsVersion" -ForegroundColor Green
Write-Host "Pipeline được cấu hình tại: $pipelineFile" -ForegroundColor Green
Write-Host "Để chạy Logstash, mở PowerShell với quyền Admin và chạy:" -ForegroundColor Cyan
Write-Host "cd $elkDir\logstash\logstash-$lsVersion\bin" -ForegroundColor White
Write-Host ".\logstash.bat -f $pipelineFile" -ForegroundColor White
