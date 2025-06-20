# PowerShell script for creating Kibana visualizations for NIDS dashboard

# Kibana settings
$KIBANA_URL = "http://localhost:5601"
$KIBANA_API = "$KIBANA_URL/api/saved_objects"
$INDEX_PATTERN = "nids-logs-*"

# Function to check if Kibana is running
function Test-KibanaConnection {
    try {
        $response = Invoke-RestMethod -Uri "$KIBANA_URL/api/status" -Method 'GET' -TimeoutSec 10
        Write-Host "Kibana is running and accessible." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Error: Cannot connect to Kibana at $KIBANA_URL" -ForegroundColor Red
        Write-Host "Please ensure Kibana is running and accessible." -ForegroundColor Yellow
        return $false
    }
}

# Function to create an index pattern if it doesn't exist
function Create-IndexPattern {
    # First check if index pattern already exists
    try {
        $existingPattern = Invoke-RestMethod -Uri "$KIBANA_API/index-pattern/$INDEX_PATTERN" -Method 'GET' -Headers @{ 'kbn-xsrf' = 'true' }
        Write-Host "Index pattern $INDEX_PATTERN already exists." -ForegroundColor Yellow
        return $existingPattern.id
    } catch {
        # Index pattern doesn't exist, create it
    }

    $payload = @{
        attributes = @{
            title = $INDEX_PATTERN
            timeFieldName = "timestamp"
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Host "Creating index pattern for $INDEX_PATTERN..."
    
    try {
        $response = Invoke-RestMethod -Uri "$KIBANA_API/index-pattern/$INDEX_PATTERN" `
            -Method 'POST' `
            -Headers @{
                'kbn-xsrf' = 'true'
                'Content-Type' = 'application/json'
            } `
            -Body $payload
        
        Write-Host "Index pattern created successfully." -ForegroundColor Green
        return $response.id
    } catch {
        Write-Host "Error creating index pattern: $_" -ForegroundColor Red
        return $null
    }
}

# Function to create a visualization
function Create-Visualization {
    param (
        [string]$name,
        [string]$title,
        [string]$visType,
        [object]$visState
    )
    
    $visStateJson = $visState | ConvertTo-Json -Depth 20
    
    $payload = @{
        attributes = @{
            title = $title
            visState = $visStateJson
            uiStateJSON = "{}"
            description = ""
            version = 1
            kibanaSavedObjectMeta = @{
                searchSourceJSON = "{ `"indexRefName`":`"kibanaSavedObjectMeta.searchSourceJSON.index`" }"
            }
        }
        references = @(
            @{
                name = "kibanaSavedObjectMeta.searchSourceJSON.index"
                type = "index-pattern"
                id = $INDEX_PATTERN
            }
        )
    } | ConvertTo-Json -Depth 20
    
    Write-Host "Creating visualization: $title..."
    
    try {
        $response = Invoke-RestMethod -Uri "$KIBANA_API/visualization/$name" `
            -Method 'POST' `
            -Headers @{
                'kbn-xsrf' = 'true'
                'Content-Type' = 'application/json'
            } `
            -Body $payload
        
        Write-Host "Visualization '$title' created successfully." -ForegroundColor Green
        return $response.id
    } catch {
        Write-Host "Error creating visualization '$title': $_" -ForegroundColor Red
        return $null
    }
}

# Function to create a search
function Create-Search {
    param (
        [string]$name,
        [string]$title,
        [array]$columns,
        [string]$sortField,
        [string]$sortOrder
    )
    
    $columnsJson = $columns | ConvertTo-Json -Compress
    
    $payload = @{
        attributes = @{
            title = $title
            description = ""
            columns = $columns
            sort = @( @{ $sortField = $sortOrder } )
            version = 1
            kibanaSavedObjectMeta = @{
                searchSourceJSON = "{ `"indexRefName`":`"kibanaSavedObjectMeta.searchSourceJSON.index`", `"query`":{`"query`":`"`",`"language`":`"kuery`"},`"filter`":[] }"
            }
        }
        references = @(
            @{
                name = "kibanaSavedObjectMeta.searchSourceJSON.index"
                type = "index-pattern"
                id = $INDEX_PATTERN
            }
        )
    } | ConvertTo-Json -Depth 20
    
    Write-Host "Creating search: $title..."
    
    try {
        $response = Invoke-RestMethod -Uri "$KIBANA_API/search/$name" `
            -Method 'POST' `
            -Headers @{
                'kbn-xsrf' = 'true'
                'Content-Type' = 'application/json'
            } `
            -Body $payload
        
        Write-Host "Search '$title' created successfully." -ForegroundColor Green
        return $response.id
    } catch {
        Write-Host "Error creating search '$title': $_" -ForegroundColor Red
        return $null
    }
}

# Function to import dashboard from JSON file
function Import-Dashboard {
    param (
        [string]$jsonFilePath
    )
    
    if (!(Test-Path $jsonFilePath)) {
        Write-Host "Dashboard JSON file not found: $jsonFilePath" -ForegroundColor Red
        return $null
    }
    
    # Check if it's NDJSON format
    $fileExtension = [System.IO.Path]::GetExtension($jsonFilePath)
    if ($fileExtension -eq ".ndjson") {
        Write-Host "Detected NDJSON format. Using bulk import API..." -ForegroundColor Yellow
        $dashboardContent = Get-Content $jsonFilePath -Raw
        
        try {
            $response = Invoke-RestMethod -Uri "$KIBANA_URL/api/saved_objects/_import" `
                -Method 'POST' `
                -Headers @{
                    'kbn-xsrf' = 'true'
                    'Content-Type' = 'application/x-ndjson'
                } `
                -Body $dashboardContent
            
            Write-Host "Dashboard imported successfully." -ForegroundColor Green
            return $response
        } catch {
            Write-Host "Error importing dashboard: $_" -ForegroundColor Red
            return $null
        }
    } else {
        # Original JSON import logic
        $dashboardJson = Get-Content $jsonFilePath -Raw
        
        Write-Host "Importing dashboard from $jsonFilePath..."
        
        try {
            $response = Invoke-RestMethod -Uri "$KIBANA_API/dashboard/nids-monitoring-dashboard" `
                -Method 'POST' `
                -Headers @{
                    'kbn-xsrf' = 'true'
                    'Content-Type' = 'application/json'
                } `
                -Body $dashboardJson
            
            Write-Host "Dashboard imported successfully." -ForegroundColor Green
            return $response.id
        } catch {
            Write-Host "Error importing dashboard: $_" -ForegroundColor Red
            return $null
        }
    }
}

# Main execution starts here
Write-Host "Starting NIDS Dashboard Creation Process..." -ForegroundColor Cyan

# 1. Check Kibana connection first
if (-not (Test-KibanaConnection)) {
    Write-Host "Aborting script execution due to Kibana connection issues." -ForegroundColor Red
    exit 1
}

# 2. Create Index Pattern first (moved up)
$indexPatternId = Create-IndexPattern
if (-not $indexPatternId) {
    Write-Host "Failed to create index pattern. Aborting." -ForegroundColor Red
    exit 1
}

# Create necessary visualizations

# 1. Events over time
$eventsOverTimeVis = @{
    title = "Attack Events Over Time"
    type = "line"
    aggs = @(
        @{
            id = "1"
            enabled = $true
            type = "count"
            schema = "metric"
            params = @{}
        },
        @{
            id = "2"
            enabled = $true
            type = "date_histogram"
            schema = "segment"
            params = @{
                field = "timestamp"
                useNormalizedEsInterval = $true
                interval = "auto"
                drop_partials = $false
                min_doc_count = 1
                extended_bounds = @{}
            }
        },
        @{
            id = "3"
            enabled = $true
            type = "terms"
            schema = "group"
            params = @{
                field = "event_type"
                orderBy = "1"
                order = "desc"
                size = 5
                otherBucket = $false
                otherBucketLabel = "Other"
                missingBucket = $false
                missingBucketLabel = "Missing"
            }
        }
    )
}
Create-Visualization -name "nids-events-over-time" -title "Attack Events Over Time" -visType "line" -visState $eventsOverTimeVis

# 2. Events by Type
$eventsByTypeVis = @{
    title = "Events by Type"
    type = "pie"
    aggs = @(
        @{
            id = "1"
            enabled = $true
            type = "count"
            schema = "metric"
            params = @{}
        },
        @{
            id = "2"
            enabled = $true
            type = "terms"
            schema = "segment"
            params = @{
                field = "event_type"
                orderBy = "1"
                order = "desc"
                size = 10
                otherBucket = $false
                otherBucketLabel = "Other"
                missingBucket = $false
                missingBucketLabel = "Missing"
            }
        }
    )
}
Create-Visualization -name "nids-events-by-type" -title "Events by Type" -visType "pie" -visState $eventsByTypeVis

# 3. Events by Protocol
$eventsByProtocolVis = @{
    title = "Events by Protocol"
    type = "pie"
    aggs = @(
        @{
            id = "1"
            enabled = $true
            type = "count"
            schema = "metric"
            params = @{}
        },
        @{
            id = "2"
            enabled = $true
            type = "terms"
            schema = "segment"
            params = @{
                field = "protocol"
                orderBy = "1"
                order = "desc"
                size = 10
                otherBucket = $false
                otherBucketLabel = "Other"
                missingBucket = $false
                missingBucketLabel = "Missing"
            }
        }
    )
}
Create-Visualization -name "nids-events-by-protocol" -title "Events by Protocol" -visType "pie" -visState $eventsByProtocolVis

# 4. Source IPs
$sourceIPsVis = @{
    title = "Source IP Addresses"
    type = "horizontal_bar"
    aggs = @(
        @{
            id = "1"
            enabled = $true
            type = "count"
            schema = "metric"
            params = @{}
        },
        @{
            id = "2"
            enabled = $true
            type = "terms"
            schema = "segment"
            params = @{
                field = "source_ip"
                orderBy = "1"
                order = "desc"
                size = 10
                otherBucket = $false
                otherBucketLabel = "Other"
                missingBucket = $false
                missingBucketLabel = "Missing"
            }
        }
    )
}
Create-Visualization -name "nids-source-ips" -title "Source IP Addresses" -visType "horizontal_bar" -visState $sourceIPsVis

# 5. Target IPs
$targetIPsVis = @{
    title = "Target IP Addresses"
    type = "horizontal_bar"
    aggs = @(
        @{
            id = "1"
            enabled = $true
            type = "count"
            schema = "metric"
            params = @{}
        },
        @{
            id = "2"
            enabled = $true
            type = "terms"
            schema = "segment"
            params = @{
                field = "destination_ip"
                orderBy = "1"
                order = "desc"
                size = 10
                otherBucket = $false
                otherBucketLabel = "Other"
                missingBucket = $false
                missingBucketLabel = "Missing"
            }
        }
    )
}
Create-Visualization -name "nids-target-ips" -title "Target IP Addresses" -visType "horizontal_bar" -visState $targetIPsVis

# 6. Recent Events Search
$columns = @("timestamp", "event_id", "event_type", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "network_zone", "confidence")
Create-Search -name "nids-recent-events" -title "Recent Attack Events" -columns $columns -sortField "timestamp" -sortOrder "desc"

# 7. Create Index Pattern
Create-IndexPattern

# 8. Import Dashboard (fix filename)
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$dashboardPath = Join-Path $scriptPath "kibana_dashboard.ndjson"  # Fixed extension
if (-not (Test-Path $dashboardPath)) {
    # Try alternative filename
    $dashboardPath = Join-Path $scriptPath "kibana_dashboard.json"
}
Import-Dashboard -jsonFilePath $dashboardPath

Write-Host "`nAll visualizations, searches, and dashboard have been created." -ForegroundColor Green
Write-Host "Open $KIBANA_URL/app/dashboards to view your dashboards" -ForegroundColor Cyan
