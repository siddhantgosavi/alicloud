function percentencode {
    param ($inputstring)
    return [uri]::EscapeDataString($inputstring).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")
}

$AccessKeyId = ""
$SecretKeyId = ""

$HTTP_METHOD = "GET"
$param = @{
    "RegionId" = "cn-hangzhou"
    "Version"= "2018-12-03"
    "AccessKeyId"= $AccessKeyId
    "Timestamp"= (Get-Date (Get-Date).ToUniversalTime() -Format "yyyy-MM-dd'T'HH:mm:ss'Z'")
    "SignatureMethod"= "HMAC-SHA1"
    "SignatureVersion"= "1.0"
    "SignatureNonce"= ((New-Guid).Guid.ToString())
    "Format"= "JSON"
    "Action"= "GetVulStatistics"
    "TypeList" = "cve"
    "GroupIdList" = "8908842"
}

$sortedkeys = $param.Keys | Sort-Object

$SEPARATOR = '&'

$stringtosign = ""
$stringtosign += "$HTTP_METHOD$SEPARATOR"
$stringtosign += percentencode("/")
$stringtosign += $SEPARATOR

$canonicalizedQueryString = ""
foreach ($key in $sortedkeys) {
    $canonicalizedQueryString += "&" + (percentencode($key)) + "=" + (percentencode($param[$key]))
}
$canonicalizedQueryString = $canonicalizedQueryString.TrimStart('&')

$stringtosign += percentencode($canonicalizedQueryString)

$hmac = New-Object System.Security.Cryptography.HMACSHA1
$hmac.Key = [Text.Encoding]::UTF8.GetBytes("$SecretKeyId&")
$signature = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringtosign))
$signature = [Convert]::ToBase64String($signature)

$query = ""

foreach ($key in $sortedkeys) {
    $query += "&" + (percentencode($key)) + "=" + (percentencode($param[$key]))
}

$query = $query.TrimStart('&')
$query = "https://tds.aliyuncs.com/?" + $query

$query += "&" + "Signature=" + (percentencode($signature))
$query

Invoke-RestMethod -Uri $query -Verbose