function percentencode {
    param ($inputstring)
    return [uri]::EscapeDataString($inputstring).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")
}

$HTTP_METHOD = "GET"

$param = @{
    "Action"= "DescribeRegions"
    "Version"= "2014-05-26"
    "AccessKeyId"= "LTAI5tJXeuotJ92hZ3FBXPZL"
    "Timestamp"= (Get-Date (Get-Date).ToUniversalTime() -Format "yyyy-MM-dd'T'HH:mm:ss'Z'")
    "SignatureMethod"= "HMAC-SHA1"
    "SignatureVersion"= "1.0"
    "SignatureNonce"= ((New-Guid).Guid.ToString())
    "Format"= "JSON"
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
$hmac.Key = [Text.Encoding]::UTF8.GetBytes("Fxe5k34OZ5gozo4sWNbDwJHCIULOhy&")
$signature = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringtosign))
$signature = [Convert]::ToBase64String($signature)

$query = ""

foreach ($key in $sortedkeys) {
    $query += "&" + (percentencode($key)) + "=" + (percentencode($param[$key]))
}

$query = $query.TrimStart('&')
$query = "https://ecs.aliyuncs.com/?" + $query

$query += "&" + "Signature=" + (percentencode($signature))
$query

Invoke-RestMethod -Uri $query -Verbose