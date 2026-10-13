if ($args[0] -eq "bad") { Write-Output "REFUSED: not a PE"; exit 3 }
Write-Output '{"packed":false,"ok":true}'; exit 0
