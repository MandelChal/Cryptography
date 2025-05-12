Get-Content -Path "AES_encrypted.bin" -Encoding Byte | Format-Hex
[System.IO.File]::ReadAllBytes("AES_encrypted.bin") | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') + " " }                                        
