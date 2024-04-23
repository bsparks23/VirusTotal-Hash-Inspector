VirusTotal Hash Inspector is a Python script that uses the VirusTotal API to find malicious assocations with a given hash by parsing the json response and looking for any security vendors that are flagging the hash by extracting the value from the "malicious" key. The results are then sorted from most malicious to least malicious. If a hash doesn't have any threat intelligence, then that data is provided and shown in the output. This allows for rapid checking of large amounts of hashes in order to help determine if the hashes are benign/malicious. 