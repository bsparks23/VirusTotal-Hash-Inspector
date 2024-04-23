import requests
import os

# Replace with VirusTotal API Key using environment variables
API_KEY = os.environ.get("ReplaceHere")

def get_file_info(hash_values):
    results = []
    
    for hash_value in hash_values:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value.strip()}"
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        
        response = requests.get(url, headers=headers)

        data = response.json()
        
        # Checking if data key exists. If it doesn't exist, then the file is not known to VirusTotal 
        if "data" in data:

            # Extracts the nested "malicious" key from the JSON response and checks if the file is flagged as malicious by security vendors
            stats = data["data"]["attributes"]["last_analysis_stats"]
            detected = stats.get("malicious") > 0
           
            results.append({"hash": hash_value.strip(), "detected": detected, "malicious": stats.get("malicious")})
        else:           
            results.append({"hash": hash_value.strip(), "detected": None, "malicious": None})

    # Sorts results based on the number of security vendors that flagged the file as malicious
    results.sort(key=lambda x: x["malicious"] if x["malicious"] is not None else float("inf"), reverse=True)
    return results
 
def main():
    hash_values = []
    print("Enter the hash values (one per line), type 'done' when finished:")
    while True:
        hash_value = input().strip()
        if hash_value.lower() == "done":
            break
        hash_values.append(hash_value)

    try:
        file_info = get_file_info(hash_values)
        print("Results:")
        for result in file_info:
            if result["detected"] is None:
                print(f"No results found for hash: {result['hash']}")
            elif result["detected"]:
                print(f"Hash: {result['hash']}, Flagged as malicious - Security Vendors Flagged:{result['malicious']} ")
            else:
                print(f"Hash: {result['hash']}, Not flagged as malicious")
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    main()