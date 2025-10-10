import os
import sys
import json
from virustotal_api import PublicApi as VirusTotalPublicApi

# Get the API Key from environment variables for security
API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

if not API_KEY:
    # Print error to stderr so Node.js can catch it
    sys.stderr.write(json.dumps({"error": "VIRUSTOTAL_API_KEY environment variable not set."}))
    sys.exit(1)

# Check if a URL was passed as an argument
if len(sys.argv) < 2:
    sys.stderr.write(json.dumps({"error": "No URL provided."}))
    sys.exit(1)

url_to_check = sys.argv[1]

try:
    # Initialize the VirusTotal API client
    vt = VirusTotalPublicApi(API_KEY)

    # Submit the URL for scanning and get the report
    response = vt.get_url_report(url_to_check)

    # Print the JSON response to standard output
    # Node.js will read this output
    print(json.dumps(response, indent=2))

except Exception as e:
    sys.stderr.write(json.dumps({"error": f"An error occurred: {str(e)}"}))
    sys.exit(1)
