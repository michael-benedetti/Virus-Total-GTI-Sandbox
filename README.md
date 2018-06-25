<h1>Poor Man's GTI/Sandbox Solution</h1>

This script requires a <a href="https://www.virustotal.com/en/documentation/public-api/">VirusTotal public API key</a>.  Once a key is obtained, modify vt.py to include your key and customize the directories list to include targeted directories for scanning.

The VirusTotal API is limited to four requests per minute.  This script will first query using the file hash to determine if it exists in the VirusTotal database and submit the file for analysis if not.  This counts as two requests.  Once the script has run once, db.pkl will be created which stores the results of the previous scan locally.  When the script is run again, any file hash changes will trigger another lookup/file submission. 

Testing Concourse
