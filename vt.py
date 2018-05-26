import requests
import hashlib
import os
import time
import pickle
import ntpath
import sys

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def check_quota(n):
    i = n
    if i == 4:
        time.sleep(60)
        i = 0
    return i + 1

apikey = '' #Enter API Key Here
url = 'https://www.virustotal.com/vtapi/v2/file/report'
directories = ["/tmp", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]
#directories.append(input("enter additional directory to scan...\n"))
params = {'apikey': apikey, 'resource': ''}
tab_buf = 30

n = 0
i = 0
with open('db.pkl', 'rb') as pkl_file:
    db = pickle.load(pkl_file)
    try:
      for directory in directories:
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if not os.path.isdir(file_path) and file != "spotify":
                n += 1
                sys.stdout.write("Files scanned: {0}   \r".format(n))
                sys.stdout.flush()
                file_md5 = md5(file_path)
                if file_path not in db or (file_path in db and file_md5 != db[file_path]['md5']):
                    params['resource'] = file_md5
                    i = check_quota(i)
                    response = requests.get(url, params=params)
                    if 'positives' in response.json():
                        if response.json()['positives'] > 0:
                            positives = "\033[91m" + str(response.json()['positives']) + "\033[0m"
                        else:
                            positives = "\033[93m" + str(response.json()['positives']) + "\033[0m"
                        print("File name: {0}{1}||  Positives: {2}".format(file, " "*(tab_buf-len(file)), positives))
                        positives = response.json()['positives']
                        scanned = True
                        db[file_path] = {'md5':file_md5, 'positives':positives, 'scanned':scanned}
                    else:
                        files = {'file': (file, open(file_path, 'rb'))}
                        i = check_quota(i)
                        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params={'apikey': apikey})
                        print("File name: {0}{1}||  Submitted for Scan".format(file, " "*(tab_buf-len(file))))
    except KeyboardInterrupt:
        print("Keyboard Interrupt! Saving Database and exiting...")

with open('db.pkl', 'wb') as pkl_file:
    pickle.dump(db, pkl_file)
print("\n\033[92mFiles with detections:")
for item in db:
    if db[item]['positives'] > 0:
        print("\033[91m{0}: {1}\033[0m".format(item, db[item]['positives']))

print("Finished with \033[92m{0}\033[0m files scanned".format(n))
