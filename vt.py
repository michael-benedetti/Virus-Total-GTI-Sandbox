# GUI Branch

import requests
import hashlib
import os
import time
import pickle
import ntpath
import sys
from classes import *
from datetime import datetime

apikey = '85b88295be77403cbfbd3c52114b9482ea31b0d3f84ed800115d37e775fb9e5e'  # Enter API Key Here


def md5(fname):
    """md5 hashing function"""
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def check_quota(n, gui):
    """check quota to ensure we don't break 4 requests/minute limitation"""
    i = n
    if i == 4:
        i = 0
        for c in range(60):
            gui.countdown_timer.configure(text="Pausing for {0} seconds".format(60-c))
            gui.update()
            time.sleep(1)
        gui.countdown_timer.configure(text="")
    return i + 1


def vt_api_post(request_type="report", file=None, resource=None, cur_request=0, gui=None):
    """function for handling VirusTotal API requests"""
    tab_buf = 30
    i = check_quota(cur_request, gui)
    params = {'apikey': apikey}
    if request_type == "report":
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params['resource'] = resource
        return requests.post(url, params), i
    elif request_type == "scan":
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        submit_files = {'file': (ntpath.basename(file), open(file, 'rb'))}
        print("File name: {0}{1}||  Submitted for Scan".format(ntpath.basename(file),
                                                               " "*(tab_buf-len(ntpath.basename(file)))))
        return requests.post(url, files=submit_files, params=params), i


def update_progress_bar(progress_bar):
    progress_bar["value"] += 1


def run(window):
    window.progress_bar["value"] = 0
    # Define directories to scan and set counting and formatting variables
    directories = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]
    tab_buf = 30
    n = i = 0
    badfiles = ['spotify', '27850']  # Some files don't submit correctly to VirusTotal - include here to skip submission

    # Check for existance of db.pkl and create if non-existent
    if not os.path.exists('db.pkl'):
        with open('db.pkl', 'wb') as pkl_file:
            empty_pkl = {'_init_pkl': {'resource': 0, 'positives': 0}}
            pickle.dump(empty_pkl, pkl_file)

    # Load pickle database
    with open('db.pkl', 'rb') as pkl_file:
        db = pickle.load(pkl_file)
        try:
            max_value = 0
            for directory in directories:
                for root, subdirs, files in os.walk(directory):
                    for file in files:
                        max_value += 1
            window.progress_bar["maximum"] = max_value - len(badfiles)
            # Recursively iterate through directories list
            for directory in directories:
                for root, subdirs, files in os.walk(directory):
                    for file in [file for file in files if file not in badfiles]:
                        file_path = os.path.join(root, file)
                        n += 1
                        update_progress_bar(window.progress_bar)
                        window.file_label.configure(text=file_path)
                        window.iterator_label.configure(text="Files Scanned: {0}".format(n))
                        window.update()
                        sys.stdout.write("Files scanned: {0}   \r".format(n))
                        sys.stdout.flush()
                        try:
                            file_md5 = md5(file_path)
                        except:
                            continue
                        # Check pickle database for file - if hash matches and file has been
                        # scanned in last 30 days, do nothing, else submit hash for VT lookup
                        if file_path not in db or (file_path in db and file_md5 != db[file_path]['md5']):
                            response, i = vt_api_post(resource=file_md5, cur_request=i, gui=window)
                            # If GET response comes back with 'positives' object, update database with data
                            if 'positives' in response.json():
                                scan_date = datetime.strptime(response.json()['scan_date'], '%Y-%m-%d %H:%M:%S')
                                time_diff = datetime.now() - scan_date
                                if time_diff.days >= 30:
                                    response, i = vt_api_post(request_type="scan", file=file_path, cur_request=i, gui=window)
                                    if file_path in db:
                                        del(db[file_path])
                                else:
                                    if response.json()['positives'] > 0:
                                        positives = "\033[91m" + str(response.json()['positives']) + "\033[0m"
                                    else:
                                        positives = "\033[93m" + str(response.json()['positives']) + "\033[0m"
                                    print("File name: {0}{1}||  Positives: {2}".format(file,
                                                                                       " "*(tab_buf-len(file)),
                                                                                       positives))
                                    positives = response.json()['positives']
                                    db[file_path] = {'md5': file_md5, 'positives': positives, 'scan_date': scan_date}
                            # If no 'positives' object in GET response, submit file for scan
                            else:
                                response, i = vt_api_post(request_type="scan", file=file_path, cur_request=i, gui=window)
                        elif file_path in db and (datetime.now() - db[file_path]['scan_date']).days >= 30:
                            response, i = vt_api_post(request_type="scan", file=file_path, cur_request=i, gui=window)
                            if file_path in db:
                                del(db[file_path])
        # Handle KeyboardInterrupt to ensure progress is saved to pickle database
        except KeyboardInterrupt:
            print("Keyboard Interrupt! Saving Database and exiting...")

    # Save dictionary to pickle database
    with open('db.pkl', 'wb') as pkl_file:
        pickle.dump(db, pkl_file)

    # Print summary
    print("\n\033[92mFiles with detections:")
    for item in db:
        if db[item]['positives'] > 0:
            print("\033[91m{0}: {1}\033[0m".format(item, db[item]['positives']))

    print("Finished with \033[92m{0}\033[0m files scanned".format(n))
    window.file_label.configure(text="Scan Completed")


if __name__ == "__main__":
    # Initiate GUI
    window = ProgramGUI()
    window.go_button.configure(command=lambda: run(window))
    window.mainloop()
    print("Done")
