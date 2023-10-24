# Warning:
# log will be reload when server restart since list can't store permanently 
# ===============================================================
# Procedure description:
# Step 1:add a new dircectory named "store-logs" as same as Apache log directory
# Step 2:Then, add two files named "access2.log" and "access3.log" in "store-logs" respectively
# Step 3: Modify model_path to your model path
# Step 4:Run server => python monitory.py for starting monitor
# ===============================================================

import os,sys,time

# get file and its modified time
def files_to_timestamp(path):
    files = [os.path.join(path, f) for f in os.listdir(path)]
    return dict ([(f, os.path.getmtime(f)) for f in files])

if __name__ == "__main__":
    path_to_watch = 'C:\\xampp\\apache\\logs' # directory monitoring
    model_path = '.\\MODELS\\model_RandomForestClassifier.pkl'
    print('Monitoring {}..'.format(path_to_watch))
    
    log_list = [] # record log

    before = files_to_timestamp(path_to_watch) # dict

    while 1:
        time.sleep (2) # monitor every two seconds
        after = files_to_timestamp(path_to_watch)
        added = [f for f in after.keys() if not f in before.keys()]
        removed = [f for f in before.keys() if not f in after.keys()]
        modified = []

        for f in before.keys():
            if not f in removed:
                if os.path.getmtime(f) != before.get(f):
                    modified.append(f)

        # if file or directory added
        if added: 
            print('Added: {}'.format(', '.join(added)))
        # if file directory removed
        if removed: 
            print('Removed: {}'.format(', '.join(removed)))
        # if file directory modified
        if modified: 
            with open(r'C:\\xampp\\apache\\logs\\access.log', "r") as fp:
                lines = fp.readlines()
                file_list = []
                for line in lines:
                    file_list.append(line)
                
                ## check if log exist in log list
                for i in range(len(file_list)-1, 0, -1):
                    if file_list[i] not in log_list:
                        log_list.append(file_list[i])
                        file1 = open('C:\\xampp\\apache\logs\\store-logs\\access2.log', 'a')
                        file1.write(file_list[i])
                        file1.close()
                    else:
                        break
                fp.close()
                
            # call predict.py
            os.system('python predict_with_blockchain.py -l C:\\xampp\\apache\\logs\\store-logs\\access2.log -m {} '.format(model_path))
            
            # move log from access2.log to access3.log
            accessLog2 = open('C:\\xampp\\apache\logs\\store-logs\\access2.log', 'r')
            accessLog3 = open('C:\\xampp\\apache\logs\\store-logs\\access3.log', 'a')
            for line in accessLog2:
                accessLog3.write(line)
            accessLog2.close()
            accessLog3.close()
            
            # erase log in access2.log
            open('C:\\xampp\\apache\logs\\store-logs\\access2.log', 'w').close()
            
            print('Modified: {}'.format(', '.join(modified)))

        
        

        before = after