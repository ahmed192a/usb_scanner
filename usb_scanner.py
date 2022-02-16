from pyudev import Context, Monitor
import psutil
import threading
import time
import yara  
import os
from sty import fg, bg, ef, rs

# yara rules path 
yarabase = 'rules'                  

class Scan(threading.Thread):
    def __init__(self, threadID, device):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.device = device
        self.safe = True

    def recursives_files(self,dirs, extension):
        files = list()
        for (dirpath, dnames, fnames) in os.walk(dirs):
            for file in fnames:
                if extension == os.path.splitext(file)[-1].lower() or extension =='*':
                    files.append(os.path.join(dirpath, file))
        return files


    def Get_Rules(self,roles_path):
        files = {}
        ind = 0
        for f in self.recursives_files(roles_path, '.yar'):
            files[str(ind)] = str(f)
            ind += 1
        return yara.compile(filepaths=files)

    def StartScan(self, USB_path, roles_path):
        rules = self.Get_Rules(roles_path)
        if os.path.isdir(USB_path):
            USB_files = self.recursives_files(USB_path, '*')
            for file in USB_files:
                if len(rules.match(file)) > 0:
                    print( fg.red  + "Thread ["+ str(self.threadID) + "]  " + file + fg.rs + " ==> " + fg.red + "Danger " + fg.rs)
                    self.safe = False
                else:
                    print("Thread [" + str(self.threadID) + "]  " + file  + " ==> "   + 'Safe ' )
    
    def run(self):
        for p in psutil.disk_partitions():
            if p.device == self.device:
                print("{} : {}".format(p.device, p.mountpoint))
                break
        self.StartScan(p.mountpoint, yarabase)
        print("Thread ["+ str(self.threadID)+"] "+bg.green+fg.blue+"Finish Scanning "+fg.rs+bg.rs+"\n")
        if(self.safe == False):
            os.system('notify-send "Scan USB Result" "Has infected files"')
        else:
            os.system('notify-send "Scan USB Result" "All files are safe"')
            




context = Context()
monitor = Monitor.from_netlink(context)
monitor.filter_by(subsystem='block')
print("Start Monitoring for USB Insertion ...")
id = 0
i = 0
for device in iter(monitor.poll, None):
    i  = (i+1)%2
    if(device.action == 'add' and i == 0):
        print('{0} : {1}'.format(device.action, device.device_node))
        time.sleep(1)
        thread1 = Scan(id, device.device_node)
        thread1.start()
        id = id + 1


        

    


            
