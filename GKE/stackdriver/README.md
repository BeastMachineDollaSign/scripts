#How to use backup:
If pwd is current directory:
Pass backup folder (must exist), google credentials and project name. A new sub-folder will be created
GCLOUD_PROJECT=abhi-test-project-2512344 STACK_DRIVER_BACKUP=./backup GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/Abhi\ Test\ Project-dca8c39952c7.json python3 backup.py

#How to use restore:
If pwd is current directory:
Pass the backup folder to restore, google credentials and project name
GCLOUD_PROJECT=abhi-test-project-2512344 STACK_DRIVER_BACKUP=./backup/201908291057 GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/Abhi\ Test\ Project-dca8c39952c7.json python3 restore.py