# Swann-DVR-Backup

This is a simple python project that is meant to run in a docker container that if it is running on the same network at
a Swann DVR, it is capable of downloading any intelligent detected video files, transcoding them to an efficient codec
if you'd like, and then uploading them to the backup location of your choice.

## Getting started

```shell
python -m venv ./venv
pip install -r ./requirements.txt
```
