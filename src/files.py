import glob
import os


def remove_old(globname: str):
    for f in glob.glob(globname):
        os.remove(f)
