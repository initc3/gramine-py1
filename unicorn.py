import os
from gunicorn.app.wsgiapp import run

os.utime = lambda path, times: pass

from gunicorn.workers import workertmp
import time
workertmp.WorkerTmp.last_update = lambda self:time.monotonic()

run()
