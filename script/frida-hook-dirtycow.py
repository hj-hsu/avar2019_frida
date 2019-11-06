#!/usr/bin/env python

# python code from https://github.com/frida/frida-python/blob/master/examples/child_gating.py
# modification:
# * from python3 to python 2.7
# * frida script for intercepting dirtyCow sample

from __future__ import print_function
import frida
from frida_tools.application import Reactor
import threading


class Application(object):
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        # self._device = frida.get_local_device()
        self._device = frida.get_usb_device()
        self._sessions = set()

        # self._device.on("delivered", lambda child: self._reactor.schedule(lambda: self._on_delivered(child)))
        self._device.on("spawn-added", lambda child: self._reactor.schedule(lambda: self._on_delivered(child)))

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        argv = ["/data/local/tmp/dcow", "/data/local/tmp/run-as",
            "/system/bin/run-as"]
        print("v spawn(argv={})".format(argv))
        pid = self._device.spawn(argv)
        self._instrument(pid)
        #package_name = "com.yk26gzrdq"
        #activity_name = "com.yk26gzrdq.DesktopActivity"
        #pid = self._device.spawn(package_name, activity=activity_name)
        #pid = self._device.spawn(package_name)
        #self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        print("v attach(pid={})".format(pid))
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(
            lambda: self._on_detached(pid, session, reason)))
        print("v enable_child_gating()")
        session.enable_child_gating()
        print("v create_script()")
        script = session.create_script("""

/**
 * to demo how Frida can intercept dirtyCow vulnerability Apps
 * @author Vash Hsu
 * @date Octorber, 2019
*/

/**
 * Log the involked methods.
 * @param {string} typeString reporting type, to group multiple send-messages
 * @param {array} infoList array of meta data, where each is ASCII string
 */
function reportCall(typeString, infoList) {
  const sendData = {
    'c': 'report',
    'type': typeString,
    'cols': infoList,
  };
  send(JSON.stringify(sendData));
}

var libcIOmap = {};
var fileIOmap = {};


setImmediate(function() {
  var updateIOmap = function(myKey, myValue) {
    libcIOmap[myKey] = myValue;
  };
  var lookupIOmap = function(myKey) {
    if (myKey in libcIOmap) {
      return libcIOmap[myKey];
    } else {
      return '';
    }
  };
  var updateFileIOmap = function(myKey, myValue) {
    fileIOmap[myKey] = myValue;
  };
  var lookupFileIOmap = function(myKey) {
    if (myKey in fileIOmap) {
      return fileIOmap[myKey];
    } else {
      return '';
    }
  };
  const isInterestingPath = function(filePath) {
    if (filePath.startsWith('/system/') || filePath.startsWith('/data/') ||
      filePath.startsWith('/proc/') || filePath.startsWith('/sdcard/')) {
      return true;
    }
    return true;
  };

  // void *mmap(void *addr, size_t length, int prot, int flags,
  //    int fd, off_t offset);
  // #define PROT_READ      0x1  /* page can be read */
  // #define MAP_PRIVATE    0x0  /* changes are private */
  Interceptor.attach(Module.findExportByName('libc.so', 'mmap'), {
    onEnter: function(args) {
      this.addr = args[0];
      this.len = parseInt(args[1]);
      this.prot = parseInt(args[2]);
      if (this.prot === 1) {
        this.prot = 'PROT_READ';
      }
      this.flags = parseInt(args[3]);
      if (this.flags === 0) {
        this.flags = 'MAP_PRIVATE';
      }
      this.fd = parseInt(args[4]);
      this.offset = parseInt(args[5]);
    },
    onLeave: function(retval) {
      var result = parseInt(retval);
      var targetFile = lookupIOmap(this.fd);
      reportCall('libc.so',
        ['mmap', this.addr, "len="+this.len, "prop="+this.prot, "flag="+this.flags,
            targetFile, "fd="+this.fd, this.offset, retval]);
      return retval;
    },
  });
  // int madvise(void *addr, size_t length, int advice);
  // #define MADV_DONTNEED 4 /* dont need these pages */
  Interceptor.attach(Module.findExportByName('libc.so', 'madvise'), {
    onEnter: function(args) {
      this.addr = args[0];
      this.len = parseInt(args[1]);
      this.advice = parseInt(args[2]);
      if (this.advice === 4) {
        this.advice = 'MADV_DONTNEED';
      }
    },
    onLeave: function(retval) {
      reportCall('libc.so',
          ['madvise', this.addr, this.len, this.advice, retval]);

      return retval;
    },
  });

  // int open(const char *pathname, int flags, mode_t mode);
  Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
    onEnter: function(args) {
      this.path = Memory.readUtf8String(args[0]);
      this.flag = args[1];
      if (parseInt(this.flag) === 0) {
        this.flag = 'O_RDONLY';
      }
      if (typeof args[2] !== 'undefined') {
        this.mode = args[2];
      } else {
        this.mode = 0;
      }
    },
    onLeave: function(retval) {
      var fd = parseInt(retval);
      if (fd != -1) {
        if (isInterestingPath(this.path)) {
          reportCall('libc.so',
              ['open', this.path, this.flag, this.mode, "fd="+fd]);
        }
        updateIOmap(fd, this.path);
      }
      return retval;
    },
  });
  // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
  Interceptor.attach(Module.findExportByName('libc.so', 'openat'), {
    onEnter: function(args) {
      this.path = Memory.readUtf8String(args[1]);
      this.flag = args[2];
      if (parseInt(this.flag) === 0) {
        this.flag = 'O_RDONLY';
      }
      this.mode = args[3];
    },
    onLeave: function(retval) {
      var fd = parseInt(retval);
      if (fd != -1) {
        reportCall('libc.so',
            ['openat', this.path, this.flag, this.mode, "fd="+fd]);
        updateIOmap(fd, this.path);
      }
      return retval;
    },
  });
  // int close(int fildes);
  Interceptor.attach(Module.findExportByName('libc.so', 'close'), {
    onEnter: function(args) {
      this.fd = parseInt(args[0]);
    },
    onLeave: function(retval) {
      var result = parseInt(retval);
      var path = lookupIOmap(this.fd);
      reportCall('libc.so', ['close', path, "fd="+this.fd, result]);
      return retval;
    },
  });
  // ssize_t write(int fd, const void *buf, size_t count);
  Interceptor.attach(Module.findExportByName('libc.so', 'write'), {
    onEnter: function(args) {
      this.fd = parseInt(args[0]);
    },
    onLeave: function(retval) {
      var result = parseInt(retval);
      var path = lookupIOmap(this.fd);
      if (isInterestingPath(path)) {
        reportCall('libc.so', ['write', path, "fd="+this.fd, result]);
      }
      return retval;
    },
  });

  // FILE *fopen(const char *restrict filename, const char *restrict mode);
  Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
    onEnter: function(args) {
      this.path = Memory.readUtf8String(args[0]);
      this.mode = Memory.readUtf8String(args[1]);
    },
    onLeave: function(retval) {
      reportCall('libc.so', ['fopen', this.path, this.mode, retval]);
      updateFileIOmap(retval, this.path, 'fptr='+retval);
      return retval;
    },
  });
  // int fclose(FILE *stream);
  Interceptor.attach(Module.findExportByName('libc.so', 'fclose'), {
    onEnter: function(args) {
      this.fptr = args[0];
    },
    onLeave: function(retval) {
      var path = lookupFileIOmap(this.fptr);
      reportCall('libc.so', ['fclose', path, 'fptr='+this.fptr, retval]);
      return retval;
    },
  });
  // size_t fwrite(const void *restrict ptr, size_t size, size_t nitems,
  // FILE *restrict stream);
  Interceptor.attach(Module.findExportByName('libc.so', 'fwrite'), {
    onEnter: function(args) {
      this.fptr = args[3];
    },
    onLeave: function(retval) {
      var path = lookupFileIOmap(this.fptr);
      var totalBytes = parseInt(retval);
      reportCall('libc.so', ['fwrite', path, 'fptr='+this.fptr,totalBytes]);
    },
  });
});


""")
        script.on("message", lambda message, data: self._reactor.schedule(lambda: self._on_message(pid, message)))
        print("v load()")
        script.load()
        print("v resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_delivered(self, child):
        print("/  delivered: {}".format(child))
        self._instrument(child.pid)

    def _on_detached(self, pid, session, reason):
        print("/  detached: pid={}, reason='{}'".format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        print("/  message: pid={}, payload={}".format(pid, message["payload"]))


app = Application()
app.run()
