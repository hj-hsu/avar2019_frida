/**
 * to demo how Frida can inject code to trace dropper with DexClassLoader
 * @author Vash Hsu
 * @date September, 2019
 * sample: 26A983760B78310BBD30CD4A75F72EA24C940303E27F059A6A80720EA25CAE5F
*/

/**
 * Log the involked methods.
 * @param {string} typeString reporting type, to group multiple send-messages
 * @param {array} infoList array of meta data, where each is ASCII string
 */
function reportCall(typeString, infoList) {
  const dataSend = {
    'c': 'report',
    'type': typeString,
    'cols': infoList,
  };
  send(JSON.stringify(dataSend));
};

const isMonitoringIO = true;
var libcIOmap = {};
var fileIOmap = {};

const isInterestingPath = function(filePath) {
  if (filePath.endsWith('.jar') || filePath.endsWith('.dex')) {
    return true;
  }
  return false;
};


/**
 * dalvik.system.DexClassLoader
 * public DexClassLoader (String dexPath,
                String optimizedDirectory,  /sdcard/
                String librarySearchPath,
                ClassLoader parent)
 * -
 */

setImmediate(function() {
  Java.perform(function() {
    var myThread = Java.use('java.lang.Thread');
    var myInstance = myThread.$new();
    const dumpStackTrace4java = function() {
      const level = 2;
      const stack = myInstance.currentThread().getStackTrace();
      var backTrace = [];
      if (stack.length > level) {
        for (var i=level; i<stack.length; i++) {
          backTrace.push(stack[i].toString());
        }
      }
      return backTrace.join(', ');
    };

    const dexClsLer = Java.use('dalvik.system.DexClassLoader');
    dexClsLer.$init.overload(
        'java.lang.String', 'java.lang.String',
        'java.lang.String', 'java.lang.ClassLoader').implementation =
          function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            const rtValue = this.$init(dexPath, optimizedDirectory,
                librarySearchPath, parent);
            reportCall('DexClassLoader', ['DexClassLoader()', 'return',
              rtValue]);
            reportCall('DexClassLoader', ['callstack', dumpStackTrace4java()]);
            reportCall('DexClassLoader', ['param dexPath', dexPath]);
            reportCall('DexClassLoader', ['param optimizedDirectory',
              optimizedDirectory]);
            reportCall('DexClassLoader', ['param librarySearchPath',
              librarySearchPath]);
            reportCall('DexClassLoader', ['param parent', parent]);
            const packages = parent.getPackages();
            for (var i=0; i<packages.length; i++) {
              reportCall('DexClassLoader', ['param parent', 'sibling',
                packages[i].getName()]);
            }

            return rtValue;
          };
  }); // end of Java.perform

  if (isMonitoringIO) {
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
    // FILE *fopen(const char *restrict filename, const char *restrict mode);
    Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
      onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
        this.mode = Memory.readUtf8String(args[1]);
      },
      onLeave: function(retval) {
        if (isInterestingPath(this.path)) {
          reportCall('libc.so', ['fopen', this.path, this.mode, retval]);
        }
        if (parseInt(retval) != 0) {
          updateFileIOmap(retval, this.path);
        }
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
        if (isInterestingPath(path)) {
          reportCall('libc.so', ['fclose', path, retval]);
        }
        return retval;
      },
    });

    // int open(const char *path, int oflag, ... );
    Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
      onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
        this.oflag = args[1];
      },
      onLeave: function(retval) {
        var fd = parseInt(retval);
        if (fd != -1) {
          if (isInterestingPath(this.path)) {
            reportCall('libc.so', ['open', this.path, this.oflag, retval]);
          }
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
        if (result >= 0) {
          if (isInterestingPath(path)) {
            reportCall('libc.so', ['close', path, result]);
          }
        }
        return retval;
      },
    });
    // ssize_t read(int fd, void *buf, size_t count);
    Interceptor.attach(Module.findExportByName('libc.so', 'read'), {
      onEnter: function(args) {
        var fd = parseInt(args[0]);
        this.filename = lookupIOmap(fd);
      },
      onLeave: function(retval) {
        if (isInterestingPath(this.filename)) {
          reportCall('libc.so', ['read', this.filename, parseInt(retval)]);
        }
        return retval;
      },
    });
    // ssize_t write(int fd, const void *buf, size_t count);
    Interceptor.attach(Module.findExportByName('libc.so', 'write'), {
      onEnter: function(args) {
        var fd = parseInt(args[0]);
        this.filename = lookupIOmap(fd);
      },
      onLeave: function(retval) {
        if (isInterestingPath(this.filename)) {
          reportCall('libc.so', ['write', this.filename, parseInt(retval)]);
        }
        return retval;
      },
    });

    // C Library: unlink() and remove()
    var unlinkFptr = Module.findExportByName('libc.so', 'unlink');
    var unlink = new NativeFunction(unlinkFptr, 'int', ['pointer']);
    var removeFptr = Module.findExportByName('libc.so', 'remove');
    var remove = new NativeFunction(removeFptr, 'int', ['pointer']);
    // libc.so: int unlink(const char *path);
    Interceptor.replace(unlinkFptr, new NativeCallback(function(var0) {
      var filePath = Memory.readUtf8String(var0);
      var returnCode = unlink(var0);
      if (isInterestingPath(filePath)) {
        reportCall('libc.so', ['unlink', filePath, returnCode]);
      }
      return returnCode;
    }, 'int', ['pointer']));
    // libc.so: int remove(const char *path);
    Interceptor.replace(removeFptr, new NativeCallback(function(var0) {
      var filePath = Memory.readUtf8String(var0);
      var returnCode = remove(var0);
      if (isInterestingPath(filePath)) {
        reportCall('libc.so', ['remove', filePath, returnCode]);
      }
      return returnCode;
    }, 'int', ['pointer']));
  }
});
