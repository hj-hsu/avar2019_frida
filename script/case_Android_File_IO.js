/**
 * to demo how Frida can inject code to inspect and control
 * Java.File and libc.so file I/O operation
 * @author Vash Hsu
 * @date September, 2019
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

const isMonitoringIO = true;
var libcIOmap = {};
var fileIOmap = {};
const isMonitoringJavaFile = true;

const isInterestingPath = function(filePath) {
  if (filePath.endsWith('.jar') || filePath.endsWith('.dex')) {
    return true;
  }
  return false;
};

setImmediate(function() {
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

  Java.perform(function() {
    if (isMonitoringJavaFile) {
      var ioFile = Java.use("java.io.File");
      // public boolean exists ()
      ioFile.exists.implementation = function() {
        var filePath = this.path['value'];
        var returnCode = this.exists();
        if (isInterestingPath(filePath)) {
          reportCall('io.FILE', ['exists', filePath, returnCode]);
        }
        return returnCode;
      }
      // public boolean delete ()
      ioFile.delete.implementation = function() {
        var filePath = this.path['value'];
        var returnCode = this.delete();
        if (isInterestingPath(filePath)) {
          reportCall('io.FILE', ['delete', filePath, returnCode]);
        }
        return returnCode;
      }
      // public boolean createNewFile ()
      //   true if the named file does not exist and was successfully created;
      //   false if the named file already exists
      ioFile.createNewFile.implementation = function() {
        var filePath = this.path['value'];
        var returnCode = this.createNewFile();
        if (isInterestingPath(filePath)) {
          reportCall('io.FILE', ['createNewFile', filePath, returnCode]);
        }
        return returnCode;
      }
    }
  }); // end of Java.perform
});
