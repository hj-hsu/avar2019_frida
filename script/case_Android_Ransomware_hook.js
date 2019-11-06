/**
 * to demo how Frida can inject code to inspect and replace payload
 * within javax.crypto encryption and decryption
 * @author Vash Hsu
 * @date September, 2019
 * sample: 61F73BF90C3234FAEB8AA7C90F24FA3F7A3A1D38B2E94D40CE96A21E7320FD28
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

const isMonitoringCipher = true;
const isMonitoringIO = true;

var libcIOmap = {};
var fileIOmap = {};

const isInterestingPath = function(filePath) {
  if (filePath.endsWith('.jar') || filePath.endsWith('.dex')) {
    return true;
  }
  return true; // return false;
};

/**
 * Convert inputed integer to ASCII string, with . if not ASCII
 * @param {integer} numOfCode integer to represent typs of Cipher structure/data
 * @return {string} printable string
 */
function getCipherOpType(numOfCode) {
  const cipherOpMode = {
    0: 'DECRYPT_MODE',
    1: 'ENCRYPT_MODE',
    2: 'PRIVATE_KEY',
    3: 'PUBLIC_KEY',
    4: 'SECRET_KEY',
    5: 'UNWRAP_MODE',
    6: 'WRAP_MODE',
  };
  if (numOfCode in cipherOpMode) {
    return cipherOpMode[numOfCode];
  } else {
    return numOfCode.toString();
  }
}

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
    if (isMonitoringCipher) {
      // Javax Crypto
      const jxCipher = Java.use('javax.crypto.Cipher');
      var mode = 0;
      /*
      init(int opmode, Key key, AlgorithmParameters params)
      init(int opmode, Certificate certificate, SecureRandom random)
      init(int opmode, Key key, SecureRandom random)
      init(int opmode, Key key, AlgorithmParameterSpec params)
      init(int opmode, Key key)
      init(int opmode, Key key, AlgorithmParameterSpec params,
          SecureRandom random)
      init(int opmode, Certificate certificate)
      init(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      */
      const cipherInit1 = jxCipher.init.overload('int',
          'java.security.Key', 'java.security.AlgorithmParameters');
      const cipherInit2 = jxCipher.init.overload('int',
          'java.security.cert.Certificate', 'java.security.SecureRandom');
      const cipherInit3 = jxCipher.init.overload('int',
          'java.security.Key', 'java.security.SecureRandom');
      const cipherInit4 = jxCipher.init.overload('int',
          'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
      const cipherInit5 = jxCipher.init.overload('int',
          'java.security.Key');
      const cipherInit6 = jxCipher.init.overload('int',
          'java.security.Key', 'java.security.spec.AlgorithmParameterSpec',
          'java.security.SecureRandom');
      const cipherInit7 = jxCipher.init.overload('int',
          'java.security.cert.Certificate');
      const cipherInit8 = jxCipher.init.overload('int',
          'java.security.Key', 'java.security.AlgorithmParameters',
          'java.security.SecureRandom');

      cipherInit1.implementation = function(var0, var1, var2) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1, var2);
      };
      cipherInit2.implementation = function(var0, var1, var2) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1, var2);
      };
      cipherInit3.implementation = function(var0, var1, var2) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1, var2);
      };
      cipherInit4.implementation = function(var0, var1, var2) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1, var2);
      };
      cipherInit5.implementation = function(var0, var1) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1);
      };
      cipherInit6.implementation = function(var0, var1, var2, var3) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1, var2, var3);
      };
      cipherInit7.implementation = function(var0, var1) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1);
      };
      cipherInit8.implementation = function(var0, var1, var2, var3) {
        mode = parseInt(var0);
        reportCall('Cipher', ['init', getCipherOpType(mode)]);
        return this.init(var0, var1, var2, var3);
      };

      const cipherDoFinalv1 = jxCipher.doFinal.overload();
      const cipherDoFinalv2 = jxCipher.doFinal.overload('[B');
      const cipherDoFinalv3 = jxCipher.doFinal.overload('[B', 'int');
      const cipherDoFinalv4 = jxCipher.doFinal.overload('[B', 'int', 'int');
      const cipherDoFinalv5 = jxCipher.doFinal.overload('[B', 'int', 'int',
          '[B');
      const cipherDoFinalv6 = jxCipher.doFinal.overload('[B', 'int', 'int',
          '[B', 'int');

      const cipherUpdatev1 = jxCipher.update.overload('[B');
      const cipherUpdatev2 = jxCipher.update.overload('[B', 'int', 'int');
      const cipherUpdatev3 = jxCipher.update.overload('[B', 'int', 'int', '[B');
      const cipherUpdatev4 = jxCipher.update.overload('[B', 'int', 'int', '[B',
          'int');

      cipherDoFinalv1.implementation = function() {
        const ret = cipherDoFinalv1.call(this);
        reportCall('Cipher', ['doFinal', getCipherOpType(mode)]);
        return ret;
      };

      cipherDoFinalv2.implementation = function(var0) {
        const ret = cipherDoFinalv2.call(this, var0);
        reportCall('Cipher', ['doFinal', getCipherOpType(mode)]);
        return ret;
      };

      cipherDoFinalv3.implementation = function(var0, var1) {
        const ret = cipherDoFinalv3.call(this, var0, var1);
        reportCall('Cipher', ['doFinal', getCipherOpType(mode)]);
        return ret;
      };

      cipherDoFinalv4.implementation = function(var0, var1, var2) {
        const ret = cipherDoFinalv4.call(this, var0, var1, var2);
        reportCall('Cipher', ['doFinal', getCipherOpType(mode)]);
        return ret;
      };

      cipherDoFinalv5.implementation = function(var0, var1, var2, var3) {
        const ret = cipherDoFinalv5.call(this, var0, var1, var2, var3);
        reportCall('Cipher', ['doFinal', getCipherOpType(mode)]);
        return ret;
      };

      cipherDoFinalv6.implementation = function(var0, var1, var2, var3, var4) {
        const ret = cipherDoFinalv6.call(this, var0, var1, var2, var3, var4);
        reportCall('Cipher', ['doFinal', getCipherOpType(mode)]);
        return ret;
      };

      cipherUpdatev1.implementation = function(var0) {
        reportCall('Cipher', ['update', getCipherOpType(mode)]);
        return cipherUpdatev1.call(this, var0);
      };

      cipherUpdatev2.implementation = function(var0, var1, var2) {
        reportCall('Cipher', ['update', getCipherOpType(mode)]);
        return cipherUpdatev2.call(this, var0, var1, var2);
      };

      cipherUpdatev3.implementation = function(var0, var1, var2, var3) {
        reportCall('Cipher', ['update', getCipherOpType(mode)]);
        return cipherUpdatev3.call(this, var0, var1, var2, var3);
      };

      cipherUpdatev4.implementation = function(var0, var1, var2, var3, var4) {
        reportCall('Cipher', ['update', getCipherOpType(mode)]);
        return cipherUpdatev4.call(this, var0, var1, var2, var3, var4);
      };
    } // end of isMonitoringCipher
  });
});
