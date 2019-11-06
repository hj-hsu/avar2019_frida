/**
 * to demo how Frida can inject code to bypass root detection
 * @author Vash Hsu
 * @date September, 2019
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

const suBinFilenameCandidate = [
  'su',
  'busybox',
  'supersu',
  'superuser.apk',
];
const hasSuBinary = function(filePath) {
  for (var i = 0; i < suBinFilenameCandidate.length; i++) {
    if (filePath.toLowerCase().endsWith(suBinFilenameCandidate[i])) {
      return true;
    }
  }
  return false;
};

setImmediate(function() {
  Java.perform(function() {
    const myThread = Java.use('java.lang.Thread');
    const myInstance = myThread.$new();
    // dump call stack to know who perfom that checking
    const dumpCallStack = function() {
      const level = 2;
      const stack = myInstance.currentThread().getStackTrace();
      var backTrace = [];
      if (stack.length > level) {
        for (var i = level; i < stack.length; i++) {
          backTrace.push(stack[i].toString());
        }
      }
      return backTrace;
    };
    // hooking exec getruntime
    const runtime = Java.use('java.lang.Runtime');
    /* https://developer.android.com/reference/java/lang/Runtime
    Process	exec(String[] cmdarray)
    Process	exec(String[] cmdarray, String[] envp)
    Process	exec(String command)
    Process	exec(String command, String[] envp)
    Process	exec(String[] cmdarray, String[] envp, File dir)
    Process	exec(String command, String[] envp, File dir)
    */
    const runtime1 = runtime.exec.overload('[Ljava.lang.String;');
    const runtime2 = runtime.exec.overload('[Ljava.lang.String;',
        '[Ljava.lang.String;');
    const runtime3 = runtime.exec.overload('java.lang.String');
    const runtime4 = runtime.exec.overload('java.lang.String',
        '[Ljava.lang.String;');
    const runtime5 = runtime.exec.overload('[Ljava.lang.String;',
        '[Ljava.lang.String;', 'java.io.File');
    const runtime6 = runtime.exec.overload('java.lang.String',
        '[Ljava.lang.String;', 'java.io.File');

    runtime1.implementation = function(cmdArray) {
      const rtValue = runtime1.call(this, cmdArray);
      // console.log('exec 1: ' + cmdArray);
      return rtValue;
    };
    runtime2.implementation = function(cmdArray, envpArray) {
      const rtValue = runtime2.call(this, cmdArray, envpArray);
      // console.log('exec 2: ' + cmdArray);
      return rtValue;
    };
    runtime3.implementation = function(cmdString) {
      const cmdArray = cmdString.split(' ');
      // console.log('exec 3: ' + cmdArray);
      for (var i = 0; i<cmdArray.length; i++) {
        if (hasSuBinary(cmdArray[i])) {
          reportCall('java.lang.Runtime', ['exec()', cmdString,
            dumpCallStack().join(', ')]);
          return runtime3.call(this, 'hello-avar');
        }
      }
      const rtValue = runtime3.call(this, cmdString);
      return rtValue;
    };
    runtime4.implementation = function(cmdString, envpArray) {
      // console.log('exec 4: ' + cmdString);
      const rtValue = runtime4.call(this, cmdString, envpArray);
      return rtValue;
    };
    runtime5.implementation = function(cmdArray, envpArray, file) {
      // console.log('exec 5: ' + cmdArray);
      const rtValue = runtime5.call(this, cmdArray, envpArray, file);
      return rtValue;
    };
    runtime6.implementation = function(cmdString, envpArray, file) {
      // console.log('exec 6: ' + cmdString);
      const rtValue = runtime6.call(this, cmdString, envpArray, file);
      return rtValue;
    };

    // hooking file existent checking
    // public boolean exists ()
    const ioFile = Java.use('java.io.File');
    ioFile.exists.implementation = function() {
      const filePath = this.path['value'];
      if (hasSuBinary(filePath)) {
        reportCall('java.io.File', ['exists', filePath, this.exists()]);
        return false;
      }
      return this.exists();
    };
    // int access(const char *path, int amode);
    Interceptor.attach(Module.findExportByName('libc.so', 'access'), {
      onEnter: function(args) {
        this.filename = Memory.readUtf8String(args[0]);
        this.mode = parseInt(args[1]);
      },
      onLeave: function(retval) {
        if (hasSuBinary(this.filename)) {
          reportCall('libc.so', ['access', this.filename, retval]);
          return -1;
        }
        return retval;
      },
    });
  });
});
