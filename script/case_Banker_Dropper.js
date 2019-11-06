/**
 * purpose: trigger time condition and reserve dropped file
 * article: https://pentest.blog/android-malware-analysis-dissecting-hydra-dropper/
 * @author Vash Hsu
 * @date September, 2019
 * sample: 46AEB04F2F03EBE7C716FC6E58A5DEA763CD9B00EB7A466D10A0744F50A7368F
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

const isInterestingPath = function(filePath) {
  if (filePath.endsWith('.jar') || filePath.endsWith('.dex')) {
    return true;
  }
  return false;
};

setImmediate(function() {
  Java.perform(function() {
    // to satisfiy trigger condition
    // java.util.Date.getTime()
    var javaDate = Java.use('java.util.Date');
    javaDate.getTime.implementation = function() {
      // new Date().getTime() >= 1553655180000L &&
      // new Date().getTime() <= 1554519180000L
      var mockValue = 1554087180000;
      const original = this.getTime();
      reportCall('util.Date', ['getTime', original, mockValue.toString()]);
      return mockValue;
    };
    var telMgr = Java.use('android.telephony.TelephonyManager');
    telMgr.getSimCountryIso.overload().implementation = function() {
      var mockValue = 'tr';
      const original = this.getSimCountryIso();
      reportCall('TelephonyManager', ['getSimCountryIso', original, mockValue]);
      return mockValue;
    };
  });

  // time_t time(time_t *tloc);
  var libcTime = Module.findExportByName('libc.so', 'time');
  var time = new NativeFunction(libcTime, 'long', ['long']);
  Interceptor.replace(libcTime, new NativeCallback(function() {
    var mockValue = 1554087180;
    const original = time(0);
    reportCall('libc.so', ['time', original.toString(), mockValue.toString()]);
    return mockValue;
  }, 'long', ['long']));

  // backup file
  const libcSystem = new NativeFunction(
      Module.findExportByName('libc.so', 'system'), 'int', ['pointer']
  );
  const system = function(stringCmd) {
    var buf = Memory.allocUtf8String(stringCmd);
    var result = libcSystem(buf);
    return result;
  };
  const backup2sdcard = function(filePath) {
    var outDir = '/traces/export/';
    system('cp \'' + filePath + '\' ' + outDir);
  };

  // C Library: unlink() and remove()
  var unlinkFptr = Module.findExportByName('libc.so', 'unlink');
  var unlink = new NativeFunction(unlinkFptr, 'int', ['pointer']);
  var removeFptr = Module.findExportByName('libc.so', 'remove');
  var remove = new NativeFunction(removeFptr, 'int', ['pointer']);
  // libc.so: int unlink(const char *path);
  Interceptor.replace(unlinkFptr, new NativeCallback(function(var0) {
    var filePath = Memory.readUtf8String(var0);
    if (isInterestingPath(filePath)) {
      backup2sdcard(filePath);
      reportCall('Demo', ['backup', filePath]);
    }
    var returnCode = unlink(var0);
    if (isInterestingPath(filePath)) {
      reportCall('libc.so', ['unlink', filePath, returnCode.toString()]);
    }
    return returnCode;
  }, 'int', ['pointer']));
  // libc.so: int remove(const char *path);
  Interceptor.replace(removeFptr, new NativeCallback(function(var0) {
    var filePath = Memory.readUtf8String(var0);
    if (isInterestingPath(filePath)) {
      backup2sdcard(filePath);
      reportCall('Demo', ['backup', filePath]);
    }
    var returnCode = remove(var0);
    if (isInterestingPath(filePath)) {
      reportCall('libc.so', ['remove', filePath, returnCode.toString()]);
    }
    return returnCode;
  }, 'int', ['pointer']));
});
