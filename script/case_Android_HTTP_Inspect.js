/**
 * to demo how Frida can inject code to inspect and replace payload
 * within http/https response
 * @author Vash Hsu
 * @date September, 2019
*/

// const INTERNAL_STORAGE = '/sdcard/Download/';

/**
 * Get path info of app's internal storage
 * @return {string} path of app's local storage, starting with /data/data/
 */
function getAppDataFolderPath() {
  const currentApp = Java.use('android.app.ActivityThread').
      currentApplication();
  const context = currentApp.getApplicationContext();
  const packageName = context.getPackageName();
  return ['/data/data', packageName].join('/') + '/';
}

/**
 * Dump raw buffer to external storage
 * @param {string} filenamePrefix prefix of new filename
 * @param {array} bufferRaw array of raw data to save
 * @return {string} path of file containing input data
 */
function dumpRaw2Storage(filenamePrefix, bufferRaw) {
  if (typeof INTERNAL_STORAGE === 'undefined') {
    const INTERNAL_STORAGE = getAppDataFolderPath();
  }
  const filename = INTERNAL_STORAGE + filenamePrefix + '__' +
      Math.round(+new Date() % 10000) + '.raw';
  const file = new File(filename, 'w');
  file.write(bufferRaw);
  file.flush();
  file.close();
  return filename;
};

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

/**
 * Check if input URL is interesting enough to forther analysis
 * @param {urlString} urlString raw URL string, which might contain parameters
 * @return {boolean} true if it's interesting to do more analysis
 */
function isInteresting(urlString) {
  const prefix = ['http', 'ftp'];
  const postfix = ['\\.zip', '\\.jar', '\\.dex', '\\.so', '\\.sh'];
  const urlCaseLess = urlString.toLocaleLowerCase();
  var i=0;
  for (i=0; i<prefix.length; i++) {
    if (urlCaseLess.startsWith(prefix[i])) {
      return true;
    }
  }
  for (i=0; i<postfix.length; i++) {
    if (urlCaseLess.endsWith(postfix[i])) {
      return true;
    }
  }
  return false;
}

/**
 * Convert inputed binary array to string
 * @param {ArrayBuffer} bufferRaw raw data
 * @return {string} javascript string
 */
function binaryToString(bufferRaw) {
  var cooking = '';
  for (var i = 0; i < bufferRaw.length; i++) {
    cooking += String.fromCharCode(((bufferRaw[i] % 256) + 256) % 256);
  }
  return cooking;
}

/**
 * Convert inputed buffer/string to ASCII string, with . if not ASCII
 * @param {array} buffer raw data waiting for convertig via ASCII
 * @return {string} printable string
 */
function dumpRaw2Ascii(buffer) {
  const codes = binaryToString(buffer).split('').
      map(function(char) {
        const numOfCode = parseInt(char.charCodeAt(0));
        // 32: x20, space
        // 126 x7E, ~
        if (numOfCode < 32 || numOfCode > 126) {
          return '.';
        } else {
          return char;
        }
      }).join('');
  return codes;
}

/**
 * Accourmulate and store payload, clenaup while isReset is true
 * @param {byte} charByte raw data waiting for convertig via ASCII
 * @param {array} cookingArray buffer to accumulate incoming byte
 * @param {integer} offset size of current buffor sotred
 * @param {boolean} isReset clean-up internally while true
 * @return {integer} size of buffer after storing
 */
function insertPayload(charByte, cookingArray, offset, isReset) {
  if (isReset === true) {
    cookingArray = [];
    return 0;
  } else {
    cookingArray[offset] = charByte;
    return (offset + 1);
  }
}

setImmediate(function() {
  Java.perform(function() {
    // URL and WebView
    const netURL = Java.use('java.net.URL');
    const webView = Java.use('android.webkit.WebView');
    const httpURLConnection = Java.use(
        'com.android.okhttp.internal.huc.HttpURLConnectionImpl');
    const byteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
    const byteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    // new URL()
    netURL.$init.overload('java.lang.String').implementation = function(var0) {
      const targetUrl = var0.toString();
      if (isInteresting(targetUrl)) {
        reportCall('URL', ['init', targetUrl]);
      }
      return this.$init(var0);
    };
    // WebView.loadUrl
    webView.loadUrl.overload('java.lang.String').implementation =
    function(var0) {
      const targetUrl = var0.toString();
      if (isInteresting(targetUrl)) {
        reportCall('WebView', ['loadUrl', targetUrl]);
      }
      this.loadUrl(var0);
    };
    // URLConnection.connect
    httpURLConnection.connect.implementation = function() {
      const targetUrl = this.getURL().toString();
      if (isInteresting(targetUrl)) {
        reportCall('Connection', ['connect', targetUrl]);
      }
      this.connect();
    };
    // URLConnection.getInputStream
    httpURLConnection.getInputStream.implementation = function() {
      const targetUrl = this.getURL().toString();
      if (isInteresting(targetUrl)) {
        const inputS = this.getInputStream();
        const outputS = byteArrayOutputStream.$new();
        var byteRaw = inputS.read();
        const bodyRaw = [];
        var offset = 0;
        while (byteRaw > -1) {
          outputS.write(byteRaw);
          offset = insertPayload(byteRaw, bodyRaw, offset, false);
          byteRaw = inputS.read();
        }
        // i.e. 'Connection' 'getInputStream' 'http://www....'
        //      'body size' '<html> ...', '/sdcard/Download/payload...'
        const savedFilename = dumpRaw2Storage('payload', bodyRaw);
        reportCall('Connection', ['getInputStream', targetUrl, offset,
          dumpRaw2Ascii(bodyRaw), savedFilename]);
        insertPayload(null, bodyRaw, 0, true); // cleanup
        inputS.close();
        outputS.write(0);
        outputS.flush();
        return byteArrayInputStream.$new(outputS.toByteArray());
      } else {
        return this.getInputStream();
      }
    };
  });
});
