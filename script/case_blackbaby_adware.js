/**
 * case study for aggressive adware: remote ad server checks imei at first place
 * hook point:
 *  > URL, connect, getInputStream
 *  > WebView.loadUrl
 *  > TelephonyManager.getDeviceId
 * @author Vash Hsu
 * @date September, 2019
 * sample: DE6706D324B667F2E7ED100D23D6B435651D55D49385790C5EF096BB222E6DA0
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
}

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
  const INTERNAL_STORAGE = getAppDataFolderPath();
  const filename = INTERNAL_STORAGE + filenamePrefix + '__' +
      Math.round(+new Date() % 10000) + '.raw';
  const file = new File(filename, 'w');
  file.write(bufferRaw);
  file.flush();
  file.close();
  return filename;
}

/**
 * Check if input URL is interesting enough to forther analysis
 * @param {urlString} urlString raw URL string, which might contain parameters
 * @return {boolean} true if it's interesting to do more analysis
 */
function isInteresting(urlString) {
  const prefix = ['http'];
  const postfix = ['\\.zip', '\\.jar', '\\.dex', '\\.so'];
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
  var rawString = '';
  for (var i = 0; i < bufferRaw.length; i++) {
    rawString += String.fromCharCode(((bufferRaw[i] % 256) + 256) % 256);
  }
  return rawString;
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
    // mock IMEI before host app performs checking with remote server
    const telManager = Java.use('android.telephony.TelephonyManager');
    telManager.getDeviceId.overload().implementation = function() {
      const original = this.getDeviceId();
      const overwriten = '123456789012347';
      /**
       * (split)  1 2 3 4 5  6 7  8 9 0 1 2 3 4
       * (double) 1 4 3 8 5 12 7 16 9 0 1 4 3 8
       * (sum)    1+4+3+8+5+1+2+7+1+6+9+0+1+4+3+8 = 63 - 70 = -7
       */
      reportCall('getDeviceId', ['moke', original, overwriten]);
      return overwriten;
    };

    // URL
    const netURL = Java.use('java.net.URL');
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

    // WebView.loadUrl
    const webView = Java.use('android.webkit.WebView');
    webView.loadUrl.overload('java.lang.String').implementation =
    function(var0) {
      const targetUrl = var0.toString();
      if (isInteresting(targetUrl)) {
        reportCall('WebView', ['loadUrl', targetUrl]);
      }
      this.loadUrl(var0);
    };
  });
});
