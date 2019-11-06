/**
 * to demo how Frida can inject code to inspect and replace payload
 * within javax.crypto encryption and decryption
 * @author Vash Hsu
 * @date September, 2019
 * @sample: 888E9A34A076B6F765F6FB3B54C885CFA3AB716CCF82A6CC56D057611A740932
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

/**
 * Check if input buffer is interesting enough to backup
 * @param {array} bufferRaw raw data from memory
 * @return {boolean} true if it has magic signature interesting
 */
function isInteresting(bufferRaw) {
  const prefix = ['PK', // zip, aar, jar, apk
    'SQLite', // SQLite Database
    'BZh', // Bzip2
    'LZIP', // Lzip
    '7z', // 7z
  ];
  const magicBytes = bufferRaw.slice(0, 7).toString(); // top 6 chars only
  for (var i = 0; i<prefix.length; i++) {
    if (magicBytes.startsWith(prefix[i])) {
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
  var bufferString = '';
  for (var i = 0; i < bufferRaw.length; i++) {
    bufferString += String.fromCharCode(((bufferRaw[i] % 256) + 256) % 256);
  }
  return bufferString;
}

/**
 * Convert inputed buffer/string to ASCII string, with . if not ASCII
 * @param {array} bufferString binary data in string
 * @return {string} printable string
 */
function dumpRaw2Ascii(bufferString) {
  const asciiString = bufferString.split('').
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
  return asciiString;
}

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

/**
 * Accourmulate and store payload, clenaup while isReset is true
 * @param {BinaryType} inputRawBytes raw data from memory
 * @param {BinaryType} cookingArray buffer to accumulate incoming byte
 * @param {number} offset size of current buffor sotred
 * @param {boolean} isReset clean-up internally while true
 * @return {integer} size of buffer after storing
 */
function capturePayload(inputRawBytes, cookingArray, offset, isReset) {
  if (isReset === true) {
    cookingArray = [];
    return 0;
  } else {
    for (var i = 0; i < inputRawBytes.length; i++) {
      cookingArray[offset] = inputRawBytes[i];
      offset = offset + 1;
    }
  }
  return offset;
}

setImmediate(function() {
  Java.perform(function() {
    /**
     * Dump raw buffer to external storage
     * @param {string} filenamePrefix prefix of new filename
     * @param {string} filenameMiddle subtype string in filename
     * @param {byteArray} bufferRaw array of raw data to save
     * @return {string} path of file containing input data
     */
    function dumpRaw2Storage(filenamePrefix, filenameMiddle, bufferRaw) {
      // get base folder at rum time
      const currentApp = Java.use('android.app.ActivityThread').
          currentApplication();
      const context = currentApp.getApplicationContext();
      const packageName = context.getPackageName();
      const baseFolder = ['/data/data', packageName].join('/') + '/';
      // name file in form of 'prefix__middle__9999__size.raw'
      const filename = filenamePrefix + '__' +
          filenameMiddle + '__' + Math.round(+new Date() % 10000) + '__' +
          bufferRaw.length + '.raw';
      const fileHandler = new File(baseFolder + filename, 'wb');

      for (var i = 0; i < bufferRaw.length; i++) {
        var charChar= String.fromCharCode(bufferRaw[i]);
        if (parseInt(charChar, 2).toString(10) == 0) {
          fileHandler.write([0]);
        } else {
          fileHandler.write(charChar);
        }
      }
      fileHandler.flush();
      fileHandler.close();
      //
      return baseFolder + filename;
    }

    // Javax Crypto
    // var javaxSecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    // var javaxIvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    const jxCipher = Java.use('javax.crypto.Cipher');
    var offset = 0;
    var buffer = [];
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
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1, var2);
    };
    cipherInit2.implementation = function(var0, var1, var2) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1, var2);
    };
    cipherInit3.implementation = function(var0, var1, var2) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1, var2);
    };
    cipherInit4.implementation = function(var0, var1, var2) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1, var2);
    };
    cipherInit5.implementation = function(var0, var1) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1);
    };
    cipherInit6.implementation = function(var0, var1, var2, var3) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1, var2, var3);
    };
    cipherInit7.implementation = function(var0, var1) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1);
    };
    cipherInit8.implementation = function(var0, var1, var2, var3) {
      mode = parseInt(var0);
      reportCall('Crypto', ['Cipher init', getCipherOpType(mode)]);
      return this.init(var0, var1, var2, var3);
    };

    const cipherDoFinalv1 = jxCipher.doFinal.overload();
    const cipherDoFinalv2 = jxCipher.doFinal.overload('[B');
    const cipherDoFinalv3 = jxCipher.doFinal.overload('[B', 'int');
    const cipherDoFinalv4 = jxCipher.doFinal.overload('[B', 'int', 'int');
    const cipherDoFinalv5 = jxCipher.doFinal.overload('[B', 'int', 'int', '[B');
    const cipherDoFinalv6 = jxCipher.doFinal.overload('[B', 'int', 'int', '[B',
        'int');

    const cipherUpdatev1 = jxCipher.update.overload('[B');
    const cipherUpdatev2 = jxCipher.update.overload('[B', 'int', 'int');
    const cipherUpdatev3 = jxCipher.update.overload('[B', 'int', 'int', '[B');
    const cipherUpdatev4 = jxCipher.update.overload('[B', 'int', 'int', '[B',
        'int');

    const secretInspect = function(handle, source, destination) {
      const sourceInString = binaryToString(source);
      const destInString = binaryToString(destination);
      const modeInString = getCipherOpType(mode);
      if (mode === 1) { // Encrypt
        if (isInteresting(sourceInString)) {
          const savedFilename = dumpRaw2Storage('payload', modeInString,
              source);
          reportCall('Cipher', [modeInString, 'saving to',
            sourceInString.length, savedFilename]);
          reportCall('Cipher', [modeInString, 'in ASCII', sourceInString.length,
            dumpRaw2Ascii(sourceInString)]);
        }
      } else { // Decrypt and others //if (isInteresting(destInString)) {
        const savedFilename = dumpRaw2Storage('payload', modeInString,
            destination);
        reportCall('Crypto', [modeInString, 'saving to', destInString.length,
          savedFilename]);
        reportCall('Crypto', [modeInString, 'in ASCII', destInString.length,
          dumpRaw2Ascii(destInString)]);
      }
      offset = capturePayload(null, buffer, 0, true);
    };

    cipherDoFinalv1.implementation = function() {
      const ret = cipherDoFinalv1.call(this);
      secretInspect(this, buffer, ret);
      return ret;
    };

    cipherDoFinalv2.implementation = function(var0) {
      offset = capturePayload(var0, buffer, offset, false);
      const ret = cipherDoFinalv2.call(this, var0);
      secretInspect(this, buffer, ret);
      return ret;
    };

    cipherDoFinalv3.implementation = function(var0, var1) {
      offset = capturePayload(var0, buffer, offset, false);
      const ret = cipherDoFinalv3.call(this, var0, var1);
      secretInspect(this, buffer, ret);
      return ret;
    };

    cipherDoFinalv4.implementation = function(var0, var1, var2) {
      offset = capturePayload(var0, buffer, offset, false);
      const ret = cipherDoFinalv4.call(this, var0, var1, var2);
      secretInspect(this, buffer, ret);
      return ret;
    };

    cipherDoFinalv5.implementation = function(var0, var1, var2, var3) {
      offset = capturePayload(var0, buffer, offset, false);
      const ret = cipherDoFinalv5.call(this, var0, var1, var2, var3);
      secretInspect(this, buffer, ret);
      return ret;
    };

    cipherDoFinalv6.implementation = function(var0, var1, var2, var3, var4) {
      offset = capturePayload(var0, buffer, offset, false);
      const ret = cipherDoFinalv6.call(this, var0, var1, var2, var3, var4);
      secretInspect(this, buffer, ret);
      return ret;
    };

    cipherUpdatev1.implementation = function(var0) {
      offset = capturePayload(var0, buffer, offset, false);
      return cipherUpdatev1.call(this, var0);
    };

    cipherUpdatev2.implementation = function(var0, var1, var2) {
      offset = capturePayload(var0, buffer, offset, false);
      return cipherUpdatev2.call(this, var0, var1, var2);
    };

    cipherUpdatev3.implementation = function(var0, var1, var2, var3) {
      offset = capturePayload(var0, buffer, offset, false);
      return cipherUpdatev3.call(this, var0, var1, var2, var3);
    };

    cipherUpdatev4.implementation = function(var0, var1, var2, var3, var4) {
      offset = capturePayload(var0, buffer, offset, false);
      return cipherUpdatev4.call(this, var0, var1, var2, var3, var4);
    };
  });
});