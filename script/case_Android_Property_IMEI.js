/**
 * to demo how Frida can modify IMEI (androidID) on the fly
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

setImmediate(function() {
  Java.perform(function() {
    /*
    android.telephony.TelephonyManager
    > getNetworkOperatorName()
    > getSimOperatorName()
    > getDeviceId()
    */
    const telManager = Java.use('android.telephony.TelephonyManager');
    telManager.getNetworkOperatorName.overload().implementation = function() {
      const original = this.getNetworkOperatorName();
      const overwriten = 'Frida';
      reportCall('getNetworkOperatorName', ['moke', original, overwriten]);
      return overwriten;
    };

    telManager.getSimOperatorName.overload().implementation = function() {
      const original = this.getSimOperatorName();
      const overwriten = 'Frida';
      reportCall('getSimOperatorName', ['moke', original, overwriten]);
      return overwriten;
    };

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
  });
});
