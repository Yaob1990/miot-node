class DeviceNotFound extends Error {
  constructor(deviceId:string, country:string) {
    super(`The device with id ${deviceId} was not found in your MiCloud account on the ${country} server! Please make sure that the specified MiCloud account and country is correct!`);
  }
}

class DeviceNotOnline extends Error {
  constructor(deviceId:string) {
    super(`The device with id ${deviceId} is not online!`);
  }
}

class MissingDeviceId extends Error {
  constructor(name:string) {
    super(`Missing deviceId for ${name}! Deviceid is required for a cloud connection! Please specify a deviceId in the 'config.json' file in order to control the device!`);
  }
}

class MissingMiCloudCredentials extends Error {
  constructor() {
    super(`Missing information required to connect to the MiCloud! Please specify a MiCloud username and password!`);
  }
}

class TwoFactorRequired extends Error {
  private notificationUrl: string;
  constructor(notificationUrl:string) {
    super('Two factor authentication required, please visit the following url and retry login: ' + notificationUrl);
    this.notificationUrl = notificationUrl;
  }
}

class UnknownDeviceModel extends Error {
  constructor() {
    super(`Could not identify the device model!`);
  }
}

export { DeviceNotFound, DeviceNotOnline, MissingDeviceId, MissingMiCloudCredentials, TwoFactorRequired, UnknownDeviceModel };
