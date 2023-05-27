import Logger from '../utils/Logger';
import MiCloud from '../protocol/MiCloud';

describe('test', () => {
  test('控制台灯', async () => {
    const miCloud = new MiCloud(new Logger());
    // 通过方法设置，注意这里参数是 aiid，不需要进一步的参数
    miCloud
      .miotAction({ did: '', siid: '', aiid: '' })
      .then((devices) => {
        console.log(JSON.stringify(devices));
      })
      .catch((err) => {
        console.log(err);
      });
  });
});
