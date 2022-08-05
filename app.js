const { createHmac } = require('crypto');

const secret = process.env.secret;

exports.handler = async function (event, context) {
  if (verifySignature(event, secret)) {
    console.log(JSON.stringify(event));
  } else {
    console.error('Invalid signature');
  }
  return context.logStreamName;
}

function verifySignature(event, secret) {
  const hmac = createHmac('sha256', secret);
  const buffer = JSON.stringify(JSON.parse(event.body));
  hmac.update(buffer, 'utf8');

  const signature = `sha256=${hmac.digest('hex')}`;
  console.log('Received signature: ', event.headers['x-hub-signature']);
  console.log('Calculated signature: ', signature);

  return signature === event.headers['x-hub-signature'];
}