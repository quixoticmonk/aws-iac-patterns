'use strict';

const DEFAULT_OBJECT = 'index.html';

exports.handler = (event, context, callback) => {
  const cfrequest = event.Records[0].cf.request;
  if (cfrequest.uri.length > 0 && cfrequest.uri.charAt(cfrequest.uri.length - 1) === '/') {
    cfrequest.uri += DEFAULT_OBJECT;
  }
  else if (!cfrequest.uri.match(/.(css|md|gif|ico|jpg|jpeg|js|png|txt|svg|woff|ttf|map|json|html)$/)) {
    cfrequest.uri += `/${DEFAULT_OBJECT}`;
  }
  callback(null, cfrequest);
  return true;
};