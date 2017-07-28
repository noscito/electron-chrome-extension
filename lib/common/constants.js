const constants = {};

// chrome.tabs
constants.TABS_ONCREATED = 'CHROME_TABS_ONCREATED';
constants.TABS_ONREMOVED = 'CHROME_TABS_ONREMOVED';

// chrome.webNavigation
constants.WEBNAVIGATION_ONBEFORENAVIGATE = 'CHROME_WEBNAVIGATION_ONBEFORENAVIGATE';
constants.WEBNAVIGATION_ONCOMPLETED = 'CHROME_WEBNAVIGATION_ONCOMPLETED';

// chrome.runtime.connect
constants.PORT_DISCONNECT_ = 'CHROME_PORT_DISCONNECT_';
constants.RUNTIME_ONCONNECT_ = 'CHROME_RUNTIME_ONCONNECT_';
constants.RUNTIME_CONNECT = 'CHROME_RUNTIME_CONNECT';
constants.PORT_POSTMESSAGE_ = 'CHROME_PORT_POSTMESSAGE_';

// chrome.i18n.getMessage
constants.I18N_MANIFEST = 'CHROME_I18N_MANIFEST';

// chrome.runtime.sendMessage
constants.RUNTIME_SENDMESSAGE = 'CHROME_RUNTIME_SENDMESSAGE';
constants.RUNTIME_ONMESSAGE_ = 'CHROME_RUNTIME_ONMESSAGE_';

// chrome.runtime.onMessage
constants.RUNTIME_ONMESSAGE_RESULT_ = 'CHROME_RUNTIME_ONMESSAGE_RESULT_';
constants.RUNTIME_SENDMESSAGE_RESULT_ = 'CHROME_RUNTIME_SENDMESSAGE_RESULT_';

// chrome.tabs.executeScript
constants.TABS_SEND_MESSAGE = 'CHROME_TABS_SEND_MESSAGE';
constants.TABS_SEND_MESSAGE_RESULT_ = 'CHROME_TABS_SEND_MESSAGE_RESULT_';

// chrome.tabs.executeScript
constants.TABS_EXECUTESCRIPT = 'CHROME_TABS_EXECUTESCRIPT';
constants.TABS_EXECUTESCRIPT_RESULT_ = 'CHROME_TABS_EXECUTESCRIPT_RESULT_';


// to differentiate fron electron implentation of chrome extensions
// we change the name of ipc  channel used
const overridenConstants = {};
Object.keys(constants).forEach(constantKey => {
  overridenConstants[constantKey] = `XX_${constants[constantKey]}`;
})

// module.exports = constants;
module.exports = overridenConstants;