var argscheck = require('cordova/argscheck'),
    exec = require('cordova/exec'),
    KeychainUnlock = {
    available: function(successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "isAvailable", []);
    },
    save: function(key,password, userAuthenticationRequired, successCallback, errorCallback) {
        exec(successCallback, errorCallback, "TouchID", "save", [key,password, userAuthenticationRequired]);
    },
    verify: function(key,message,label,successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "verify", [key,message,label]);
    },
    has: function(key,successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "has", [key]);
    },
    delete: function(key,successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "delete", [key]);
    },
    setLocale: function(locale,successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "setLocale", [locale]);
    },
    move: function(key, packageName,successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "move", [key,packageName]);
    }
    password: function(message,packageName,successCallback, errorCallback){
        exec(successCallback, errorCallback, "TouchID", "askPassword", [message,packageName]);
    }
};

module.exports = KeychainUnlock;
