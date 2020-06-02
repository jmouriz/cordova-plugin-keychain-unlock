var argscheck = require('cordova/argscheck'),
    exec = require('cordova/exec'),
    KeychainUnlock = {
    available: function(success, error) {
        exec(success, error, 'KeychainUnlock', 'available', []);
    },
    save: function(key, password, success, error) {
        exec(success, error, 'KeychainUnlock', 'save', [key, password]);
    },
    verify: function(key, message, success, error) {
        exec(success, error, 'KeychainUnlock', 'verify', [key, message]);
    },
    has: function(key, success, error) {
        exec(success, error, 'KeychainUnlock', 'has', [key]);
    },
    delete: function(key, success, error) {
        exec(success, error, 'KeychainUnlock', 'delete', [key]);
    }
};

module.exports = KeychainUnlock;
