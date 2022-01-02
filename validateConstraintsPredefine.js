"use strict";

var _ = require("underscore");
var validate;
var constraints;


function createConstraints() {

    constraints = {};
    var sessionIdConstr = {
        "format": "^[a-f0-9]+$",
        "length": {
            is: 96
        }
    };

    var withServiceSessionIdConstr = {
        "format": "^[a-zA-Z0-9]+$",
        "length": {
            "minimum": 1,
            "maximum": 96
        }
    };

    constraints.sessionIdConstrOptional = sessionIdConstr;
    constraints.sessionIdConstrRequested = _.extend({ presence: true }, sessionIdConstr);

    constraints.controlPanelIDConstrOptional = sessionIdConstr;
    constraints.controlPanelIDConstrRequested = _.extend({ presence: true }, sessionIdConstr);

    constraints.settingsIDConstrOptional = sessionIdConstr;
    constraints.settingsIDConstrRequested = _.extend({ presence: true }, sessionIdConstr);

    constraints.loginTokenConstrOptional = sessionIdConstr;
    constraints.requestedLoginTokenConstr = _.extend({ presence: true }, sessionIdConstr);

    constraints.PlatformUIDConstrOptional = sessionIdConstr;
    constraints.requestedPlatformUIDConstr = _.extend({ presence: true }, sessionIdConstr);

    constraints.tokenConstrOptional = sessionIdConstr;
    constraints.tokenConstrRequested = _.extend({ presence: true }, sessionIdConstr);

    constraints.activationConstrOptional = sessionIdConstr;
    constraints.activationConstrRequested = _.extend({ presence: true }, sessionIdConstr);

    var excludeSpecialCharacters = {
        "format": "^([^<>'\"\/;`%!$&|]+|N\/A)$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.ExcludeSpecialCharactersOptional = excludeSpecialCharacters;
    constraints.ExcludeSpecialCharactersRequested = _.extend({ presence: true }, excludeSpecialCharacters);

    var intervalstr = {
        "format": "^[0-9\/ *]+$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.IntervalstrOptional = intervalstr;
    constraints.IntervalstrRequested = _.extend({ presence: true }, intervalstr);

    var IndexConstr = {
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: 0
        }
    };

    constraints.IndexConstrOptional = IndexConstr;
    constraints.IndexConstrRequested = _.extend({ presence: true }, IndexConstr);

    constraints.NaturalNumberConstrOptional = IndexConstr;
    constraints.NaturalNumberConstrRequested = _.extend({ presence: true }, IndexConstr);

    var portNumberConstr = {
        numericality: {
            onlyInteger: true,
            greaterThan: 0,
            lessThanOrEqualTo: 65536
        }
    };

    constraints.portNumberConstrOptional = portNumberConstr;
    constraints.portNumberConstrRequested = _.extend({ presence: true }, portNumberConstr);

    var ipConstr = {
        format: {
            pattern: "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        }
    };

    constraints.ipConstrOptional = ipConstr;
    constraints.ipConstrRequested = _.extend({ presence: true }, ipConstr);

    var CIDRMaskConstr = {
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: 0,
            lessThanOrEqualTo: 32
        }
    }

    constraints.CIDRMaskConstrOptional = CIDRMaskConstr;
    constraints.CIDRMaskConstrRequested = _.extend({ presence: true }, CIDRMaskConstr);


    var boolConstr = {
        inclusion: {
            within: [true, false, "true", "false"]
        }
    };

    constraints.boolConstrOptional = boolConstr;
    constraints.boolConstrRequested = _.extend({ presence: true }, boolConstr);

    var hostConstr = {
        format: "^[.a-zA-Z0-9\\-_]+$",
        length: {
            "minimum": 1,
            "maximum": 255
        }
    };
    constraints.hostConstrOptional = hostConstr;
    constraints.hostConstrRequested = _.extend({ presence: true }, hostConstr);

    var pathConstr = {
        path: {},
        length: {
            "minimum": 1,
            "maximum": 1000
        }
    };

    constraints.pathConstrOptional = pathConstr;
    constraints.pathConstrRequested = _.extend({ presence: true }, pathConstr);

    var mediaStreamConstr = {
        mediaStream: {},
        length: {
            "minimum": 1,
            "maximum": 1000
        }
    };
    constraints.mediaStreamRequested = _.extend({ presence: true }, mediaStreamConstr);


    var deviceIdConstr = {
        "format": "^[.a-zA-Z0-9@_\\-]+$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.deviceIdConstrOptional = deviceIdConstr;
    constraints.deviceIdConstrRequested = _.extend({ presence: true }, deviceIdConstr);

    var packageNameConstr = {
        "format": "^(shared:)?[.a-zA-Z0-9_]+[a-zA-Z0-9_]$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.packageNameConstrOptional = packageNameConstr;
    constraints.packageNameConstrRequested = _.extend({ presence: true }, packageNameConstr);

    var emailConstr = {
        "email": true
    };

    constraints.emailConstrOptional = emailConstr;
    constraints.emailConstrRequested = _.extend({ presence: true }, emailConstr);

    var platIdConstr = {
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: 0,
            lessThanOrEqualTo: 9999
        }
    };

    constraints.platIdConstrOptional = platIdConstr;
    constraints.platIdConstrRequested = _.extend({ presence: true }, platIdConstr);

    var appIdConstr = {
        numericality: {
            onlyInteger: true,
            greaterThanOrEqualTo: -1,
            lessThanOrEqualTo: 10
        }
    };

    constraints.appIdConstrConstrOptional = appIdConstr;
    constraints.appIdConstrConstrRequested = _.extend({ presence: true }, appIdConstr);

    var passcodeConstr = {
        "format": "^[^ \t\r\n\v\f]+$", //Non-whitespace characters
        "length": {
            "minimum": 1,
            "maximum": 1024
        }
    };

    constraints.passcodeConstrOptional = passcodeConstr;
    constraints.passcodeConstrRequested = _.extend({ presence: true }, passcodeConstr);

    var adDomainNameConstr = {
        format: "^([.a-zA-Z0-9_\\-]+|N\/A)$",
        length: {
            minimum: 1,
            maximum: 255
        }
    };

    constraints.adDomainNameConstrOptional = adDomainNameConstr;
    constraints.adDomainNameConstrRequested = _.extend({ presence: true }, adDomainNameConstr);

    var phoneNumberConstr = {
        "format": "^([0-9\\\-()\+ *]+|N\/A|NULL)$",
        "length": {
            "minimum": 2,
            "maximum": 20
        }
    };

    constraints.phoneNumberConstrOptional = phoneNumberConstr;
    constraints.phoneNumberConstrRequested = _.extend({ presence: true }, phoneNumberConstr);

    var timeZoneConstr = {
        format: "^[a-zA-Z0-9/_\\-+]+$",
        length: {
            minimum: 1,
            maximum: 255
        }
    };

    constraints.timeZoneConstrOptional = timeZoneConstr;
    constraints.timeZoneConstrRequested = _.extend({ presence: true }, timeZoneConstr);

    var timeStampConstr = {
        format: "^[ A-Z0-9:\\-.]+$",
        length: {
            minimum: 1,
            maximum: 255
        }
    };

    constraints.timeStampConstrOptional = timeStampConstr;
    constraints.timeStampConstrRequested = _.extend({ presence: true }, timeStampConstr);

    var playerVersionConstr = {
        "format": "^[.0-9a-zA-Z\\-]+$",
        "length": {
            "minimum": 3,
            "maximum": 255
        }
    }

    constraints.playerVersionConstrOptional = playerVersionConstr;
    constraints.playerVersionConstrRequested = _.extend({ presence: true }, playerVersionConstr);

    var userNameConstr = {
        "format": "^[.0-9a-zA-Z\\\-@_\/ ]+$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    }

    constraints.userNameConstrOptional = userNameConstr;
    constraints.userNameConstrRequested = _.extend({ presence: true }, userNameConstr);

    var packageUIDConstr = {
        numericality: {
            onlyInteger: true,
            greaterThan: 0,
            lessThan: 99999
        }
    }

    constraints.packageUIDConstrOptional = packageUIDConstr;
    constraints.packageUIDConstrRequested = _.extend({ presence: true }, packageUIDConstr);

    var binaryBoolConstr = {
        inclusion: {
            within: ["0", "1", 0, 1]
        }
    };

    constraints.binaryBoolConstrOptional = binaryBoolConstr;
    constraints.binaryBoolConstrRequested = _.extend({ presence: true }, binaryBoolConstr);

    var Y_N_boolConstr = {
        inclusion: {
            within: ["Y", "N"]
        }
    };

    constraints.Y_N_boolConstrOptional = Y_N_boolConstr;
    constraints.Y_N_boolConstrRequested = _.extend({ presence: true }, Y_N_boolConstr);

    var openTextConstr = {
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    }

    constraints.openTextConstrOptional = openTextConstr;
    constraints.openTextConstrRequested = _.extend({ presence: true }, openTextConstr);

    var dateConstr = {
        "nuboDate": {}
    };

    constraints.dateConstrOptional = dateConstr;
    constraints.dateConstrRequested = _.extend({ presence: true }, dateConstr);

    var urlConstr = {
        url: {
            allowLocal: true,
            schemes: [".+"]
        }
    };

    constraints.urlConstrOptional = urlConstr;
    constraints.urlConstrRequested = _.extend({ presence: true }, urlConstr);


    var serverUrlConstr = {
        "format": "^[.a-zA-Z0-9_\\-]+$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.serverUrlConstrOptional = serverUrlConstr;
    constraints.serverUrlConstrRequested = _.extend({ presence: true }, serverUrlConstr);

    var freeField = {
        "format": "^([^<>\/;`%!$&|]+|N\/A)$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.freeFieldOptional = freeField;
    constraints.freeFieldRequested = _.extend({ presence: true }, freeField);

    var withServiceAllowedChars = {
        "format": "^([\\\\=,:+.a-zA-Z0-9\\-\@\_\'\" \u05BE\u05d0-\u05EA\u05F3\u05F4]+|N\/A|NULL)$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    var withServicePassword = {
        "format": "^[:\\-a-zA-Z0-9@#$&!]+$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    var subscriptionID = {
        "format": "^([\+\/=a-zA-Z0-9]+|-1)$",
        "length": {
            "minimum": 1,
            "maximum": 255
        }
    };

    constraints.subscriptionIDOptional = subscriptionID;
    constraints.subscriptionIDRequested = _.extend({ presence: true }, subscriptionID);

    var float = {
        numericality: {}
    };

    constraints.floatOptional = float;
    constraints.floatRequested = _.extend({ presence: true }, float);


    validate.validators.array = function (value, options, key, attributes) {
        var itemConstraint = _.extend({}, options);
        var arr;
        if (validate.isArray(value)) {
            arr = value;
        } else {
            arr = [value];
        }

        var totalRes = {};
        arr.forEach(function (val, index) {
            var ent = {};
            var constr = {};
            if (typeof val === "object") {
                ent = val;
                constr = itemConstraint;
            } else {
                ent[index] = val;
                constr[index] = itemConstraint;
            }
            var res = validate(ent, constr);
            if (res) totalRes[index] = res;
        });
        return validate.isEmpty(totalRes) ? undefined : totalRes;
    };

    validate.validators.isArray = function (value, options, key, attributes) {
        if (validate.isArray(value)) {
            return undefined;
        } else {
            return "is not array";
        }
    };

    validate.validators.path = function (value, options, key, attributes) {
        if (!value) {
            return undefined;
        }

        //var legalChars = (/^[a-zA-Z0-9\/@\-_()\ ,.]+$/).test(value);
        var pathManipulation = (/^.*[.]{2}.*$/).test(value);

        if (/*legalChars && */!pathManipulation) {
            return undefined;
        }
        else {
            return "illegal"
        }
    };

    validate.validators.mediaStream = function (value, options, key, attributes) {
        if (!value) {
            return undefined;
        }

        var legalChars = (/^[a-zA-Z0-9\-\.\_\:\,\/\?\&\=]+$/).test(value);
        var pathManipulation = (/^.*[.]{2}.*$/).test(value);

        if (legalChars && !pathManipulation) {
            return undefined;
        }
        else {
            return "illegal"
        }
    };

    validate.validators.nuboDate = function (value, options, key, attributes) {
        if (!value) {
            return undefined;
        }

        var legalChars = (/^[.0-9a-zA-Z\-()\+ :]{0,255}$/).test(value);

        if (legalChars) {
            return undefined;
        }
        else {
            return "illegal date"
        }
    };

    validate.validators.buffer = function (value, options, key, attributes) {
        var validateConstraint = _.extend({}, options);
        var bufferToString;

        if (value) {
            if (Buffer.isBuffer(value)) {
                bufferToString = value.toString();
            }
            else {
                return "not a buffer type"
            }
        }

        var res = validate.single(bufferToString, validateConstraint);

        if (res) {
            return res;
        }
        else {
            return undefined;
        }
    };
    return constraints;
}

module.exports = function (withValidateJS) {
    if (constraints) {
        return constraints;
    }
    if (withValidateJS) {
        validate = withValidateJS;
    } else {
        validate = require("validate.js");
    }
    return createConstraints();
}

