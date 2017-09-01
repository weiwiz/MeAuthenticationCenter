/**
 * Created by jacky on 2017/2/4.
 */
'use strict';
var logger = require('./../mlogger/mlogger');
var _ = require('lodash');
var util = require('util');
var nodeUuid = require("node-uuid");

var VirtualDevice = require('./../virtual-device').VirtualDevice;
var TIMR_OUT = 1000*60*60*24;
var USER_TYPE_ID = '060A08000000';
var OPERATION_SCHEMAS = {
    "login": {
        "type": "object",
        "properties": {
            "userName": {"type": "string"},
            "password": {"type": "string"}
        },
        "required": ["userName", "password"]
    },
    "checkToken": {
        "type": "object",
        "properties": {
            "token": {"type": "string"}
        },
        "required": ["token"]
    }
};
function AuthenticationCenter(conx, uuid, token, configurator) {
    VirtualDevice.call(this, conx, uuid, token, configurator);
}
util.inherits(AuthenticationCenter, VirtualDevice);

/**
 * 远程RPC回调函数
 * @callback onMessage~login
 * @param {object} response:
 * {
 *      "payload":
 *      {
 *          "retCode":{string},
 *          "description":{string},
 *          "data":{object}
 *      }
 * }
 */
/**
 * 用户登录验证
 * @param {object} message:输入消息
 * @param {onMessage~login} peerCallback: 远程RPC回调
 * */
AuthenticationCenter.prototype.login = function (message, peerCallback) {
    var self = this;
    logger.warn(message);
    var responseMessage = {retCode: 200, description: "Success.", data: {}};
    self.messageValidate(message, OPERATION_SCHEMAS.login, function (error) {
        if (error) {
            responseMessage = error;
            peerCallback(error);
        }
        else {
            var getDevice = {
                devices: self.configurator.getConfRandom("services.device_manager"),
                payload: {
                    cmdName: "getDevice",
                    cmdCode: "0003",
                    parameters: {
                        "type.id": USER_TYPE_ID,
                        "extra.phoneNumber": message.userName
                    }
                }
            };
            self.message(getDevice, function (response) {
                if (response.retCode !== 200) {
                    logger.error(response.retCode, response.description);
                    responseMessage.retCode = response.retCode;
                    responseMessage.description = response.description;
                    peerCallback(responseMessage);
                }
                else {
                    var deviceInfo = response.data[0];
                    if (deviceInfo.extra && deviceInfo.extra.password === message.password) {
                        var authToken = nodeUuid.v4();
                        var updateDevice = {
                            devices: self.configurator.getConfRandom("services.device_manager"),
                            payload: {
                                cmdName: "deviceUpdate",
                                cmdCode: "0004",
                                parameters: {
                                    "uuid": deviceInfo.uuid,
                                    "extra.authToken": {
                                        token: authToken,
                                        timestamp: Date.now()
                                    }
                                }
                            }
                        };
                        self.message(updateDevice, function (response) {
                            if (response.retCode !== 200) {
                                logger.error(response.retCode, response.description);
                                responseMessage.retCode = response.retCode;
                                responseMessage.description = response.description;
                            }
                            else {
                                responseMessage.data = {token: deviceInfo.uuid + "_" + authToken};
                            }
                            peerCallback(responseMessage);
                        });
                    }
                    else {
                        responseMessage.retCode = 205001;
                        responseMessage.description = logger.getErrorInfo(responseMessage.retCode);
                        peerCallback(responseMessage);
                    }
                }
            });
        }
    });
};

/**
 * 远程RPC回调函数
 * @callback onMessage~checkToken
 * @param {object} response:
 * {
 *      "payload":
 *      {
 *          "retCode":{string},
 *          "description":{string},
 *          "data":{object}
 *      }
 * }
 */
/**
 * 验证用户token有效性
 * @param {object} message:输入消息
 * @param {onMessage~checkToken} peerCallback: 远程RPC回调
 * */
AuthenticationCenter.prototype.checkToken = function (message, peerCallback) {
    var self = this;
    logger.info("checkToken", message);
    var responseMessage = {retCode: 200, description: "Success.", data: {}};
    self.messageValidate(message, OPERATION_SCHEMAS.checkToken, function (error) {
        if (error) {
            responseMessage = error;
            peerCallback(error);
        }
        else {
            var array = message.token.split("_");
            var deviceUuid = array[0];
            var token = array[1];
            var getDevice = {
                devices: self.configurator.getConfRandom("services.device_manager"),
                payload: {
                    cmdName: "getDevice",
                    cmdCode: "0003",
                    parameters: {
                        "uuid": deviceUuid
                    }
                }
            };
            self.message(getDevice, function (response) {
                if (response.retCode !== 200) {
                    logger.error(response.retCode, response.description);
                    responseMessage.retCode = response.retCode;
                    responseMessage.description = response.description;
                    peerCallback(responseMessage);
                }
                else {
                    var deviceInfo = response.data[0];
                    if (!deviceInfo.extra.authToken
                        || deviceInfo.extra.authToken.token !== token
                        || deviceInfo.extra.authToken.timestamp + TIMR_OUT < Date.now()) {
                        responseMessage.retCode = 207010;
                        responseMessage.description = logger.getErrorInfo(responseMessage.retCode);
                    }
                    else {
                        var updateDevice = {
                            devices: self.configurator.getConfRandom("services.device_manager"),
                            payload: {
                                cmdName: "deviceUpdate",
                                cmdCode: "0004",
                                parameters: {
                                    "uuid": deviceInfo.uuid,
                                    "extra.authToken.timestamp": Date.now()
                                }
                            }
                        };
                        self.message(updateDevice, function (response) {
                            if (response.retCode !== 200) {
                                logger.error(response.retCode, response.description);
                                responseMessage.retCode = response.retCode;
                                responseMessage.description = response.description;
                            }
                        });
                    }
                    peerCallback(responseMessage);
                }
            });
        }
    });
};


module.exports = {
    Service: AuthenticationCenter,
    OperationSchemas: OPERATION_SCHEMAS
};