--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-16
-- Time: 11:57
-- To change this template use File | Settings | File Templates.
-- 检测IP黑/白名单

-- 引用模块
local init = require("init")
local util = require("util")
local output = require("wafOutput")

local limit_IP = ngx.shared.limit_IP

local _M = {}

-- 检测当前请求访问的用户IP是否在处于白名单之中
function _M.IPWhiteCheck()

    -- 获取白名单检测是否开启
    local IPWhiteCheck = init.getIPWhiteCheck()
    -- 获取白名单规则
    local IPWhiteList = init.getIPWhiteList()

    -- 获取当前用户请求IP
    local clientIP = util.getClientIP()
    if not clientIP then
        return false
    end

    if IPWhiteCheck then

        -- 检查当前访问用户的IP是否处于被禁止的动态名单
        -- 如果处于被禁止状态直接结束
        local request, _ = limit_IP:get(clientIP)
        if request then
            output.sayHtml(util.getClientIP(), util.getHost(),
                util.getServerName() .. util.getRequestUri(), request)
        end

        if next(IPWhiteList) ~= nil then

            for _, ip in pairs(IPWhiteList) do
                -- 检测当前IP是否处于白名单之中
                if ip == clientIP then
                    return true
                end
            end
        end
    end
    return false
end

-- 检测当前请求访问的用户IP是否在处于黑名单之中
function _M.IPBlockCheck()
    -- 获取黑名单检测是否开启
    local IPBlockCheck = init.getIPBlockCheck()
    -- 获取黑名单规则
    local IPBlockList = init.getIPBlockList()

    -- 获取当前用户请求IP
    local clientIP = util.getClientIP()
    if not clientIP then
        return true
    end

    if IPBlockCheck then

        -- 检查当前访问用户的IP是否处于被禁止的动态名单
        -- 如果处于被禁止状态直接结束
        local request, _ = limit_IP:get(clientIP)
        if request then
            output.sayHtml(util.getClientIP(), util.getHost(),
                util.getServerName() .. util.getRequestUri(), request)
        end

        if next(IPBlockList) ~= nil then

            -- 检查是否在初始的禁止名单内
            for _, ip in pairs(IPBlockList) do
                if ip == clientIP then
                    output.sayHtml(util.getClientIP(), util.getHost(),
                        util.getServerName() .. util.getRequestUri(), "您的IP已被网站禁止访问")
                end
            end
        end
    end
    return true
end

return _M

