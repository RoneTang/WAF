--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-16
-- Time: 14:48
-- To change this template use File | Settings | File Templates.
-- 防止CC攻击以及记录日志

-- 引用模块
local init = require("init")
local util = require("util")
local log = require("log")
local output = require("wafOutput")

local limit_CC = ngx.shared.limit_CC
local limit_IP = ngx.shared.limit_IP
local IP_Times = ngx.shared.IP_Times

local _M = {}

-- 防止CC攻击以及记录日志
function _M.CCDenyCheck()

    -- 获取防止CC功能是否开启
    local CCDenyCheck = init.getCCDenyCheck()
    -- 获取防止CC的Rate
    local CCRate = init.getCCRate()
    if not CCRate then
        return
    end
    -- 获取判定是在CC攻击的界限
    local CCCount = tonumber(string.match(CCRate, '(.*)/'))
    local CCSeconds = tonumber(string.match(CCRate, '/(.*)'))

    if CCDenyCheck then

        local clientIP = util.getClientIP()
        local uri = util.getUri()
        local token = clientIP .. uri
        local request, _ = limit_CC:get(token)
        if request then
            if request > CCCount then

                math.randomseed(tostring(ngx.now()):reverse():sub(1, 6))
                local BlokTime = math.random(1,tonumber(init.getBlockTime()))
                -- 将该疑似CC攻击的IP加入动态IP黑名单中
                local req, _ = limit_IP:get(clientIP)
                if req then
                    limit_IP:replace(clientIP,"您因为请求过于频繁，请过一段时间在访问",BlokTime)
                else
                    limit_IP:set(clientIP,"您因为请求过于频繁，请过一段时间在访问",BlokTime)
                end


                log.jsonLog(util.getMethod(), util.getRequestUri(), clientIP, "CC攻击","CC防御")
                output.sayHtml(util.getClientIP(),util.getHost(),
                    util.getServerName()..util.getRequestUri(),"同一页面请求频率太高")
                return false
            else
                limit_CC:incr(token, 1)
            end
        else
            limit_CC:set(token, 1, CCSeconds)
        end
    end
    return true
end

-- 检测IP访问次数是否过于频繁
-- 若是过于频繁则记录并且将IP加入黑名单
function _M.IPTimesCheck()
    -- 获取IP访问频率
    local Count = init.getCount()
    if not Count then
        return
    end
    local IPCount = tonumber(string.match(Count, '(.*)/'))
    local IPSecond = tonumber(string.match(Count, '/(.*)'))

    -- 获取客户端IP
    local clientIP = util.getClientIP()
    math.randomseed(tostring(ngx.now()):reverse():sub(1, 6))
    local BlokTime = math.random(1,tonumber(init.getBlockTime()))
    local request, _ = IP_Times:get(clientIP)
    if request then
        if request > IPCount then
            -- 将请求频繁的IP加入动态IP黑名单中
            local req, _ = limit_IP:get(clientIP)
            if req then
                limit_IP:replace(clientIP,"您因为请求过于频繁，请过一段时间在访问",BlokTime)
            else
                limit_IP:set(clientIP,"您因为请求过于频繁，请过一段时间在访问",BlokTime)
            end
            log.jsonLog(util.getMethod(), "-", clientIP, "请求频繁","请求频繁")
            output.sayHtml(util.getClientIP(),util.getHost(),
                util.getServerName()..util.getRequestUri(),"同一IP请求频率太高")
            return false
        else
            IP_Times:incr(clientIP,1)
        end
    else
        IP_Times:set(clientIP,1,IPSecond)
    end
    return true
end

return _M

