--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-17
-- Time: 16:10
-- To change this template use File | Settings | File Templates.
-- 用于useragent，cookie，扫描器检测


-- 引用模块
local init = require("init")
local util = require("util")
local log = require("log")
local output = require("wafOutput")
local mysqlUtil = require("mysqlUtil")
local limit_IP = ngx.shared.limit_IP

-- 引用函数
local ruleMatch = ngx.re.find
local unescape = ngx.unescape_uri


local _M = {}

function _M.Forbidden(data)
    if data == "" then
        data = "你曾今恶意攻击网站被禁止访问"
    end
    math.randomseed(tostring(ngx.now()):reverse():sub(1, 6))
    local BlokTime = math.random(1, tonumber(init.getBlockTime()))
    local clientIP = util.getClientIP()
    local req, _ = limit_IP:get(clientIP)
    if req then
        limit_IP:replace(clientIP, data, BlokTime)
        return false
    else
        limit_IP:set(clientIP, data, BlokTime)
    end
    return true
end

function _M.injectionCheck(data, warning)
    -- 获取get参数检测是否开启
    local ArgCheck = init.getArgCheck()
    -- 获取get参数检测规则
    local argsList = init.getArgsList()
    if data == "" then
        return true
    end
    if ArgCheck then
        if next(argsList) ~= nil then
            for _, rule in pairs(argsList) do
                if rule ~= "" and ruleMatch(unescape(data), rule, "isjo") then
                    local uri = util.getRequestUri()
                    local method = util.getMethod()
                    local serverName = util.getServerName()
                    local useragent = util.getUserAgent()
                    local ClientIP = util.getClientIP()
                    local host = util.getHost()
                    local isTrue = _M.Forbidden("您曾经恶意攻击网站被禁止访问")
                    if isTrue then
                        log.jsonLog(method, uri, data, rule, "SQL注入")
                        mysqlUtil.addLog(ClientIP, "SQL注入", util.getMethod(), uri, useragent, serverName)
                        output.sayHtml(ClientIP, host, serverName .. uri, warning)
                    end

                    break
                end
            end
        end
    end
    return true
end

function _M.xssCheck(data, warning)
    local XSSCheck = init.getXSSCheck()
    local XSSList = init.getXSSList()
    if data == "" then
        return true
    end
    if XSSCheck then
        if next(XSSList) ~= nil then
            for _, rule in pairs(XSSList) do
                if rule ~= "" and ruleMatch(unescape(data), rule, "isjo") then
                    local uri = util.getRequestUri()
                    local method = util.getMethod()
                    local serverName = util.getServerName()
                    local useragent = util.getUserAgent()
                    local ClientIP = util.getClientIP()
                    local host = util.getHost()
                    log.jsonLog(method, uri, data, rule, "XSS攻击")
                    mysqlUtil.addLog(ClientIP, "XSS攻击", util.getMethod(), uri, useragent, serverName)
                    output.sayHtml(ClientIP, host, serverName .. uri, warning)
                    --_M.Forbidden("您曾经恶意攻击网站被禁止访问")
                    break
                end
            end
        end
    end
    return true
end

-- 检测用户请求中的useragent
function _M.UserAgentCheck()

    -- 获取useragent检测是否开启
    local userAgentCheck = init.getUserAgentCheck()
    -- 获取useragent规则
    local userAgentList = init.getUserAgentList()



    -- 获取 useragent的值
    local userAgent = util.getUserAgent()
    if userAgent == "unknown" then
        return false
    end
    local warning = "您的User-Agent被网站禁止"
    if userAgentCheck then
        if next(userAgentList) ~= nil then
            for _, rule in pairs(userAgentList) do
                if rule ~= "" and ruleMatch(unescape(userAgent), rule, "isjo") then
                    -- 日志记录
                    local uri = util.getRequestUri()
                    local method = util.getMethod()
                    local serverName = util.getServerName()
                    --local useragetn = util.getUserAgent()
                    local ClientIP = util.getClientIP()
                    local host = util.getHost()
                    local isTrue = _M.Forbidden("使用扫描器扫描网站")
                    if isTrue then
                        log.jsonLog(method, uri, userAgent, rule, "扫描器扫描")
                        mysqlUtil.addLog(ClientIP, "扫描器扫描", method, uri, userAgent, serverName)
                        output.sayHtml(ClientIP, host, serverName .. uri, warning)
                    end

                    --ngx.exit(403)
                    break
                end
            end
        end
        if _M.injectionCheck(userAgent, warning) then
            _M.xssCheck(userAgent, warning)
        end
    end

    return false
end

-- 检测用户请求头中的cookie
function _M.CookieCheck()

    -- 获取cookie检测是否开启
    local CookieCheck = init.getCookieCheck()
    -- 获取cookie规则
    local CookieList = init.getCookieList()

    -- 获取cookie值
    local cookie = util.getCookie()
    if not cookie then
        return false
    end

    local warning = "Cookie中含有非法字符"
    if CookieCheck then
        if next(CookieList) ~= nil then
            for _, rule in pairs(CookieList) do
                if rule ~= "" and ruleMatch(unescape(cookie), rule, "isjo") then
                    -- 日志记录
                    local uri = util.getRequestUri()
                    local method = util.getMethod()
                    local serverName = util.getServerName()
                    local useragent = util.getUserAgent()
                    local ClientIP = util.getClientIP()
                    local host = util.getHost()
                    local isTrue = _M.Forbidden("使用扫描器扫描网站")
                    if isTrue then
                        log.jsonLog(method, uri, cookie, rule, "扫描器扫描")
                        mysqlUtil.addLog(ClientIP, "扫描器扫描", method, uri, useragent, serverName)
                        output.sayHtml(ClientIP, host, serverName .. uri, warning)
                    end

                    --ngx.exit(403)
                    break
                end
            end
        end
        if _M.injectionCheck(cookie, warning) then
            _M.xssCheck(cookie, warning)
        end
    end

    return false
end

-- 该函数用于简单的对部分扫描器进行识别
function _M.FingerprintIdentification()

    local flag = false
    -- 根据请求头判断是否是扫描器在对网站进行扫描
    if ngx.var.http_Acunetix_Aspect or ngx.var.http_X_Scan_Memo or ngx.var.http_X_Scanner then
        flag = true
    end

    local location = util.getLocation()
    if location == "acunetix_wvs_security_test" or location == "Netsparker" then
        flag = true
    end

    local x_forwarded_for = util.getXForwardedFor()
    if x_forwarded_for == "acunetix_wvs_security_test" or x_forwarded_for == "nessus" then
        flag = true
    end

    if flag then
        local uri = util.getUri()
        local method = util.getMethod()
        local ClientIP = util.getClientIP()
        local serverName = util.getServerName()
        local host = util.getHost()

        local isTrue = _M.Forbidden("使用扫描器扫描网站")
        if isTrue then
            log.jsonLog(method, uri, "-", "扫描器", "扫描器扫描")
            mysqlUtil.addLog(ClientIP, "扫描器扫描", method, uri, util.getUserAgent(), serverName)
            output.sayHtml(ClientIP, host, serverName .. uri, "请不要使用扫描器扫描网站")
        end
    end
end


function _M.refererChek()

    -- 获取referrer,useragent
    local referer = util.getReferrer()
    if not referer then
        return false
    end
    local ua = util.getUserAgent()
    local exts = [[\.(gif|jpg|jpeg|png|bmp|js|css|swf)$]]
    local http = "http"
    if ngx.var.https == "on" then
        http = "https"
    end
    local white_referer = {
        [0] = [[^]] .. http .. [[://[^/]*]] .. ngx.var.host .. [[[^/]*/.*]],
        [1] = [[^https?://[^/]*google\.com[^/]*/.*]],
        [2] = [[^https?://[^/]*baidu\.com[^/]*/.*]]
    }
    local white_ua = { [0] = "googlebot", [1] = "spider" }
    if referer ~= "unknown" then
        local warning = "referrer中含有非法字符"
        if _M.injectionCheck(referer, warning) then
            _M.xssCheck(referer, warning)
        end
    end
    if referer ~= "unknown" and ruleMatch(util.getUri(), exts, "ijos") then
        for _, val in pairs(white_referer) do
            if ruleMatch(referer, val, "ijos") then
                return true
            end
        end

        for _, val in pairs(white_ua) do
            if ruleMatch(ua, val, "ijos") then
                return true
            end
        end
        output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. util.getUri(), "图片禁止下载")
    end
    return false
end


return _M

