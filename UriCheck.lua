--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-16
-- Time: 14:04
-- To change this template use File | Settings | File Templates.
-- 检测URI黑白名单

-- 引用模块
local init = require("init")
local util = require("util")
local output = require("wafOutput")
local log = require("log")
local mysqlUtil = require("mysqlUtil")
local postParser = require("postParser")

-- 引用函数
local ruleMatch = ngx.re.find
local unescape = ngx.unescape_uri

local _M = {}

-- URL白名单检测
function _M.WhiteUrlCheck()

    -- 获取URI白名单检测是否开启
    local WhiteUrlCheck = init.getWhiteUrlCheck()
    -- 获取URI白名单检测规则
    local WhiteUrlList = init.getWhiteUrlList()


    if WhiteUrlCheck then
        if next(WhiteUrlList) ~= nil then

            -- 获取用户访问URI
            local uri = util.getUri()
            if not uri then
                return false
            end

            for _, rule in pairs(WhiteUrlList) do
                if rule ~= "" and ruleMatch(unescape(uri), rule, "isjo") then
                    return true
                end
            end
        end
    end
    return false
end

-- URL黑名单检测
function _M.BlockUrlCheck()

    -- 获取URI黑名单是否开启
    local BlockUrlCheck = init.getBlockUrlCheck()
    -- 获取URI黑名检测规则
    local BlockUrlList = init.getBlockUrlList()

    if BlockUrlCheck then
        if next(BlockUrlList) ~= nil then

            -- 获取用户访问URI
            local uri = util.getRequestUri()
            if not uri then
                return false
            end

            local isTrue = false
            for _, rule in pairs(BlockUrlList) do
                if rule ~= "" and ruleMatch(unescape(uri), rule, "isjo")  then

                    if not isTrue then
                        log.jsonLog(util.getMethod(), uri, "-", rule, "敏感文件访问")
                        mysqlUtil.addLog(util.getClientIP(),"敏感文件访问",util.getMethod(),uri,util.getUserAgent(),util.getServerName())
                        isTrue = true
                    end
                    --ngx.exit(403)
                    output.sayHtml(util.getClientIP(), util.getHost(),
                        util.getServerName() .. util.getUri(), "您访问的资源属于被网站禁止访问的资源")
                end
            end
        end
    end
    return false
end

function _M.XSSCheck()

    local XSSCheck = init.getXSSCheck()
    local XSSList = init.getXSSList()
    if XSSCheck then
        if next(XSSList) ~= nil then
            local data
            if util.getMethod() == "GET" then
                local uri = util.getRequestUri()
                if not uri then
                    return true
                end
                data = uri
            end

            if util.getMethod() == "POST" then
                local content_type = util.getContentType()
                local boundary = postParser.getBoundary(content_type)
                if boundary then
                    return
                end
                ngx.req.read_body()
                data = ngx.req.get_body_data()
            end

            for _, rule in pairs(XSSList) do
                if rule ~= "" and ruleMatch(unescape(data), rule, "isjo") then
                    if util.getMethod() == "GET" then
                        log.jsonLog(util.getMethod(), data, data, rule, "XSS攻击")
                        mysqlUtil.addLog(util.getClientIP(),"XSS攻击",util.getMethod(),util.getUri(),util.getUserAgent(),util.getServerName())
                    end
                    if util.getMethod() == "POST" then
                        log.jsonLog(util.getMethod(), util.getUri(), data, rule, "XSS攻击")
                        mysqlUtil.addLog(util.getClientIP(),"POST攻击",util.getMethod(),util.getUri(),util.getUserAgent(),util.getServerName())
                    end
                    output.sayHtml(util.getClientIP(), util.getHost(),
                        util.getServerName() .. util.getUri(), "您的请求存在XSS行为")
                end
            end
        end
    end
    return true
end

-- 后台访问控制
function _M.manageIPCheck()
    if not init.getAccessControlCheck() then
        return false
    end
    local manageIPJson = init.getManageIP()
    if manageIPJson == nil then
        return false
    end
    local uri = util.getUri()
    local ClientIP = util.getClientIP()
    local isFlag = false
    local isUrl = false
    for _, value in pairs(manageIPJson) do
        if uri ~= nil and ruleMatch(uri, value["URL"], "isjo") then
            isUrl = true
            for _, val in ipairs(value["ClientIP"]) do
                if val == ClientIP then
                    isFlag = true
                    break
                end
            end
            if isFlag then
                return true
            end
        end
    end

    if isUrl then
        output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. uri, "您访问的URL地址您无权访问")
    end

    return false
end


return _M
