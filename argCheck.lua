--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-17
-- Time: 16:57
-- To change this template use File | Settings | File Templates.
-- 用于参数检测

-- 引用模块
local init = require("init")
local util = require("util")
local log = require("log")
local postParser = require("postParser")
local postAccess = require("postaccess")
local output = require("wafOutput")
local mysqlUtil = require("mysqlUtil")

-- 引用函数
local ruleMatch = ngx.re.find
local unescape = ngx.unescape_uri

local limit_IP = ngx.shared.limit_IP

local _M = {}

-- 用于弥补存在GET只读100个请求参数
function _M.GETURLCheck()
    -- 获取get参数检测是否开启
    local ArgCheck = init.getArgCheck()
    -- 获取get参数检测规则
    local argsList = init.getArgsList()

    local url = util.getRequestUri()
    if ArgCheck then
        if next(argsList) ~= nil then
            for _, rule in pairs(argsList) do
                if url and type(url) ~= "boolean" and rule ~= "" and ruleMatch(unescape(url), rule, "isjo") then
                    log.jsonLog(util.getMethod(), url, url, rule, "SQL注入")
                    mysqlUtil.addLog(util.getClientIP(),"SQL注入",util.getMethod(),url,util.getUserAgent(),util.getServerName())
                    _M.Forbidden("您曾经恶意攻击网站被禁止访问")
                    output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. url, "请求中的变量含有非法字符")
                end
            end
        end
    end
end

function _M.POSTURLCheck(rules)
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    for _, rule in pairs(rules) do
        if data and type(data) ~= "boolean" and rule ~= "" and ruleMatch(unescape(data), rule, "isjo") then
            log.jsonLog(util.getMethod(), util.getUri(), data, rule, "SQL注入")
            mysqlUtil.addLog(util.getClientIP(),"SQL注入",util.getMethod(),util.getUri(),util.getUserAgent(),util.getServerName())
            _M.Forbidden("您曾经恶意攻击网站被禁止访问")
            output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. util.getUri(), "请求中的变量含有非法字符")
        end
    end
end

-- 该函数用于对疑似进行SQL注入攻击的IP地址加入到黑名单之中
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.Forbidden(data)

    math.randomseed(tostring(ngx.now()):reverse():sub(1, 6))
    local BlokTime = math.random(1,tonumber(init.getBlockTime()))
    local clientIP = util.getClientIP()
    local req, _ = limit_IP:get(clientIP)
    if req then
        limit_IP:replace(clientIP, data, BlokTime)
    else
        limit_IP:set(clientIP, data, BlokTime)
    end
    return true
end

-- 该函数用于对SQL注入进行检测，若是存在SQL注入
-- 将SQL注入攻击者IP加入黑名单并进行日志记录
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.argsCheck(args, rules)

    local ARGDATA

    for _, rule in pairs(rules) do
        for key, val in pairs(args) do
            if type(val) == 'table' then
                local temp = {}
                for _, v in pairs(val) do
                    if v == true then
                        v = ""
                    end
                    table.insert(temp, v)
                end
                ARGDATA = table.concat(temp, " ")
            else
                ARGDATA = val
            end

            -- 请求的参数与规则进行匹配
            if ARGDATA and type(ARGDATA) ~= "boolean" and rule ~= "" and (ruleMatch(unescape(ARGDATA), rule, "isjo") or ruleMatch(unescape(key), rule, "isjo")) then
                local method = util.getMethod()
                local uri = util.getRequestUri()
                if uri == "" then
                    uri = util.getUri()
                end
                local data = key .. "=" .. ARGDATA

                log.jsonLog(method, uri, data, rule, "SQL注入")
                mysqlUtil.addLog(util.getClientIP(),"SQL注入",util.getMethod(),uri,util.getUserAgent(),util.getServerName())
                _M.Forbidden("您曾经恶意攻击网站被禁止访问")
                output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. uri, "请求中的变量含有非法字符")
            end

        end
    end

    return true
end

-- 该函数用于对GET请求的参数进行检测
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.GetArgsCheck()

    -- 获取get参数检测是否开启
    local ArgCheck = init.getArgCheck()
    -- 获取get参数检测规则
    local argsList = init.getArgsList()

    -- 获取get请求的参数
    local args = util.getGetArgs()
    if not args then
        return true
    end

    if ArgCheck then
        if next(argsList) ~= nil and next(args) ~= nil then
            _M.argsCheck(args, argsList)
        end
    end
    return true
end

-- 该函数用于对POST上传文件的文件名和内容进行检测
-- 对于疑似禁止的行为进行记录
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.PostCheckMethodA(postList)

    -- 获取文件扩展名规则
    local filenameExtList = init.getFilenameExtList()

    local len = string.len
    local sock, _ = ngx.req.socket()
    if not sock then
        return
    end

    -- 设置缓存大小为128K
    ngx.req.init_body(128 * 1024)
    -- 设置超事
    sock:settimeout(0)
    local content_length = util.getContentLength()
    local chunk_size = 4096
    if content_length < chunk_size then
        chunk_size = content_length
    end
    local size = 0
    while size < content_length do
        -- 通过socket接收数据
        local data, _, partial = sock:receive(chunk_size)
        data = data or partial
        if not data then
            return
        end
        ngx.req.append_body(data)

        -- 首先对文件中的内容进行检测
        local flag, message = postAccess.bodyParser(data, postList)
        if flag then
            local method = util.getMethod()
            local uri = util.getUri()
            log.jsonLog(method, uri, data, message, "文件包含")
            mysqlUtil.addLog(util.getClientIP(),"文件包含",util.getMethod(),uri,util.getUserAgent(),util.getServerName())
            return ngx.redirect(uri)
            --output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. uri, "上传的文件中包含非法内容")
            --ngx.exit(200)
        end

        size = size + len(data)

        -- 对文件的扩展名进行检测
        local m = ngx.re.match(data, [[^Content-Disposition:.*?;\s*filename\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
            "joim")
        local filename
        if m then
            filename = m[1] or m[2]
        end
        if filename then
            local flag, message = postAccess.fileExtCheck(filename, filenameExtList)
            if flag then
                local method = util.getMethod()
                local uri = util.getUri()
                log.jsonLog(method, uri, filename, message, "文件扩展名非法")
                mysqlUtil.addLog(util.getClientIP(),"文件扩展名非法",util.getMethod(),uri,util.getUserAgent(),util.getServerName())
                return ngx.redirect(uri)
                --output.sayHtml(util.getClientIP(), util.getHost(), util.getServerName() .. uri, "上传的文件扩展名被禁止")
                --ngx.exit(403)
            end
        end
        local less = content_length - size
        if less < chunk_size then
            chunk_size = less
        end
    end
    ngx.req.finish_body()
    return true
end

-- 该函数用于对POST请求中的key-value类型的检测
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.PostCheckMethodB(postList)

    -- 获取post请求参数
    local args = util.getPostArgs()
    if not args then
        return true
    end

    _M.argsCheck(args, postList)


    return true
end

-- 该函数应用于对POST请求的参数的检测
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.PostArgsCheck()

    -- 获取post参数检测是否开启
    local PostCheck = init.getPostCheck()
    -- 获取post参数检测规则
    local postList = init.getPostList()
    local argsList = init.getArgsList()

    if PostCheck then
        if next(postList) ~= nil then
            local content_type = util.getContentType()
            local boundary = postParser.getBoundary(content_type)
            if boundary then
                _M.PostCheckMethodA(postList)
            else
                _M.PostCheckMethodB(argsList)
                _M.POSTURLCheck(argsList)
            end
        end
    end
    return true
end

-- 调用整个模块中所有用于参数检测的方法
-- 函数运行返回一个boolean类型的返回值或者无返回值
function _M.ARGSCHECK()
    -- 获取用户提交请求的方法（GET|POST）
    local method = util.getMethod()
    if not method then
        return true
    end
    if method == "GET" then
        _M.GetArgsCheck()
        _M.GETURLCheck()
    elseif method == "POST" then
        _M.PostArgsCheck()
    end
    return true
end

return _M

