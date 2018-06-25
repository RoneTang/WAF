--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2017-05-18
-- Time: 15:57
-- To change this template use File | Settings | File Templates.
--

local _M = {}

-- 导入模块
local config = require("conf.config")
local cjson = require("cjson")

-- 导入配置文件中的值
local LogCheck = config.LogCheck
local LogPath = config.LogPath


-- 获取客户端IP地址
function _M.getClientIP()
    local IP = ngx.var.remote_addr
    if IP == nil then
        local headers = ngx.req.get_headers()
        IP = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or "0.0.0.0"
    end
    return IP
end

-- 获取客户端访问uri
function _M.getUri()
    local uri = ngx.var.uri
    if not uri then
        uri = "unknown"
    end
    return uri
end

-- 获取客户端访问时的方法GET/POST
function _M.getMethod()
    local method = ngx.var.request_method
    if not method then
        method = "unknown"
    end
    return method
end

-- 获取客户端的useragent
function _M.getUserAgent()
    local userAgent = ngx.var.http_user_agent
    if not userAgent then
        userAgent = "unknown"
    end
    return userAgent
end

-- 获取server name
function _M.getServerName()
    local serverName = ngx.var.server_name
    if not serverName then
        serverName = "unknown"
    end
    return serverName
end

-- 获取时间
function _M.getLocalTime()
    ngx.update_time()
    local time = ngx.localtime()
    if not time then
        ngx.update_time()
        time = ngx.localtime()
    end
    return time
end

function _M.getToDay()
    local today = ngx.today()
    if not today then
        today = ngx.today()
    end
    return today
end

-- 获取cookie
function _M.getCookie()
    local cookie = ngx.var.http_cookie
    if not cookie then
        cookie = "unknown"
    end
    return cookie
end

-- 获取get请求参数
function _M.getGetArgs()
    local args = ngx.req.get_uri_args()
    return args
end

-- 获取post请求参数
function _M.getPostArgs()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    return args
end

-- 获取请求头中的content-type
function _M.getContentType()
    local content_type = ngx.var.http_content_type
    if not content_type then
        content_type = "unknown"
    end
    return content_type
end

-- 获取请求头中的content-length
function _M.getContentLength()
    local content_lengthString = ngx.req.get_headers()['content-length']
    local content_length = tonumber(content_lengthString)
    return content_length
end

-- 获取请求中可能存在的Location
function _M.getLocation()
    local location = ngx.var.htpp_Location
    if not location then
        location = ""
    end
    return location
end

-- 获取可能存在的x_forwarded_for
function _M.getXForwardedFor()
    local x_forwarded_for = ngx.var.http_X_Forwarded_For
    if not x_forwarded_for then
        x_forwarded_for = ""
    end
    return x_forwarded_for
end

-- 获取referrer
function _M.getReferrer()
    local referer = ngx.var.valid_referers
    if not referer then
        referer = ngx.var.http_referer
        if not referer then
            referer = "unknown"
        end
    end

    return referer
end

-- 获取http中的host
function _M.getHost()
    local host = ngx.var.host
    if not host then
        host = "unknown"
    end
    return host
end

-- 获取用户请求的整个url
function _M.getRequestUri()
    local request_uri = ngx.unescape_uri(ngx.var.request_uri)
    if not request_uri then
        request_uri = "unknown"
    end
    return request_uri
end

-- 读取存在文件中的规则
function _M.readRule(filename)
    local file = io.open(config.RULE_PATH .. '/' .. filename, "r")
    if file == nil then
        return
    end
    local temp = {}
    for line in file:lines() do
        table.insert(temp, line)
    end
    file:close()
    return (temp)
end

-- 读取文件
function _M.readFile(filepath)
    local fd = io.open(filepath,"r")
    if fd == nil then
        return
    end
    -- 全部内容读取
    local str = fd:read("*a")
    fd:close()
    return str
end

-- 读取json文件
function _M.loadJson(filename)
    local file = _M.readFile(config.RULE_PATH.."/"..filename)
    local json = cjson.decode(file) or {}
    return json
end

-- 判断是否开启某一项功能
function _M.Judgment(options)
    if options == "on" then
        return true
    else
        return false
    end
end

-- 写文件
function _M.writeFile(logFile, message)
    local file = io.open(logFile, "ab")
    if file == nil then
        return
    end
    file:write(message)
    file:flush()
    file:close()
end

-- 日志记录
function _M.log(method, url, data, ruletag)
    if _M.Judgment(LogCheck) then
        local RealIP = _M.getClientIP()
        local UserAgent = ngx.var.http_user_agent
        local ServerName = ngx.var.server_name
        local time = ngx.localtime()
        local line
        if UserAgent then
            line = RealIP .. " [" .. time .. "] \"" .. method .. " " .. ServerName .. url .. "\" \"" .. data .. "\"  \"" .. UserAgent .. "\" \"" .. ruletag .. "\"\n"
        else
            line = RealIP .. " [" .. time .. "] \"" .. method .. " " .. ServerName .. url .. "\" \"" .. data .. "\" - \"" .. ruletag .. "\"\n"
        end
        local FileName = LogPath .. '/' .. ServerName .. "_" .. ngx.today() .. "_sec.log"
        _M.writeFile(FileName, line)
    end
end

return _M