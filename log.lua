--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-16
-- Time: 16:30
-- To change this template use File | Settings | File Templates.
-- 日志记录

-- 引入模块
local init = require("init")
local util = require("util")
local cjson = require("cjson")

local _M = {}

-- 写文件
function _M.writeFile(logFile,message)
    if logFile == "" or message == "" then
        return
    end
    local file = io.open(logFile, "ab")
    if file == nil then
        return
    end
    file:write(message.."\n")
    file:flush()
    file:close()
end

-- 日志记录
function _M.Log(method,url,data,ruletag)
    local RealIP = util.getClientIP()
    local UserAgent = util.getUserAgent()
    local ServerName = util.getServerName()
    local localTime = util.getLocalTime()
    local LogPath = init.getLogPath()
    local today = util.getToDay()

    local Message
    Message = "[ "..RealIP .. " ] [ " .. localTime .. " ] [ " .. method .. " ] [ " .. ServerName .. url .. " ] [ " .. data .. " ]  [ "
            .. UserAgent .. " ] [ " .. ruletag .. " ]"
    local FileName = LogPath .. '/' .. ServerName .. "_" .. today .. "_sec.log"
    _M.writeFile(FileName,Message)
end

-- Json格式日志记录
function _M.jsonLog(method,url,data,ruletag,tag)
    local CLIENT_IP = util.getClientIP()
    local USER_AGENT = util.getUserAgent()
    local SERVER_NAME = util.getServerName()
    local LOCAL_TIME = util.getLocalTime()
    local LogPath = init.getLogPath()
    local today = util.getToDay()

    if url == "-" then
        url = ""
    end

    -- 构建json格式数据
    local logJsonObj = {
        Client_IP = CLIENT_IP,
        Local_Time = LOCAL_TIME,
        Server_Name = SERVER_NAME,
        User_Agent = USER_AGENT,
        Attack_Method = method,
        Request_URL = SERVER_NAME..url,
        Request_Data = data,
        Rule_Tag = ruletag,
        Tag = tag
    }
    local logMessage = cjson.encode(logJsonObj)
    local FileName = LogPath .. '/' .. SERVER_NAME .. "_" .. today .. "_sec.log"

    -- 写入文件
    _M.writeFile(FileName,logMessage)

end


return _M

