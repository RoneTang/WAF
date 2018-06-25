--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-16
-- Time: 10:01
-- To change this template use File | Settings | File Templates.
-- 读取配置文件中的所有规则

-- 引用模块
local util = require("util")
local config = require("conf.config")

local _M = {}

-- 定义所需要读取的规则变量
local IPWhiteList
local IPBlockList
local WhiteUrlList
local BlockUrlList
local argsList
local userAgentList
local CookieList
local postList
local filenameExtList
local managerIP
local XSSList

-- 定义用于判定是否开启检查规则的变量
local IPWhiteCheck
local IPBlockCheck
local WhiteUrlCheck
local BlockUrlCheck
local CCDenyCheck
local ArgCheck
local UserAgentCheck
local CookieCheck
local PostCheck
local LogCheck
local AccessControl
local Redirect
local XSSCheck
local MysqlLog

-- 定义用于防止CC的值
local CCRate
-- 定义日志记录的位置
local LogPath
-- 定义IP访问的频率
local Count
-- 定义封禁时间
local BlokTime
local dbConfig = {
    host = "",
    port = 0,
    database = "",
    user = "",
    password = ""
}

-- 将所有在配置文件之中的规则读取到内存之中
function _M.READRULE()
    IPWhiteList = util.readRule("IPWhiteList.rule")
    IPBlockList = util.readRule("IPBlockList.rule")
    WhiteUrlList = util.readRule("WhiteUrl.rule")
    BlockUrlList = util.readRule("BlockUrl.rule")
    argsList = util.readRule("args.rule")
    userAgentList = util.readRule("useragents.rule")
    CookieList = util.readRule("cookies.rule")
    postList = util.readRule("post.rule")
    filenameExtList = util.readRule("filenameExtension.rule")
    managerIP = util.loadJson("manage_IP.json")
    XSSList = util.readRule("xss.rule")
    CCRate = config.CCRate
    LogPath = config.LogPath
    Count = config.Count
    BlokTime = config.BlockTime
end

-- 判断哪些功能是被开启的
function _M.CHECK()
    IPWhiteCheck = util.Judgment(config.IPWhiteCheck)
    IPBlockCheck = util.Judgment(config.IPBlockCheck)
    WhiteUrlCheck = util.Judgment(config.WhiteUrlCheck)
    BlockUrlCheck = util.Judgment(config.BlockUrlCheck)
    CCDenyCheck = util.Judgment(config.CCDenyCheck)
    ArgCheck = util.Judgment(config.ArgCheck)
    UserAgentCheck = util.Judgment(config.UserAgentCheck)
    CookieCheck = util.Judgment(config.CookieCheck)
    PostCheck = util.Judgment(config.PostCheck)
    LogCheck = util.Judgment(config.LogCheck)
    AccessControl = util.Judgment(config.AccessControl)
    Redirect = util.Judgment(config.Redirect)
    XSSCheck = util.Judgment(config.XSSCheck)
    MysqlLog = util.Judgment(config.MysqlLog)
end

function _M.setdbConfig()
    dbConfig.host = config.host
    dbConfig.port = config.port
    dbConfig.database = config.database
    dbConfig.user = config.user
    dbConfig.password = config.password
end

function _M.getdbConfig()
    return dbConfig
end

function _M.getMysqlLog()
    return MysqlLog
end

-- 获取是否XSS检查
function _M.getXSSCheck()
    return XSSCheck
end

-- 获取是否重定向
function _M.getRedirectCheck()
    return Redirect
end

-- 获取是否访问控制
function _M.getAccessControlCheck()
    return AccessControl
end

-- 获取日志记录是否开启
function _M.getLogCheck()
    return LogCheck
end

-- 获取IP白名单的检查是否开启
function _M.getIPWhiteCheck()
    return IPWhiteCheck
end

-- 获取IP黑名单的检查是否开启
function _M.getIPBlockCheck()
    return IPBlockCheck
end

-- 获取URL白名单检查是否开启
function _M.getWhiteUrlCheck()
    return WhiteUrlCheck
end

-- 获取URL黑名单是否开启
function _M.getBlockUrlCheck()
    return BlockUrlCheck
end

-- 获取是否开启CC防御
function _M.getCCDenyCheck()
    return CCDenyCheck
end

-- 获取是否开启参数检查
function _M.getArgCheck()
    return ArgCheck
end

-- 获取是否开启useragent检查
function _M.getUserAgentCheck()
    return UserAgentCheck
end

-- 获取是否开启cookie检查
function _M.getCookieCheck()
    return CookieCheck
end

-- 获取是否开启POST检查
function _M.getPostCheck()
    return PostCheck
end

-- 获取IP白名单规则
function _M.getIPWhiteList()
    return IPWhiteList
end

-- 获取IP黑名单规则
function _M.getIPBlockList()
    return IPBlockList
end

-- 获取URL白名单规则
function _M.getWhiteUrlList()
    return WhiteUrlList
end

-- 获取URL黑名单规则
function _M.getBlockUrlList()
    return BlockUrlList
end

-- 获取参数检测规则
function _M.getArgsList()
    return argsList
end

-- 获取useragent规则
function _M.getUserAgentList()
    return userAgentList
end

-- 获取cookie检测规则
function _M.getCookieList()
    return CookieList
end

-- 获取POSt参数检测规则
function _M.getPostList()
    return postList
end

-- 获取文件名后缀检测规则
function _M.getFilenameExtList()
    return filenameExtList
end

-- 获取CC防御界限值
function _M.getCCRate()
    return CCRate
end

-- 获取日志路径
function _M.getLogPath()
    return LogPath
end

-- 获取IP访问频率
function _M.getCount()
    return Count
end

-- 获取封禁时间
function _M.getBlockTime()
    return BlokTime
end

-- 获取manageIP
function _M.getManageIP()
    return managerIP
end

-- 获取XSSList
function _M.getXSSList()
    return XSSList
end


_M.READRULE()
_M.CHECK()
_M.setdbConfig()
return _M



