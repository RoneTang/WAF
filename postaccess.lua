--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-10
-- Time: 16:57
-- To change this template use File | Settings | File Templates.
-- 用于对post的参数进行检测

local _M = {}

local ruleMatch = ngx.re.find
local unescape = ngx.unescape_uri

function _M.dataCheck(data, rules)
    for _, rule in pairs(rules) do
        if rule ~= "" and ruleMatch(data, rule, "joi") then
            return false
        end
    end
    return true
end

function _M.printTest(data)
    ngx.header.content_type = "text/html"
    ngx.say(data)
end

-- 文件内容检测
function _M.bodyParser(data, rules)
    if data == nil then
        return false,"数据为空"
    end
    if next(rules) == nil then
        return false,"规则为空"
    end
    for _, rule in pairs(rules) do
        if rule ~= "" and data ~= "" and ruleMatch(unescape(data), rule, "isjo") then
            return true, rule
        end
    end
    return false
end

-- 文件扩展名检测
function _M.fileExtCheck(data, rules)
    data = string.lower(data)
    if data then
        if next(rules) ~= "" then
            for _, rule in pairs(rules) do
                if data ~= "" and ruleMatch(data, rule, "isjo") then
                    return true, rule
                end
            end
        end
    end
    return false,"数据为空"
end

return _M



