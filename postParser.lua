--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-10
-- Time: 13:22
-- To change this template use File | Settings | File Templates.


local _M = {}


local find = string.find
local sub = string.sub
local re_match = ngx.re.match
local re_find = ngx.re.find

function _M.printTest(data)
    ngx.header.content_type = "text/html"
    ngx.say(data)
end

-- 获取boundary特征值
function _M.getBoundary(header)
    if type(header) == "table" then
        header = header[1]
    end

    local m, err = re_match(header,
        [[;\s*boundary\s*=\s*(?:"([^"]+)"|([-|+*$&!.%'`~^\#\w]+))]],
        "joi")
    if m then
        return m[1] or m[2]
    end
    if err then
        return nil, "bad regex: " .. err
    end
    return nil
end

function _M.getData(body,boundary)

    -- 将字符串的位置移动到开始匹配的位置
    local start = 1
    --local str = sub(body,fr,to+1)
    local length = string.len(body)
    while true do

        if length <= start then
            break
        end

        local fr, to = find(body, boundary, start, true)
        if not fr then
            return nil
        end
        start = to + 1

        local fr, to = find(body, "\n\n", start, true)
        if not to then
            break
        end
        local tempstartlength = to +1
        local fr, to = find(body, "\n"..boundary, tempstartlength, true)
        local templength = fr


        -- 解析POST数据中的name参数
        match_table[1] = nil
        match_table[2] = nil
        local m, err = re_match(sub(body,start,templength),
            [[^Content-Disposition:.*?;\s*name\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
            "joim", nil, match_table)
        local name
        if m then
            name = m[1] or m[2]
        end
        if name == nil then
            name=""
        end

        -- 解析POST数据的filename参数
        local tempBody = sub(body,start,templength)
        local m, err = re_match(tempBody,
            [[^Content-Disposition:.*?;\s*filename\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
            "joim", nil, match_table)
        local filename
        if m then
            filename = m[1] or m[2]
        end
        if filename == nil then
            filename=""
        end

        -- 解析POST上传的文件的格式
        local fr, to = re_find(tempBody, [[^Content-Type:\s*([^;\s]+)]], "joim",
            nil, 1)
        local mime
        local tempTo
        if fr then
            mime = sub(tempBody, fr, to)
            tempTo = to + 2
        end
        if mime == nil then
            mime=""
            tempTo = 0
        end

        --[[local fr, to = find(body, "\n\n", start, true)
        if not to then
            break
        end

        -- 解析POST上传的数据
        start = to +1
        local fr, to = find(body, "\n"..boundary, start, true)--]]
        if mime ~= nil then
            tempstartlength = tempstartlength + tempTo
        end
        local str = sub(body,tempstartlength,templength-1)
        start = templength
        --if str ~= "" then
            _M.printTest(name.."--"..filename.."--"..mime.."--"..str.."--")
            --[[table.insert(data,name)
            table.insert(data,filename)
            table.insert(data,mime)
            table.insert(data,str)
        --end
        table.insert(datas,data)
        data = {}]]
    end
    --[[for k, val in pairs(datas) do
        if type(val) == table then
            for k, v in pairs(val) do
                _M.printTest(v)
            end
        end
    end
    return datas]]


    --_M.printTest(name)
end

function _M.getSingleDataName(body)
    local m, err = re_match(body,
        [[^Content-Disposition:.*?;\s*name\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
        "joim")
    local name
    if m then
        name = m[1] or m[2]
    end
    if name == nil then
        name=""
    end
    --_M.printTest(name)
    return name
end

function _M.getSingleDataFileName(body)
    local m, err = re_match(body,
        [[^Content-Disposition:.*?;\s*filename\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
        "joim", nil, match_table)
    local filename
    if m then
        filename = m[1] or m[2]
    end
    if filename == nil then
        filename=""
    end
    --_M.printTest(filename)
    return filename
end

function _M.getSingleDataMime(body)
    local fr, to = re_find(body, [[^Content-Type:\s*([^;\s]+)]], "joim",
        nil, 1)
    local mime
    local tempTo
    if fr then
        mime = sub(body, fr, to)
        tempTo = to + 2
    end
    if mime == nil then
        mime=""
        tempTo = 0
    end
    --_M.printTest(mime)
    return mime,tempTo
end

function _M.getSingleData(body,start,length)
    local str = sub(body,start,length)
    --_M.printTest(str)
    return str
end

return _M

