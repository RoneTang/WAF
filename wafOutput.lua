--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-20
-- Time: 15:02
-- To change this template use File | Settings | File Templates.
-- 输出警告页面

local init = require("init")

local _M = {}
local html = [[<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>网站防火墙</title>
<style>
p {
	line-height:20px;
}
ul{ list-style-type:none;}
li{ list-style-type:none;}
</style>
</head>

<body style=" padding:0; margin:0; font:14px/1.5 Microsoft Yahei, 宋体,sans-serif; color:#555;">

 <div style="margin: 0 auto; width:600px; padding-top:100px; overflow:hidden;">


  <div style="width:600px; float:left;">
    <div style=" height:40px; line-height:40px; color:#fff; font-size:16px; overflow:hidden; background:#6bb3f6; padding-left:16px;">网站防火墙 </div>
    <div style="border:1px dashed #cdcece; border-top:none; font-size:14px; background:#fff; color:#555; line-height:24px; height:220px; padding:20px 20px 0 20px; overflow-y:auto;background:#f3f7f9;">
      <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">
      <span style=" font-weight:600; color:#fc4f03;">您的请求带有不合法参数，已被网站管理员设置拦截！</span>
      </p>
      <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"align="center">可能原因：{reason}</p>
      <p style=" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:1; text-indent:0px;">如何解决：</p>
      <ul style="margin-top: 0px; margin-bottom: 0px; margin-left: 0px; margin-right: 0px; -qt-list-indent: 1;">
        <li style=" margin-top:12px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">1）检查提交内容；</li>
        <li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">2）如网站托管，请联系空间提供商；</li>
        <li style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">3）普通网站访客，请联系网站管理员；</li>
       </ul>
       <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;" align="center">用户IP：{ip}   服务器地址：{host}</p>
       <p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;" align="center">访问URL ：{url}</p>
    </div>
  </div>
</div>
</body></html>]]

function _M.sayHtml(ClientIP, host, url, reason)
    if not init.getRedirectCheck() then
        return false
    end
    local nowhtml = html
    ngx.header.content_type = "text/html"
    nowhtml = string.gsub(nowhtml, "{ip}", ClientIP)
    nowhtml = string.gsub(nowhtml, "{host}", host)
    nowhtml = string.gsub(nowhtml, "{reason}", reason)
    if url ~= "" then
        nowhtml = string.gsub(nowhtml, "{url}", ngx.unescape_uri(url))
    else
        nowhtml = string.gsub(nowhtml, "{url}", ngx.var.host)
    end

    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(nowhtml)
    ngx.exit(ngx.status)
end

return _M

