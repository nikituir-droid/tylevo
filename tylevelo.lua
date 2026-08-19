-- V Loader v7.2.6 (ASCII Source Compatibility + Hardened Runtime)
-- Security is server-authoritative. This file intentionally contains no reusable auth secret.

local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")
local HttpService = game:GetService("HttpService")
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")
local Workspace = game:GetService("Workspace")
local LocalPlayer = Players.LocalPlayer or Players.PlayerAdded:Wait()

local API = "https://83.97.111.55"
local LOADER_VERSION = "7.2.6"
local DEVICE_DIR = "NetNull"
local DEVICE_FILE = DEVICE_DIR .. "/device_v5.json"

local env = (type(getgenv) == "function" and getgenv()) or _G
local requestFn = env.request or env.http_request or (env.syn and env.syn.request) or (env.http and env.http.request) or (env.fluxus and env.fluxus.request)
assert(type(requestFn) == "function", "NetNull: executor request() is unavailable")
-- Capture the runtime compiler once. This does not make client execution unhookable,
-- but avoids later global replacement during the loader lifetime.
local runtimeCompiler = loadstring or load
assert(type(runtimeCompiler) == "function", "NetNull: executor loadstring/load is unavailable")

local rawBit = bit32 or rawget(_G, "bit")
assert(rawBit and rawBit.bxor and rawBit.band and rawBit.bor and rawBit.bnot and rawBit.lshift and rawBit.rshift, "NetNull: bit32/bit library is required")
local bit = {
    bxor = rawBit.bxor,
    band = rawBit.band,
    bor = rawBit.bor,
    bnot = rawBit.bnot,
    lshift = rawBit.lshift,
    rshift = rawBit.rshift,
    rrotate = rawBit.rrotate or rawBit.ror,
}
assert(bit.rrotate, "NetNull: rotate-right bit operation is unavailable")

local MOD = 4294967296
local K = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local function u32(x) return x % MOD end
local function sha256Raw(message)
    local H = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
    local bitLen = #message * 8
    local high = math.floor(bitLen / MOD)
    local low = bitLen % MOD
    message = message .. string.char(0x80)
    local pad = (56 - (#message % 64)) % 64
    message = message .. string.rep("\0", pad)
    local function b(n, shift) return bit.band(bit.rshift(n, shift), 0xff) end
    message = message .. string.char(b(high,24),b(high,16),b(high,8),b(high,0),b(low,24),b(low,16),b(low,8),b(low,0))
    for chunk = 1, #message, 64 do
        local W = {}
        for i=0,15 do
            local p=chunk+i*4
            local a,c,d,e=string.byte(message,p,p+3)
            W[i]=u32(bit.bor(bit.lshift(a,24),bit.lshift(c,16),bit.lshift(d,8),e))
        end
        for i=16,63 do
            local x,y=W[i-15],W[i-2]
            local s0=bit.bxor(bit.rrotate(x,7),bit.rrotate(x,18),bit.rshift(x,3))
            local s1=bit.bxor(bit.rrotate(y,17),bit.rrotate(y,19),bit.rshift(y,10))
            W[i]=u32(W[i-16]+s0+W[i-7]+s1)
        end
        local a,bv,c,d,e,f,g,h=H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]
        for i=0,63 do
            local S1=bit.bxor(bit.rrotate(e,6),bit.rrotate(e,11),bit.rrotate(e,25))
            local ch=bit.bxor(bit.band(e,f),bit.band(bit.bnot(e),g))
            local t1=u32(h+S1+ch+K[i+1]+W[i])
            local S0=bit.bxor(bit.rrotate(a,2),bit.rrotate(a,13),bit.rrotate(a,22))
            local maj=bit.bxor(bit.band(a,bv),bit.band(a,c),bit.band(bv,c))
            local t2=u32(S0+maj)
            h=g; g=f; f=e; e=u32(d+t1); d=c; c=bv; bv=a; a=u32(t1+t2)
        end
        H[1]=u32(H[1]+a); H[2]=u32(H[2]+bv); H[3]=u32(H[3]+c); H[4]=u32(H[4]+d)
        H[5]=u32(H[5]+e); H[6]=u32(H[6]+f); H[7]=u32(H[7]+g); H[8]=u32(H[8]+h)
    end
    local out={}
    for _,n in ipairs(H) do
        out[#out+1]=string.char(bit.band(bit.rshift(n,24),255),bit.band(bit.rshift(n,16),255),bit.band(bit.rshift(n,8),255),bit.band(n,255))
    end
    return table.concat(out)
end
local function hex(raw) return (raw:gsub('.', function(c) return string.format('%02x', string.byte(c)) end)) end
local function sha256(s) return hex(sha256Raw(s)) end
local function hmacSha256(key, message)
    if #key > 64 then key = sha256Raw(key) end
    key = key .. string.rep("\0", 64-#key)
    local opad, ipad = {}, {}
    for i=1,64 do
        local k=string.byte(key,i)
        opad[i]=string.char(bit.bxor(k,0x5c))
        ipad[i]=string.char(bit.bxor(k,0x36))
    end
    return hex(sha256Raw(table.concat(opad) .. sha256Raw(table.concat(ipad) .. message)))
end

-- Fail closed if an executor's bit implementation is incompatible or if the
-- embedded SHA-256/HMAC implementation is accidentally modified.
do
    assert(
        sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "NetNull: SHA-256 self-test failed"
    )
    assert(
        hmacSha256("key", "The quick brown fox jumps over the lazy dog") ==
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        "NetNull: HMAC-SHA256 self-test failed"
    )
end

local function encode(v) return HttpService:JSONEncode(v) end
local function decode(v)
    local ok,res=pcall(HttpService.JSONDecode,HttpService,v or "")
    return ok and res or nil
end

local function requestRaw(method, path, payload, headers)
    local body = payload
    local h = headers or {}
    h["Accept"] = h["Accept"] or "application/json"
    h["X-NetNull-Loader"] = LOADER_VERSION
    if body ~= nil and h["Content-Type"] == nil then h["Content-Type"] = "application/json" end
    local ok,res=pcall(requestFn,{Url=API..path,Method=method,Headers=h,Body=body})
    if not ok then return nil,0,tostring(res) end
    local status=tonumber(res.StatusCode or res.Status or res.status_code or 0) or 0
    local rb=res.Body or res.body or ""
    if status < 200 or status >= 300 then
        local data=decode(rb)
        local detail=data and data.detail or rb
        if type(detail)=="table" then detail=detail.reason or detail.code or encode(detail) end
        return nil,status,tostring(detail or ("HTTP "..status))
    end
    return rb,status,nil
end

local function publicJson(method,path,obj)
    local payload = obj and encode(obj) or nil
    local rb,status,err=requestRaw(method,path,payload,nil)
    if not rb then return nil,status,err end
    return decode(rb),status,nil
end

-- Client/executor wall clocks are not trusted. Some environments incorrectly
-- fold the local timezone into os.time(), so the loader anchors signed requests
-- to the API clock instead of widening authentication windows indefinitely.
local clockOffset=0
local clockSynced=false

local function applyServerTime(serverTime, localReference)
    local serverNow=tonumber(serverTime)
    local localNow=tonumber(localReference) or os.time()
    if not serverNow or not localNow then return false end
    clockOffset=math.floor(serverNow-localNow)
    clockSynced=true
    return true
end

local function syncServerTime()
    local before=os.time()
    local data,status,err=publicJson("GET","/api/v5/time",nil)
    local after=os.time()
    if not data or not data.ok or not tonumber(data.server_time) then
        return false,err or ("HTTP "..tostring(status))
    end
    local midpoint=math.floor((before+after)/2)
    applyServerTime(data.server_time,midpoint)
    return true
end

local function newNonce()
    return sha256(HttpService:GenerateGUID(false)..":"..tostring(os.clock())..":"..tostring(math.random())):sub(1,32)
end

local function signedHeaders(device, method, path, payload, session)
    local ts=tostring(os.time()+clockOffset)
    local nonce=newNonce()
    local body=payload or ""
    local sessionHash=session and sha256(session) or "-"
    local canonical=table.concat({"NN5",string.upper(method),path,ts,nonce,sha256(body),sessionHash},"\n")
    return {
        ["X-NN-Device"]=device.id,
        ["X-NN-Time"]=ts,
        ["X-NN-Nonce"]=nonce,
        ["X-NN-Signature"]=hmacSha256(device.secret,canonical),
        ["Authorization"]=session and ("Bearer "..session) or nil,
    }
end

local function isStaleProof(status,err)
    return status==401 and string.find(string.lower(tostring(err or "")),"stale request proof",1,true)~=nil
end

local function signedRequestRaw(device, session, method, path, payload, extraHeaders)
    local function attempt()
        local headers=signedHeaders(device,method,path,payload,session)
        if extraHeaders then
            for k,v in pairs(extraHeaders) do headers[k]=v end
        end
        return requestRaw(method,path,payload,headers)
    end

    local rb,status,err=attempt()
    if not rb and isStaleProof(status,err) then
        local synced=syncServerTime()
        if synced then rb,status,err=attempt() end
    end
    return rb,status,err
end

local function signedJson(device, session, method, path, obj)
    local payload=obj and encode(obj) or nil
    local rb,status,err=signedRequestRaw(device,session,method,path,payload,nil)
    if not rb then return nil,status,err end
    local data=decode(rb)
    if data and data.server_time then applyServerTime(data.server_time) end
    return data,status,nil
end

local function signedRaw(device, session, method, path)
    return signedRequestRaw(device,session,method,path,nil,{["Accept"]="application/octet-stream"})
end

local function saveDevice(device)
    if type(writefile)~="function" then return false end
    pcall(function()
        if type(makefolder)=="function" and type(isfolder)=="function" and not isfolder(DEVICE_DIR) then makefolder(DEVICE_DIR) end
    end)
    local ok=pcall(writefile,DEVICE_FILE,encode(device))
    return ok
end

local function loadDevice()
    if type(readfile)~="function" or type(isfile)~="function" or not isfile(DEVICE_FILE) then return nil end
    local ok,text=pcall(readfile,DEVICE_FILE)
    if not ok then return nil end
    local d=decode(text)
    if type(d)~="table" or type(d.id)~="string" or type(d.secret)~="string" then return nil end
    return d
end

local function clearDevice()
    if type(delfile)=="function" and type(isfile)=="function" and isfile(DEVICE_FILE) then pcall(delfile,DEVICE_FILE) end
end

local parent=CoreGui
if type(gethui)=="function" then
    local ok,p=pcall(gethui)
    if ok and p then parent=p end
end

local old=parent:FindFirstChild("NETNULL_LOADER_V7")
if old then old:Destroy() end

-- ============================================================
-- NetNull v7.1 UI
-- User-facing UI intentionally avoids exposing protocol details.
-- Security/auth logic above this point is unchanged.
-- ============================================================

local C = {
    bg = Color3.fromRGB(3, 5, 7),
    bg2 = Color3.fromRGB(7, 10, 14),
    panel = Color3.fromRGB(7, 10, 14),
    panel2 = Color3.fromRGB(10, 14, 19),
    card = Color3.fromRGB(12, 17, 23),
    cardHover = Color3.fromRGB(16, 23, 31),
    border = Color3.fromRGB(35, 52, 66),
    borderSoft = Color3.fromRGB(22, 33, 43),
    accent = Color3.fromRGB(83, 190, 255),
    accent2 = Color3.fromRGB(143, 220, 255),
    accentDeep = Color3.fromRGB(12, 55, 82),
    text = Color3.fromRGB(247, 250, 252),
    textSoft = Color3.fromRGB(203, 215, 223),
    muted = Color3.fromRGB(126, 144, 156),
    dim = Color3.fromRGB(84, 101, 113),
    success = Color3.fromRGB(86, 230, 188),
    danger = Color3.fromRGB(255, 102, 121),
    warning = Color3.fromRGB(255, 193, 96),
    warningBg = Color3.fromRGB(27, 21, 13),
    warningBorder = Color3.fromRGB(80, 59, 25),
}

local function tw(obj, t, props, style, direction)
    local tween=TweenService:Create(
        obj,
        TweenInfo.new(t or .16, style or Enum.EasingStyle.Quad, direction or Enum.EasingDirection.Out),
        props
    )
    tween:Play()
    return tween
end

local function corner(obj, radius)
    local c=Instance.new("UICorner")
    c.CornerRadius=UDim.new(0, radius or 10)
    c.Parent=obj
    return c
end

local function stroke(obj, color, thickness, transparency)
    local s=Instance.new("UIStroke")
    s.Color=color or C.border
    s.Thickness=thickness or 1
    s.Transparency=transparency or 0
    s.Parent=obj
    return s
end

local function gradient(obj, c1, c2, rotation)
    local g=Instance.new("UIGradient")
    g.Color=ColorSequence.new(c1, c2)
    g.Rotation=rotation or 0
    g.Parent=obj
    return g
end

local function padding(obj, l, r, t, b)
    local p=Instance.new("UIPadding")
    p.PaddingLeft=UDim.new(0,l or 0)
    p.PaddingRight=UDim.new(0,r or 0)
    p.PaddingTop=UDim.new(0,t or 0)
    p.PaddingBottom=UDim.new(0,b or 0)
    p.Parent=obj
    return p
end

local function label(parentObj, textValue, size, pos, font, textSize, color)
    local x=Instance.new("TextLabel")
    x.Parent=parentObj
    x.BackgroundTransparency=1
    x.Size=size
    x.Position=pos or UDim2.new()
    x.Font=font or Enum.Font.GothamMedium
    x.TextSize=textSize or 13
    x.TextColor3=color or C.text
    x.Text=textValue or ""
    x.TextXAlignment=Enum.TextXAlignment.Left
    x.TextYAlignment=Enum.TextYAlignment.Center
    return x
end

local function makeButton(parentObj, textValue, size, pos, variant)
    local b=Instance.new("TextButton")
    b.Parent=parentObj
    b.Size=size
    b.Position=pos or UDim2.new()
    b.BorderSizePixel=0
    b.AutoButtonColor=false
    b.Font=Enum.Font.GothamMedium
    b.TextSize=13
    b.Text=textValue
    b.TextColor3=C.text
    b.BackgroundColor3=(variant=="accent") and Color3.fromRGB(10, 31, 43) or C.card
    corner(b,10)
    local bs=stroke(b,(variant=="accent") and C.accent or C.borderSoft,1,(variant=="accent") and .15 or .25)
    b.MouseEnter:Connect(function()
        if not b.Active then return end
        if variant=="accent" then
            tw(b,.12,{BackgroundColor3=Color3.fromRGB(13, 43, 59)})
            tw(bs,.12,{Color=C.accent2,Transparency=0})
        else
            tw(b,.12,{BackgroundColor3=C.cardHover})
            tw(bs,.12,{Color=C.border,Transparency=0})
        end
    end)
    b.MouseLeave:Connect(function()
        if variant=="accent" then
            tw(b,.12,{BackgroundColor3=Color3.fromRGB(10, 31, 43)})
            tw(bs,.12,{Color=C.accent,Transparency=.15})
        else
            tw(b,.12,{BackgroundColor3=C.card})
            tw(bs,.12,{Color=C.borderSoft,Transparency=.25})
        end
    end)
    return b,bs
end

local gui=Instance.new("ScreenGui")
gui.Name="NETNULL_LOADER_V7"
gui.ResetOnSpawn=false
gui.IgnoreGuiInset=false
gui.ZIndexBehavior=Enum.ZIndexBehavior.Sibling
gui.DisplayOrder=100000
gui.Parent=parent

local main=Instance.new("Frame")
main.Parent=gui
main.AnchorPoint=Vector2.new(.5,.5)
main.Position=UDim2.fromScale(.5,.5)
main.Size=UDim2.fromOffset(640,472)
main.BackgroundColor3=C.panel
main.BorderSizePixel=0
main.ClipsDescendants=true
main.ZIndex=2
corner(main,20)
local mainStroke=stroke(main,C.border,1,.18)
gradient(main,C.panel,C.bg,115)

local mainScale=Instance.new("UIScale")
mainScale.Parent=main

local function updateScale()
    local cam=Workspace.CurrentCamera
    if not cam then return end
    local vp=cam.ViewportSize
    local margin=UserInputService.TouchEnabled and 36 or 28
    local fit=math.min((vp.X-margin)/640,(vp.Y-margin)/472,1)
    mainScale.Scale=math.max(fit,.30)
end
updateScale()
if Workspace.CurrentCamera then
    Workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(updateScale)
end

-- Restrained inner accent. It never extends outside the loader frame.
local accentStrip=Instance.new("Frame")
accentStrip.Parent=main
accentStrip.Position=UDim2.fromOffset(24,0)
accentStrip.Size=UDim2.fromOffset(94,2)
accentStrip.BackgroundColor3=C.accent
accentStrip.BorderSizePixel=0
accentStrip.ZIndex=4
local accentGrad=Instance.new("UIGradient")
accentGrad.Parent=accentStrip
accentGrad.Color=ColorSequence.new({
    ColorSequenceKeypoint.new(0,C.accent2),
    ColorSequenceKeypoint.new(.55,C.accent),
    ColorSequenceKeypoint.new(1,Color3.fromRGB(24,48,61)),
})

-- Header.
local logo=Instance.new("TextLabel")
logo.Parent=main
logo.Position=UDim2.fromOffset(28,22)
logo.Size=UDim2.fromOffset(44,44)
logo.BackgroundColor3=Color3.fromRGB(8,17,23)
logo.BorderSizePixel=0
logo.Font=Enum.Font.GothamBold
logo.TextSize=28
logo.Text="V"
logo.TextColor3=C.text
logo.TextXAlignment=Enum.TextXAlignment.Center
logo.TextYAlignment=Enum.TextYAlignment.Center
logo.ZIndex=5
corner(logo,12)
stroke(logo,C.accent,1,.28)

local version=label(main,"LOADER  "..LOADER_VERSION,UDim2.fromOffset(190,24),UDim2.fromOffset(84,32),Enum.Font.GothamMedium,12,C.muted)
version.ZIndex=5

local accessBadge=Instance.new("Frame")
accessBadge.Parent=main
accessBadge.AnchorPoint=Vector2.new(1,0)
accessBadge.Position=UDim2.new(1,-28,0,26)
accessBadge.Size=UDim2.fromOffset(108,38)
accessBadge.BackgroundColor3=Color3.fromRGB(8,24,32)
accessBadge.BorderSizePixel=0
accessBadge.ZIndex=5
corner(accessBadge,11)
local accessStroke=stroke(accessBadge,C.border,1,.2)

local accessDot=Instance.new("Frame")
accessDot.Parent=accessBadge
accessDot.Position=UDim2.fromOffset(13,14)
accessDot.Size=UDim2.fromOffset(9,9)
accessDot.BackgroundColor3=C.accent
accessDot.BorderSizePixel=0
accessDot.ZIndex=6
corner(accessDot,99)

local accessText=label(accessBadge,"FREE",UDim2.new(1,-35,1,0),UDim2.fromOffset(31,0),Enum.Font.GothamBold,12,C.accent2)
accessText.ZIndex=6

-- User + status area.
local identityCard=Instance.new("Frame")
identityCard.Parent=main
identityCard.Position=UDim2.fromOffset(28,92)
identityCard.Size=UDim2.new(1,-56,0,82)
identityCard.BackgroundColor3=C.bg2
identityCard.BorderSizePixel=0
identityCard.ZIndex=4
corner(identityCard,13)
stroke(identityCard,C.borderSoft,1,.35)

local userCaption=label(identityCard,"\208\159\208\160\208\158\208\164\208\152\208\155\208\172",UDim2.fromOffset(110,19),UDim2.fromOffset(17,10),Enum.Font.GothamBold,10,C.dim)
userCaption.ZIndex=5

local userName=label(identityCard,tostring(LocalPlayer.Name),UDim2.new(.52,-18,0,30),UDim2.fromOffset(17,31),Enum.Font.GothamSemibold,16,C.text)
userName.ZIndex=5
userName.TextTruncate=Enum.TextTruncate.AtEnd

local statusWrap=Instance.new("Frame")
statusWrap.Parent=identityCard
statusWrap.AnchorPoint=Vector2.new(1,.5)
statusWrap.Position=UDim2.new(1,-16,.5,0)
statusWrap.Size=UDim2.fromOffset(260,48)
statusWrap.BackgroundTransparency=1
statusWrap.ZIndex=5

local statusDot=Instance.new("Frame")
statusDot.Parent=statusWrap
statusDot.Position=UDim2.fromOffset(0,18)
statusDot.Size=UDim2.fromOffset(8,8)
statusDot.BackgroundColor3=C.warning
statusDot.BorderSizePixel=0
statusDot.ZIndex=6
corner(statusDot,99)

local statusLabel=label(statusWrap,"\208\159\208\190\208\180\208\186\208\187\209\142\209\135\208\181\208\189\208\184\208\181...",UDim2.new(1,-20,1,0),UDim2.fromOffset(20,0),Enum.Font.GothamMedium,13,C.textSoft)
statusLabel.ZIndex=6
statusLabel.TextXAlignment=Enum.TextXAlignment.Left
statusLabel.TextWrapped=true

-- Action cards.
local actionsTitle=label(main,"\208\151\208\144\208\159\208\163\208\161\208\154",UDim2.fromOffset(130,20),UDim2.fromOffset(28,194),Enum.Font.GothamBold,10,C.dim)
actionsTitle.ZIndex=5

local launchFree,freeStroke=makeButton(main,"FREE",UDim2.fromOffset(280,76),UDim2.fromOffset(28,220),"normal")
launchFree.ZIndex=5
launchFree.Text=""
local freeTitle=label(launchFree,"FREE",UDim2.new(1,-32,0,30),UDim2.fromOffset(18,10),Enum.Font.GothamBold,16,C.text)
freeTitle.ZIndex=6
local freeSub=label(launchFree,"\208\158\209\129\208\189\208\190\208\178\208\189\208\190\208\185 \208\180\208\190\209\129\209\130\209\131\208\191",UDim2.new(1,-32,0,22),UDim2.fromOffset(18,42),Enum.Font.GothamMedium,12,C.muted)
freeSub.ZIndex=6
local freeArrow=label(launchFree,"\226\128\186",UDim2.fromOffset(24,40),UDim2.new(1,-40,.5,-20),Enum.Font.GothamBold,24,C.accent)
freeArrow.ZIndex=6
freeArrow.TextXAlignment=Enum.TextXAlignment.Center

local launchBeta,betaStroke=makeButton(main,"BETA",UDim2.fromOffset(280,76),UDim2.fromOffset(332,220),"accent")
launchBeta.ZIndex=5
launchBeta.Text=""
local betaTitle=label(launchBeta,"BETA",UDim2.new(1,-32,0,30),UDim2.fromOffset(18,10),Enum.Font.GothamBold,16,C.text)
betaTitle.ZIndex=6
local betaSub=label(launchBeta,"\208\160\208\176\209\129\209\136\208\184\209\128\208\181\208\189\208\189\209\139\208\185 \208\180\208\190\209\129\209\130\209\131\208\191",UDim2.new(1,-32,0,22),UDim2.fromOffset(18,42),Enum.Font.GothamMedium,12,C.accent2)
betaSub.ZIndex=6
local betaArrow=label(launchBeta,"\226\128\186",UDim2.fromOffset(24,40),UDim2.new(1,-40,.5,-20),Enum.Font.GothamBold,24,C.accent2)
betaArrow.ZIndex=6
betaArrow.TextXAlignment=Enum.TextXAlignment.Center

-- BETA activation area. Hidden automatically after BETA is bound.
local activationCard=Instance.new("Frame")
activationCard.Parent=main
activationCard.Position=UDim2.fromOffset(28,314)
activationCard.Size=UDim2.new(1,-56,0,78)
activationCard.BackgroundColor3=C.bg2
activationCard.BorderSizePixel=0
activationCard.ZIndex=4
corner(activationCard,13)
stroke(activationCard,C.borderSoft,1,.35)

local activationLabel=label(activationCard,"BETA ACCESS",UDim2.fromOffset(120,18),UDim2.fromOffset(15,9),Enum.Font.GothamBold,10,C.dim)
activationLabel.ZIndex=5

local keyBox=Instance.new("TextBox")
keyBox.Parent=activationCard
keyBox.Position=UDim2.fromOffset(15,34)
keyBox.Size=UDim2.new(1,-164,0,32)
keyBox.BackgroundColor3=C.card
keyBox.BorderSizePixel=0
keyBox.ClearTextOnFocus=false
keyBox.Font=Enum.Font.Code
keyBox.TextSize=12
keyBox.TextColor3=C.textSoft
keyBox.PlaceholderColor3=C.dim
keyBox.PlaceholderText="BETA / recovery code"
keyBox.Text=""
keyBox.ZIndex=5
corner(keyBox,8)
stroke(keyBox,C.borderSoft,1,.35)

local keyBtn=makeButton(activationCard,"\208\144\208\186\209\130\208\184\208\178\208\184\209\128\208\190\208\178\208\176\209\130\209\140",UDim2.fromOffset(132,32),UDim2.new(1,-147,0,34),"accent")
keyBtn.ZIndex=5

local boundCard=Instance.new("Frame")
boundCard.Parent=main
boundCard.Position=activationCard.Position
boundCard.Size=activationCard.Size
boundCard.BackgroundColor3=Color3.fromRGB(8,31,35)
boundCard.BorderSizePixel=0
boundCard.Visible=false
boundCard.ZIndex=4
corner(boundCard,13)
stroke(boundCard,C.success,1,.55)

local boundDot=Instance.new("Frame")
boundDot.Parent=boundCard
boundDot.Position=UDim2.fromOffset(16,28)
boundDot.Size=UDim2.fromOffset(10,10)
boundDot.BackgroundColor3=C.success
boundDot.BorderSizePixel=0
boundDot.ZIndex=5
corner(boundDot,99)
local boundTitle=label(boundCard,"BETA \208\176\208\186\209\130\208\184\208\178\208\184\209\128\208\190\208\178\208\176\208\189\208\176",UDim2.fromOffset(260,26),UDim2.fromOffset(40,18),Enum.Font.GothamSemibold,14,C.text)
boundTitle.ZIndex=5
local boundSub=label(boundCard,"\208\154\208\190\208\180 \208\177\208\190\208\187\209\140\209\136\208\181 \208\189\208\181 \209\130\209\128\208\181\208\177\209\131\208\181\209\130\209\129\209\143 \208\189\208\176 \209\141\209\130\208\190\208\188 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\181",UDim2.new(1,-58,0,22),UDim2.fromOffset(40,43),Enum.Font.GothamMedium,11,C.muted)
boundSub.ZIndex=5

-- Bottom utility bar. Device details are intentionally tucked away.
local utility=Instance.new("Frame")
utility.Parent=main
utility.Position=UDim2.fromOffset(28,410)
utility.Size=UDim2.new(1,-56,0,36)
utility.BackgroundTransparency=1
utility.ZIndex=4

local manualBtn=makeButton(utility,"\208\152\208\189\209\129\209\130\209\128\209\131\208\186\209\134\208\184\209\143",UDim2.fromOffset(140,36),UDim2.fromOffset(0,0),"normal")
manualBtn.ZIndex=5
local deviceBtn=makeButton(utility,"\208\163\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190",UDim2.fromOffset(140,36),UDim2.fromOffset(152,0),"normal")
deviceBtn.ZIndex=5

local footer=label(utility,"V",UDim2.fromOffset(80,36),UDim2.new(1,-80,0,0),Enum.Font.GothamBold,12,C.dim)
footer.ZIndex=5
footer.TextXAlignment=Enum.TextXAlignment.Right

-- Modal dim layer.
local modalDim=Instance.new("Frame")
modalDim.Parent=gui
modalDim.Size=UDim2.fromScale(1,1)
modalDim.BackgroundColor3=Color3.new(0,0,0)
modalDim.BackgroundTransparency=.28
modalDim.BorderSizePixel=0
modalDim.Visible=false
modalDim.Active=true
modalDim.ZIndex=50

local function modalCard(size)
    local m=Instance.new("Frame")
    m.Parent=modalDim
    m.AnchorPoint=Vector2.new(.5,.5)
    m.Position=UDim2.fromScale(.5,.5)
    m.Size=size
    m.BackgroundColor3=C.panel
    m.BorderSizePixel=0
    m.ZIndex=51
    corner(m,18)
    stroke(m,C.border,1,.05)
    gradient(m,C.panel,C.bg,115)
    local ms=Instance.new("UIScale")
    ms.Parent=m
    local function resizeModal()
        local cam=Workspace.CurrentCamera
        if not cam then return end
        local vp=cam.ViewportSize
        local sx=size.X.Offset
        local sy=size.Y.Offset
        local margin=UserInputService.TouchEnabled and 56 or 24
        local fit=math.min((vp.X-margin)/sx,(vp.Y-margin)/sy,1)
        ms.Scale=math.max(fit,.30)
    end
    resizeModal()
    if Workspace.CurrentCamera then
        Workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(resizeModal)
    end
    return m
end

-- Mobile/desktop drag helper. Primarily a fallback for unusual executor viewports.
local function makeDraggable(frame, handle)
    handle.Active=true
    local dragging=false
    local dragInput=nil
    local dragStart=nil
    local startPos=nil

    handle.InputBegan:Connect(function(input)
        if input.UserInputType==Enum.UserInputType.MouseButton1 or input.UserInputType==Enum.UserInputType.Touch then
            dragging=true
            dragStart=input.Position
            startPos=frame.Position
            input.Changed:Connect(function()
                if input.UserInputState==Enum.UserInputState.End then
                    dragging=false
                end
            end)
        end
    end)

    handle.InputChanged:Connect(function(input)
        if input.UserInputType==Enum.UserInputType.MouseMovement or input.UserInputType==Enum.UserInputType.Touch then
            dragInput=input
        end
    end)

    UserInputService.InputChanged:Connect(function(input)
        if not dragging or input~=dragInput or not dragStart or not startPos then return end
        local delta=input.Position-dragStart
        frame.Position=UDim2.new(
            startPos.X.Scale,startPos.X.Offset+delta.X,
            startPos.Y.Scale,startPos.Y.Offset+delta.Y
        )
    end)
end

-- Device / support modal.
local deviceModal=modalCard(UDim2.fromOffset(470,300))
deviceModal.Visible=false

local dTitle=label(deviceModal,"\208\163\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190",UDim2.fromOffset(280,34),UDim2.fromOffset(24,18),Enum.Font.GothamBold,22,C.text)
dTitle.ZIndex=52
local dSub=label(deviceModal,"\208\152\209\129\208\191\208\190\208\187\209\140\208\183\209\131\208\185\209\130\208\181 \209\141\209\130\208\190\209\130 \209\128\208\176\208\183\208\180\208\181\208\187 \209\130\208\190\208\187\209\140\208\186\208\190 \208\180\208\187\209\143 \208\191\208\190\208\180\208\180\208\181\209\128\208\182\208\186\208\184 \208\184\208\187\208\184 \208\191\208\181\209\128\208\181\208\191\209\128\208\184\208\178\209\143\208\183\208\186\208\184.",UDim2.new(1,-48,0,42),UDim2.fromOffset(24,54),Enum.Font.GothamMedium,12,C.muted)
dSub.ZIndex=52
dSub.TextWrapped=true
dSub.TextYAlignment=Enum.TextYAlignment.Top

local deviceIdBox=Instance.new("TextBox")
deviceIdBox.Parent=deviceModal
deviceIdBox.Position=UDim2.fromOffset(24,102)
deviceIdBox.Size=UDim2.new(1,-48,0,42)
deviceIdBox.BackgroundColor3=C.card
deviceIdBox.BorderSizePixel=0
deviceIdBox.ClearTextOnFocus=false
deviceIdBox.TextEditable=false
deviceIdBox.Font=Enum.Font.Code
deviceIdBox.TextSize=11
deviceIdBox.TextColor3=C.textSoft
deviceIdBox.Text="Device ID unavailable"
deviceIdBox.ZIndex=52
corner(deviceIdBox,9)
stroke(deviceIdBox,C.borderSoft,1,.35)

local copyBtn=makeButton(deviceModal,"\208\154\208\190\208\191\208\184\209\128\208\190\208\178\208\176\209\130\209\140 ID",UDim2.fromOffset(202,38),UDim2.fromOffset(24,158),"normal")
copyBtn.ZIndex=52
local resetBtn=makeButton(deviceModal,"\208\161\208\177\209\128\208\190\209\129\208\184\209\130\209\140 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190",UDim2.fromOffset(202,38),UDim2.new(1,-226,0,158),"normal")
resetBtn.ZIndex=52

local dWarning=label(deviceModal,"\208\159\208\190\209\129\208\187\208\181 \209\129\208\177\209\128\208\190\209\129\208\176 BETA \208\191\208\190\209\130\209\128\208\181\208\177\209\131\208\181\209\130\209\129\209\143 \208\189\208\190\208\178\209\139\208\185 recovery-\208\186\208\190\208\180.",UDim2.new(1,-48,0,36),UDim2.fromOffset(24,207),Enum.Font.GothamMedium,11,C.warning)
dWarning.ZIndex=52
dWarning.TextWrapped=true

local dClose=makeButton(deviceModal,"\208\151\208\176\208\186\209\128\209\139\209\130\209\140",UDim2.new(1,-48,0,36),UDim2.fromOffset(24,246),"accent")
dClose.ZIndex=52

-- Safety manual modal, restored from the previous loader.
local manual=modalCard(UDim2.fromOffset(760,UserInputService.TouchEnabled and 500 or 580))
manual.Visible=false

local manualTop=Instance.new("Frame")
manualTop.Parent=manual
manualTop.Size=UDim2.new(1,0,0,112)
manualTop.BackgroundColor3=Color3.fromRGB(7,20,29)
manualTop.BorderSizePixel=0
manualTop.ZIndex=52
corner(manualTop,18)
gradient(manualTop,Color3.fromRGB(8,25,36),Color3.fromRGB(7,14,21),0)
makeDraggable(manual,manualTop)
local manualTopMask=Instance.new("Frame")
manualTopMask.Parent=manualTop
manualTopMask.Position=UDim2.new(0,0,1,-18)
manualTopMask.Size=UDim2.new(1,0,0,18)
manualTopMask.BackgroundColor3=Color3.fromRGB(7,14,21)
manualTopMask.BorderSizePixel=0
manualTopMask.ZIndex=52

local mBrand=label(manual,"V",UDim2.fromOffset(70,38),UDim2.fromOffset(26,16),Enum.Font.GothamBold,30,C.text)
mBrand.ZIndex=53
local mBadge=Instance.new("TextLabel")
mBadge.Parent=manual
mBadge.Position=UDim2.fromOffset(26,54)
mBadge.Size=UDim2.fromOffset(126,24)
mBadge.BackgroundColor3=Color3.fromRGB(9,54,72)
mBadge.BorderSizePixel=0
mBadge.Font=Enum.Font.GothamSemibold
mBadge.Text="SAFETY MANUAL"
mBadge.TextColor3=C.accent2
mBadge.TextSize=10
mBadge.ZIndex=53
corner(mBadge,7)
stroke(mBadge,C.accent,1,.45)

local mIntro=label(manual,"\208\146\209\139\208\177\208\181\209\128\208\184\209\130\208\181 \209\143\208\183\209\139\208\186 / Choose language",UDim2.new(1,-380,0,24),UDim2.fromOffset(166,54),Enum.Font.GothamMedium,12,C.muted)
mIntro.ZIndex=53

local langHolder=Instance.new("Frame")
langHolder.Parent=manual
langHolder.AnchorPoint=Vector2.new(1,0)
langHolder.Position=UDim2.new(1,-26,0,20)
langHolder.Size=UDim2.fromOffset(218,40)
langHolder.BackgroundColor3=C.card
langHolder.BorderSizePixel=0
langHolder.ZIndex=53
corner(langHolder,9)
stroke(langHolder,C.borderSoft,1,.25)

local ruBtn=makeButton(langHolder,"\208\160\209\131\209\129\209\129\208\186\208\184\208\185",UDim2.fromOffset(101,32),UDim2.fromOffset(4,4),"normal")
ruBtn.ZIndex=54
local enBtn=makeButton(langHolder,"English",UDim2.fromOffset(101,32),UDim2.fromOffset(113,4),"normal")
enBtn.ZIndex=54

local manualContent=Instance.new("Frame")
manualContent.Parent=manual
manualContent.Position=UDim2.fromOffset(26,126)
manualContent.Size=UDim2.new(1,-52,1,-202)
manualContent.BackgroundTransparency=1
manualContent.Visible=false
manualContent.ZIndex=52

local warningCard=Instance.new("Frame")
warningCard.Parent=manualContent
warningCard.Size=UDim2.new(1,0,0,66)
warningCard.BackgroundColor3=C.warningBg
warningCard.BorderSizePixel=0
warningCard.ZIndex=53
corner(warningCard,10)
stroke(warningCard,C.warningBorder,1,.05)

local warnMark=label(warningCard,"!",UDim2.fromOffset(32,66),UDim2.fromOffset(12,0),Enum.Font.GothamBold,20,C.warning)
warnMark.ZIndex=54
warnMark.TextXAlignment=Enum.TextXAlignment.Center
local warnTitle=label(warningCard,"",UDim2.new(1,-60,0,21),UDim2.fromOffset(50,9),Enum.Font.GothamSemibold,13,C.warning)
warnTitle.ZIndex=54
local warnSub=label(warningCard,"",UDim2.new(1,-64,0,30),UDim2.fromOffset(50,31),Enum.Font.GothamMedium,11,Color3.fromRGB(205,181,141))
warnSub.ZIndex=54
warnSub.TextWrapped=true
warnSub.TextYAlignment=Enum.TextYAlignment.Top

local tipsScroll=Instance.new("ScrollingFrame")
tipsScroll.Parent=manualContent
tipsScroll.Position=UDim2.fromOffset(0,78)
tipsScroll.Size=UDim2.new(1,0,1,-78)
tipsScroll.BackgroundTransparency=1
tipsScroll.BorderSizePixel=0
tipsScroll.ScrollBarThickness=3
tipsScroll.ScrollBarImageColor3=C.accentDeep
tipsScroll.CanvasSize=UDim2.new(0,0,0,0)
tipsScroll.AutomaticCanvasSize=Enum.AutomaticSize.Y
tipsScroll.ZIndex=53

local tipsLayout=Instance.new("UIListLayout")
tipsLayout.Parent=tipsScroll
tipsLayout.Padding=UDim.new(0,9)
tipsLayout.SortOrder=Enum.SortOrder.LayoutOrder

padding(tipsScroll,0,7,0,4)

local itemLabels={}
local function makeTip(index)
    local card=Instance.new("Frame")
    card.Parent=tipsScroll
    card.Name="Tip"..tostring(index)
    card.Size=UDim2.new(1,-7,0,72)
    card.BackgroundColor3=C.card
    card.BorderSizePixel=0
    card.LayoutOrder=index
    card.ZIndex=54
    corner(card,10)
    local cs=stroke(card,C.borderSoft,1,.32)

    local number=Instance.new("TextLabel")
    number.Parent=card
    number.Position=UDim2.fromOffset(12,19)
    number.Size=UDim2.fromOffset(34,34)
    number.BackgroundColor3=Color3.fromRGB(8,50,67)
    number.BorderSizePixel=0
    number.Font=Enum.Font.GothamBold
    number.Text=tostring(index)
    number.TextColor3=C.accent2
    number.TextSize=11
    number.ZIndex=55
    corner(number,8)
    stroke(number,C.accent,1,.55)

    local txt=label(card,"",UDim2.new(1,-72,1,-18),UDim2.fromOffset(58,9),Enum.Font.GothamMedium,13,C.textSoft)
    txt.ZIndex=55
    txt.TextWrapped=true
    txt.TextYAlignment=Enum.TextYAlignment.Center
    txt.LineHeight=1.08
    itemLabels[index]=txt

    card.MouseEnter:Connect(function()
        tw(card,.12,{BackgroundColor3=C.cardHover})
        tw(cs,.12,{Color=C.border,Transparency=.1})
    end)
    card.MouseLeave:Connect(function()
        tw(card,.12,{BackgroundColor3=C.card})
        tw(cs,.12,{Color=C.borderSoft,Transparency=.32})
    end)
end
for i=1,7 do makeTip(i) end

local manualFooter=Instance.new("Frame")
manualFooter.Parent=manual
manualFooter.Position=UDim2.new(0,0,1,-62)
manualFooter.Size=UDim2.new(1,0,0,62)
manualFooter.BackgroundColor3=Color3.fromRGB(6,10,15)
manualFooter.BorderSizePixel=0
manualFooter.ZIndex=53

local footerText=label(manualFooter,"",UDim2.new(1,-238,1,0),UDim2.fromOffset(26,0),Enum.Font.GothamMedium,10,C.dim)
footerText.ZIndex=54
footerText.TextWrapped=true
footerText.TextYAlignment=Enum.TextYAlignment.Center
footerText.Size=UDim2.new(1,-238,0,42)
footerText.Position=UDim2.fromOffset(26,2)

local creatorCredit=label(manualFooter,"Loader created by NetNull",UDim2.fromOffset(300,14),UDim2.fromOffset(26,44),Enum.Font.GothamMedium,9,C.dim)
creatorCredit.ZIndex=54
creatorCredit.TextTransparency=.12

local continueBtn,continueStroke=makeButton(manualFooter,"\208\146\209\139\208\177\208\181\209\128\208\184\209\130\208\181 \209\143\208\183\209\139\208\186",UDim2.fromOffset(184,38),UDim2.new(1,-210,.5,-19),"accent")
continueBtn.ZIndex=54
continueBtn.Active=false

local TEXT={
    ru={
        intro="\208\160\209\131\209\129\209\129\208\186\208\184\208\185 \208\178\209\139\208\177\209\128\208\176\208\189",
        warnTitle="\208\146\208\144\208\150\208\157\208\158: \208\159\208\160\208\158\208\167\208\152\208\162\208\144\208\153\208\162\208\149 \208\159\208\149\208\160\208\149\208\148 \208\151\208\144\208\159\208\163\208\161\208\154\208\158\208\156",
        warnSub="\208\173\209\130\208\190 \208\189\208\181 \208\179\208\176\209\128\208\176\208\189\209\130\208\184\209\143 \208\177\208\181\208\183\208\190\208\191\208\176\209\129\208\189\208\190\209\129\209\130\208\184. \208\154\208\190\208\189\209\130\209\128\208\190\208\187\208\184\209\128\209\131\208\185\209\130\208\181 \209\132\208\176\209\128\208\188 \208\178\209\128\209\131\209\135\208\189\209\131\209\142, \209\129\208\190\208\177\208\187\209\142\208\180\208\176\208\185\209\130\208\181 \209\131\208\188\208\181\209\128\208\181\208\189\208\189\209\139\208\185 \209\130\208\181\208\188\208\191 \208\184 \209\129\209\128\208\176\208\183\209\131 \208\178\209\139\208\186\208\187\209\142\209\135\208\176\208\185\209\130\208\181 \208\188\208\190\208\180\209\131\208\187\209\140 \208\191\209\128\208\184 \209\129\209\130\209\128\208\176\208\189\208\189\208\190\208\188 \208\191\208\190\208\178\208\181\208\180\208\181\208\189\208\184\208\184.",
        footer="V \208\189\208\181 \208\188\208\190\208\182\208\181\209\130 \208\179\208\176\209\128\208\176\208\189\209\130\208\184\209\128\208\190\208\178\208\176\209\130\209\140 \208\177\208\181\208\183\208\190\208\191\208\176\209\129\208\189\208\190\209\129\209\130\209\140 \208\176\208\186\208\186\208\176\209\131\208\189\209\130\208\176. \208\157\208\181 \208\190\209\129\209\130\208\176\208\178\208\187\209\143\208\185\209\130\208\181 \208\176\208\178\209\130\208\190\208\188\208\176\209\130\208\184\208\183\208\176\209\134\208\184\209\142 \208\177\208\181\208\183 \208\191\209\128\208\184\209\129\208\188\208\190\209\130\209\128\208\176 \208\184 \209\129\208\190\208\177\208\187\209\142\208\180\208\176\208\185\209\130\208\181 \208\191\209\128\208\176\208\178\208\184\208\187\208\176 \208\184\208\179\209\128\209\139.",
        wait="\208\159\208\190\208\180\208\190\208\182\208\180\208\184\209\130\208\181 %ds",
        go="\208\159\209\128\208\190\208\180\208\190\208\187\208\182\208\184\209\130\209\140",
        tips={
            "\208\157\208\158\208\146\208\171\208\153 \208\144\208\154\208\154\208\144\208\163\208\157\208\162 \226\128\148 \208\159\208\149\208\160\208\146\208\171\208\149 7 \208\148\208\157\208\149\208\153: \208\184\208\183\208\177\208\181\208\179\208\176\208\185\209\130\208\181 \208\176\208\179\209\128\208\181\209\129\209\129\208\184\208\178\208\189\208\190\208\179\208\190 \208\184 \208\188\208\189\208\190\208\179\208\190\209\135\208\176\209\129\208\190\208\178\208\190\208\179\208\190 \208\176\208\178\209\130\208\190\209\132\208\176\209\128\208\188\208\176. \208\167\208\181\209\128\208\181\208\180\209\131\208\185\209\130\208\181 \208\186\208\190\208\189\209\130\209\128\208\176\208\177\208\176\208\189\208\180\209\131 \209\129 \208\187\208\190\208\180\208\186\208\176\208\188\208\184, \208\179\209\128\209\131\208\183\208\190\208\178\208\184\208\186\208\176\208\188\208\184 \208\184 \208\190\208\177\209\139\209\135\208\189\209\139\208\188\208\184 \208\184\208\179\209\128\208\190\208\178\209\139\208\188\208\184 \208\176\208\186\209\130\208\184\208\178\208\189\208\190\209\129\209\130\209\143\208\188\208\184, \208\189\208\181 \208\190\209\129\209\130\208\176\208\178\208\187\209\143\208\185\209\130\208\181 \208\176\208\178\209\130\208\190\208\188\208\176\209\130\208\184\208\183\208\176\209\134\208\184\209\142 \208\177\208\181\208\183 \208\191\209\128\208\184\209\129\208\188\208\190\209\130\209\128\208\176.",
            "\208\167\208\149\208\160\208\149\208\148\208\163\208\153\208\162\208\149 \208\144\208\154\208\162\208\152\208\146\208\157\208\158\208\161\208\162\208\152: \208\189\208\181 \208\180\208\181\209\128\208\182\208\184\209\130\208\181 \208\190\208\180\208\184\208\189 \208\184 \209\130\208\190\209\130 \208\182\208\181 \208\188\208\176\209\128\209\136\209\128\209\131\209\130 \208\191\208\190\209\129\209\130\208\190\209\143\208\189\208\189\208\190. \208\161\208\188\208\181\209\136\208\184\208\178\208\176\208\185\209\130\208\181 \208\186\208\190\208\189\209\130\209\128\208\176\208\177\208\176\208\189\208\180\209\131 \209\129 \208\187\208\190\208\180\208\186\208\176\208\188\208\184, \208\179\209\128\209\131\208\183\208\190\208\178\208\184\208\186\208\176\208\188\208\184 \208\184 \208\190\208\177\209\139\209\135\208\189\209\139\208\188\208\184 \208\184\208\179\209\128\208\190\208\178\209\139\208\188\208\184 \208\176\208\186\209\130\208\184\208\178\208\189\208\190\209\129\209\130\209\143\208\188\208\184.",
            "\208\161\208\156\208\149\208\168\208\152\208\146\208\144\208\153\208\162\208\149 \208\152\208\161\208\162\208\158\208\167\208\157\208\152\208\154\208\152 \208\148\208\158\208\165\208\158\208\148\208\144: \208\184\209\129\208\191\208\190\208\187\209\140\208\183\209\131\208\185\209\130\208\181 \208\189\208\181 \209\130\208\190\208\187\209\140\208\186\208\190 \208\186\208\190\208\189\209\130\209\128\208\176\208\177\208\176\208\189\208\180\209\131, \208\189\208\190 \208\184 \208\187\208\181\208\179\208\176\208\187\209\140\208\189\209\139\208\181 \208\188\208\181\209\133\208\176\208\189\208\184\208\186\208\184 \226\128\148 \208\191\209\128\208\184\208\189\209\130\208\181\209\128\209\139, \208\180\208\190\208\188, \208\186\208\176\208\191\209\131\209\129\209\130\209\131 \208\184 \208\180\209\128\209\131\208\179\208\184\208\181 \208\180\208\190\209\129\209\130\209\131\208\191\208\189\209\139\208\181 \209\129\208\191\208\190\209\129\208\190\208\177\209\139 \208\183\208\176\209\128\208\176\208\177\208\190\209\130\208\186\208\176.",
            "\208\161\208\154\208\158\208\160\208\158\208\161\208\162\208\172 \208\154\208\158\208\157\208\162\208\160\208\144\208\145\208\144\208\157\208\148\208\171: \208\189\208\181 \209\129\209\130\208\176\208\178\209\140\209\130\208\181 \208\178\209\139\209\136\208\181 210. \208\157\208\176 \208\177\208\190\208\187\209\140\209\136\208\181\208\185 \209\129\208\186\208\190\209\128\208\190\209\129\209\130\208\184 \209\128\208\176\209\129\209\130\209\145\209\130 \209\136\208\176\208\189\209\129 \208\191\209\128\208\190\208\191\209\131\209\129\209\130\208\184\209\130\209\140 \209\130\208\190\209\135\208\186\209\131, \208\183\208\176\209\129\209\130\209\128\209\143\209\130\209\140 \208\184\208\187\208\184 \209\129\208\187\208\190\208\188\208\176\209\130\209\140 \208\178\208\183\208\176\208\184\208\188\208\190\208\180\208\181\208\185\209\129\209\130\208\178\208\184\208\181 \209\129 NPC.",
            "\208\148\208\155\208\175 \208\162\208\149\208\161\208\162\208\158\208\146 \208\152\208\161\208\159\208\158\208\155\208\172\208\151\208\163\208\153\208\162\208\149 \208\158\208\162\208\148\208\149\208\155\208\172\208\157\208\171\208\153 \208\144\208\154\208\154\208\144\208\163\208\157\208\162: \208\189\208\181 \208\191\209\128\208\190\208\178\208\181\209\128\209\143\208\185\209\130\208\181 \208\189\208\190\208\178\209\139\208\181 \209\132\209\131\208\189\208\186\209\134\208\184\208\184 \209\129\209\128\208\176\208\183\209\131 \208\189\208\176 \208\190\209\129\208\189\208\190\208\178\208\189\208\190\208\188 \208\176\208\186\208\186\208\176\209\131\208\189\209\130\208\181, \208\181\209\129\208\187\208\184 \208\190\208\189 \208\180\208\187\209\143 \208\178\208\176\209\129 \208\178\208\176\208\182\208\181\208\189.",
            "\208\159\208\158\208\161\208\155\208\149 \208\148\208\158\208\155\208\147\208\158\208\153 \208\161\208\149\208\161\208\161\208\152\208\152: \209\129\208\180\208\181\208\187\208\176\208\185\209\130\208\181 \208\191\208\181\209\128\208\181\209\128\209\139\208\178 \208\184 \208\191\209\128\208\190\208\178\208\181\209\128\209\140\209\130\208\181 \208\180\208\181\208\189\209\140\208\179\208\184, \208\184\208\189\208\178\208\181\208\189\209\130\208\176\209\128\209\140, \208\191\208\190\208\187\208\190\208\182\208\181\208\189\208\184\208\181 \208\191\208\181\209\128\209\129\208\190\208\189\208\176\208\182\208\176 \208\184 \208\186\208\190\209\128\209\128\208\181\208\186\209\130\208\189\208\190\209\129\209\130\209\140 \208\183\208\176\208\178\208\181\209\128\209\136\208\181\208\189\208\184\209\143 \208\188\208\176\209\128\209\136\209\128\209\131\209\130\208\176.",
            "\208\159\208\160\208\152 \208\155\208\174\208\145\208\158\208\156 \208\161\208\145\208\158\208\149: \208\181\209\129\208\187\208\184 \208\188\208\190\208\180\209\131\208\187\209\140 \208\183\208\176\209\134\208\184\208\186\208\187\208\184\208\187\209\129\209\143, \208\183\208\176\208\178\208\184\209\129 \208\184\208\187\208\184 \208\180\208\178\208\184\208\179\208\176\208\181\209\130\209\129\209\143 \209\129\209\130\209\128\208\176\208\189\208\189\208\190 \226\128\148 \209\129\209\128\208\176\208\183\209\131 \208\178\209\139\208\186\208\187\209\142\209\135\208\184\209\130\208\181 \208\181\208\179\208\190. \208\157\208\181 \208\183\208\176\208\191\209\131\209\129\208\186\208\176\208\185\209\130\208\181 \208\189\208\181\209\129\208\186\208\190\208\187\209\140\208\186\208\190 \208\176\208\178\209\130\208\190\209\132\208\176\209\128\208\188\208\190\208\178 \208\190\208\180\208\189\208\190\208\178\209\128\208\181\208\188\208\181\208\189\208\189\208\190.",
        }
    },
    en={
        intro="English selected",
        warnTitle="IMPORTANT: READ BEFORE LAUNCH",
        warnSub="This is not a safety guarantee. Monitor farming manually, keep a moderate pace and disable a module immediately if it behaves strangely.",
        footer="V cannot guarantee account safety. Do not leave automation unattended and follow the game's rules.",
        wait="Wait %ds",
        go="Continue",
        tips={
            "NEW ACCOUNT \226\128\148 FIRST 7 DAYS: avoid aggressive or long unattended autofarming. Rotate contraband with boats, trucks and normal gameplay activities, and do not leave automation unattended.",
            "ROTATE ACTIVITIES: do not keep one route running continuously. Mix contraband with boats, trucks and normal gameplay activities.",
            "MIX INCOME SOURCES: do not rely only on contraband. Use legitimate mechanics too \226\128\148 printers, house income, cabbage and other available methods.",
            "CONTRABAND SPEED: do not set it above 210. Higher values increase the chance of missing points, getting stuck or breaking NPC interactions.",
            "USE A SEPARATE ACCOUNT FOR TESTING: do not test new features first on your main account if that account matters to you.",
            "AFTER A LONG SESSION: take a break and verify cash, inventory, character position and that the route completed correctly.",
            "ON ANY FAILURE: if a module loops, gets stuck or moves strangely, disable it immediately. Do not run multiple autofarms at the same time.",
        }
    }
}

local persistentStorage = type(writefile)=="function" and type(readfile)=="function" and type(isfile)=="function"
local device=loadDevice()
local session=nil
local state=nil
local busy=false
local selectedLang=nil
local countdownToken=0
local manualRequiresWait=true
local resetArmed=false
local resetArmToken=0

local function setStatus(textValue, kind)
    statusLabel.Text=textValue
    if kind=="good" then
        statusDot.BackgroundColor3=C.success
        statusLabel.TextColor3=C.textSoft
    elseif kind=="bad" then
        statusDot.BackgroundColor3=C.danger
        statusLabel.TextColor3=C.textSoft
    elseif kind=="busy" then
        statusDot.BackgroundColor3=C.warning
        statusLabel.TextColor3=C.textSoft
    else
        statusDot.BackgroundColor3=C.accent
        statusLabel.TextColor3=C.textSoft
    end
end

local function setReady(enabled)
    local list={launchFree,launchBeta,keyBtn,resetBtn,copyBtn,manualBtn,deviceBtn}
    for _,b in ipairs(list) do
        b.Active=enabled
        b.AutoButtonColor=false
    end
    if enabled then
        launchFree.TextTransparency=1
        launchBeta.TextTransparency=1
    end
end

local function refreshDeviceView()
    if device and device.id then
        deviceIdBox.Text=tostring(device.id)
    else
        deviceIdBox.Text="Device ID unavailable"
    end
end

local function setState(s)
    state=s
    local access=string.lower(tostring((s and s.access_tier) or "free"))
    local isBeta=(access=="beta")

    accessText.Text=isBeta and "BETA" or "FREE"
    accessDot.BackgroundColor3=isBeta and C.success or C.accent
    accessText.TextColor3=isBeta and C.success or C.accent2
    accessBadge.BackgroundColor3=isBeta and Color3.fromRGB(7,35,31) or Color3.fromRGB(11,31,42)
    accessStroke.Color=isBeta and C.success or C.border

    activationCard.Visible=not isBeta
    boundCard.Visible=isBeta
    betaSub.Text=isBeta and "\208\148\208\190\209\129\209\130\209\131\208\191 \208\176\208\186\209\130\208\184\208\178\208\184\209\128\208\190\208\178\208\176\208\189" or "\208\160\208\176\209\129\209\136\208\184\209\128\208\181\208\189\208\189\209\139\208\185 \208\180\208\190\209\129\209\130\209\131\208\191"
    betaSub.TextColor3=isBeta and C.success or C.accent2
    refreshDeviceView()
end

local function enrollFree()
    setReady(false)
    session=nil
    setStatus("\208\159\208\190\208\180\208\186\208\187\209\142\209\135\208\181\208\189\208\184\208\181 \208\186 NetNull...","busy")
    local data,code,err=publicJson("POST","/api/v5/enroll/free",{
        roblox_user_id=LocalPlayer.UserId,
        roblox_username=LocalPlayer.Name,
        loader_version=LOADER_VERSION,
    })
    if not data or not data.ok then
        warn("[NetNull] enrollment:",err or code)
        setStatus("\208\157\208\181 \209\131\208\180\208\176\208\187\208\190\209\129\209\140 \208\191\208\190\208\180\208\186\208\187\209\142\209\135\208\184\209\130\209\140\209\129\209\143. \208\159\208\190\208\191\209\128\208\190\208\177\209\131\208\185\209\130\208\181 \208\181\209\137\209\145 \209\128\208\176\208\183.","bad")
        return false
    end
    if data.server_time then applyServerTime(data.server_time) end
    device={id=data.device.id,secret=data.device.secret}
    local persisted=saveDevice(device)
    setState(data.state)
    if not persisted then
        setStatus("FREE \208\180\208\190\209\129\209\130\209\131\208\191\208\181\208\189. \208\148\208\187\209\143 BETA \209\130\209\128\208\181\208\177\209\131\208\181\209\130\209\129\209\143 \209\129\208\190\209\133\209\128\208\176\208\189\208\181\208\189\208\184\208\181 \209\132\208\176\208\185\208\187\208\190\208\178 executor'\208\190\208\188.","busy")
    end
    return true
end

local function createSession()
    if not device then return false,"device missing",0 end
    if not clockSynced then
        local synced,syncErr=syncServerTime()
        if not synced then return false,"clock sync failed: "..tostring(syncErr),0 end
    end
    local data,code,err=signedJson(device,nil,"POST","/api/v5/session",{loader_version=LOADER_VERSION})
    if not data or not data.ok then
        return false,err or ("HTTP "..tostring(code)),code
    end
    if data.server_time then applyServerTime(data.server_time) end
    session=data.session
    setState(data.state)
    setReady(true)
    setStatus("\208\147\208\190\209\130\208\190\208\178\208\190 \208\186 \208\183\208\176\208\191\209\131\209\129\208\186\209\131","good")
    return true,nil,code
end

local function ensureSession()
    if session then return true end
    if not device then
        if not enrollFree() then return false end
    end

    local ok,err,code=createSession()
    if ok then return true end

    -- Do not destroy a valid persisted device on a transient network/5xx error.
    -- Only a real auth rejection is allowed to rotate the device credential.
    if tonumber(code)~=401 then
        warn("[NetNull] session temporary failure:",err or code)
        setStatus("\208\161\208\181\209\128\208\178\208\181\209\128 \208\178\209\128\208\181\208\188\208\181\208\189\208\189\208\190 \208\189\208\181\208\180\208\190\209\129\209\130\209\131\208\191\208\181\208\189. \208\163\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190 \209\129\208\190\209\133\209\128\208\176\208\189\208\181\208\189\208\190.","bad")
        return false
    end

    warn("[NetNull] stored device rejected:",err)
    clearDevice()
    device=nil
    session=nil
    setStatus("\208\158\208\177\208\189\208\190\208\178\208\187\209\143\208\181\208\188 \208\191\209\128\208\184\208\178\209\143\208\183\208\186\209\131 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\176...","busy")

    if not enrollFree() then return false end
    local ok2,err2,code2=createSession()
    if not ok2 then
        warn("[NetNull] session:",err2)
        if tonumber(code2)==401 then
            setStatus("\208\157\208\181 \209\131\208\180\208\176\208\187\208\190\209\129\209\140 \208\191\208\190\208\180\209\130\208\178\208\181\209\128\208\180\208\184\209\130\209\140 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190. \208\159\209\128\208\190\208\178\208\181\209\128\209\140\209\130\208\181 \208\178\209\128\208\181\208\188\209\143/executor.","bad")
        else
            setStatus("\208\161\208\181\209\128\208\178\208\181\209\128 \208\178\209\128\208\181\208\188\208\181\208\189\208\189\208\190 \208\189\208\181\208\180\208\190\209\129\209\130\209\131\208\191\208\181\208\189. \208\159\208\190\208\191\209\128\208\190\208\177\209\131\208\185\209\130\208\181 \208\191\208\190\208\183\208\182\208\181.","bad")
        end
        return false
    end
    return true
end

local function signedBinaryJson(deviceObj, sessionToken, path, obj)
    local payload=encode(obj)
    return signedRequestRaw(
        deviceObj,
        sessionToken,
        "POST",
        path,
        payload,
        {["Accept"]="application/octet-stream",["Content-Type"]="application/json"}
    )
end

local function closeModals()
    modalDim.Visible=false
    deviceModal.Visible=false
    manual.Visible=false
end

local function showDeviceModal()
    refreshDeviceView()
    modalDim.Visible=true
    deviceModal.Visible=true
    manual.Visible=false
    resetArmed=false
    resetBtn.Text="\208\161\208\177\209\128\208\190\209\129\208\184\209\130\209\140 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190"
    resetBtn.BackgroundColor3=C.card
end

local function updateManualLanguage(lang, requireWait)
    selectedLang=lang
    local t=TEXT[lang]
    mIntro.Text=t.intro
    warnTitle.Text=t.warnTitle
    warnSub.Text=t.warnSub
    footerText.Text=t.footer
    for i=1,7 do itemLabels[i].Text=t.tips[i] end
    manualContent.Visible=true

    ruBtn.BackgroundColor3=(lang=="ru") and C.accentDeep or C.card
    enBtn.BackgroundColor3=(lang=="en") and C.accentDeep or C.card
    ruBtn.TextColor3=(lang=="ru") and C.accent2 or C.textSoft
    enBtn.TextColor3=(lang=="en") and C.accent2 or C.textSoft

    countdownToken=countdownToken+1
    local token=countdownToken
    continueBtn.Active=false

    if not requireWait then
        continueBtn.Text=t.go
        continueBtn.Active=true
        return
    end

    task.spawn(function()
        for sec=5,1,-1 do
            if token~=countdownToken or not manual.Visible then return end
            continueBtn.Text=string.format(t.wait,sec)
            task.wait(1)
        end
        if token~=countdownToken or not manual.Visible then return end
        continueBtn.Text=t.go
        continueBtn.Active=true
    end)
end

local function showManual(requireWait)
    manualRequiresWait=requireWait==true
    modalDim.Visible=true
    manual.Visible=true
    deviceModal.Visible=false
    selectedLang=nil
    manualContent.Visible=false
    mIntro.Text="\208\146\209\139\208\177\208\181\209\128\208\184\209\130\208\181 \209\143\208\183\209\139\208\186 / Choose language"
    continueBtn.Text="\208\146\209\139\208\177\208\181\209\128\208\184\209\130\208\181 \209\143\208\183\209\139\208\186"
    continueBtn.Active=false
    ruBtn.BackgroundColor3=C.card
    enBtn.BackgroundColor3=C.card
    ruBtn.TextColor3=C.textSoft
    enBtn.TextColor3=C.textSoft
end

ruBtn.MouseButton1Click:Connect(function()
    updateManualLanguage("ru",manualRequiresWait)
end)
enBtn.MouseButton1Click:Connect(function()
    updateManualLanguage("en",manualRequiresWait)
end)

continueBtn.MouseButton1Click:Connect(function()
    if not continueBtn.Active or not selectedLang then return end
    countdownToken=countdownToken+1
    closeModals()
end)

manualBtn.MouseButton1Click:Connect(function()
    if busy then return end
    showManual(false)
end)

deviceBtn.MouseButton1Click:Connect(function()
    if busy then return end
    showDeviceModal()
end)

dClose.MouseButton1Click:Connect(closeModals)

copyBtn.MouseButton1Click:Connect(function()
    if device and type(setclipboard)=="function" then
        pcall(setclipboard,device.id)
        setStatus("ID \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\176 \209\129\208\186\208\190\208\191\208\184\209\128\208\190\208\178\208\176\208\189","good")
    else
        setStatus("\208\154\208\190\208\191\208\184\209\128\208\190\208\178\208\176\208\189\208\184\208\181 \208\189\208\181\208\180\208\190\209\129\209\130\209\131\208\191\208\189\208\190 \208\178 \209\141\209\130\208\190\208\188 executor'\208\181","bad")
    end
end)

resetBtn.MouseButton1Click:Connect(function()
    if busy then return end

    if not resetArmed then
        resetArmed=true
        resetArmToken=resetArmToken+1
        local token=resetArmToken
        resetBtn.Text="\208\159\208\190\208\180\209\130\208\178\208\181\209\128\208\180\208\184\209\130\209\140 \209\129\208\177\209\128\208\190\209\129"
        resetBtn.BackgroundColor3=Color3.fromRGB(74,30,36)
        task.spawn(function()
            task.wait(6)
            if token==resetArmToken and resetArmed then
                resetArmed=false
                resetBtn.Text="\208\161\208\177\209\128\208\190\209\129\208\184\209\130\209\140 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190"
                resetBtn.BackgroundColor3=C.card
            end
        end)
        return
    end

    resetArmed=false
    resetArmToken=resetArmToken+1
    busy=true
    setReady(false)
    closeModals()
    setStatus("\208\161\208\177\209\128\208\176\209\129\209\139\208\178\208\176\208\181\208\188 \208\191\209\128\208\184\208\178\209\143\208\183\208\186\209\131...","busy")

    if device and session then
        pcall(function()
            signedJson(device,session,"POST","/api/v5/device/revoke",{})
        end)
    end

    clearDevice()
    device=nil
    session=nil
    state=nil

    local ok=enrollFree()
    if ok then ok=createSession() end
    if not ok then setStatus("\208\157\208\181 \209\131\208\180\208\176\208\187\208\190\209\129\209\140 \209\129\208\177\209\128\208\190\209\129\208\184\209\130\209\140 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190","bad") end
    busy=false
end)

local function accessErrorText(code,err,credential)
    local text=string.lower(tostring(err or ""))
    local upper=string.upper(tostring(credential or ""))
    if string.sub(upper,1,8)=="NN-BETA-" then
        return "\208\173\209\130\208\190 \209\129\209\130\208\176\209\128\209\139\208\185 BETA-\208\186\208\187\209\142\209\135. \208\159\208\190\209\129\208\187\208\181 \208\188\208\184\208\179\209\128\208\176\209\134\208\184\208\184 \208\189\209\131\208\182\208\181\208\189 recovery-\208\186\208\190\208\180."
    end
    if tonumber(code)==409 and string.find(text,"beta device limit",1,true) then
        return "BETA \209\131\208\182\208\181 \208\191\209\128\208\184\208\178\209\143\208\183\208\176\208\189\208\176 \208\186 \209\129\209\130\208\176\209\128\208\190\208\188\209\131 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\209\131. \208\152\209\129\208\191\208\190\208\187\209\140\208\183\209\131\208\185\209\130\208\181 recovery-\208\186\208\190\208\180."
    end
    if tonumber(code)==409 and string.find(text,"user binding",1,true) then
        return "\208\159\209\128\208\184\208\178\209\143\208\183\208\186\208\176 \208\183\208\176\208\189\209\143\209\130\208\176 \208\180\209\128\209\131\208\179\208\184\208\188 \208\183\208\176\208\191\209\128\208\190\209\129\208\190\208\188. \208\159\208\190\208\178\209\130\208\190\209\128\208\184\209\130\208\181 \209\135\208\181\209\128\208\181\208\183 \208\191\208\176\209\128\209\131 \209\129\208\181\208\186\209\131\208\189\208\180."
    end
    if tonumber(code)==403 and string.find(text,"recovery unavailable",1,true) then
        return "Recovery-\208\186\208\190\208\180 \208\189\208\181 \208\191\208\190\208\180\209\133\208\190\208\180\208\184\209\130 \209\141\209\130\208\190\208\188\209\131 BETA-\208\191\209\128\208\190\209\132\208\184\208\187\209\142."
    end
    if tonumber(code)==403 then
        return "\208\154\208\190\208\180 \208\189\208\181\208\180\208\181\208\185\209\129\209\130\208\178\208\184\209\130\208\181\208\187\208\181\208\189, \208\191\209\128\208\190\209\129\209\128\208\190\209\135\208\181\208\189 \208\184\208\187\208\184 \209\131\208\182\208\181 \208\184\209\129\208\191\208\190\208\187\209\140\208\183\208\190\208\178\208\176\208\189."
    end
    if tonumber(code)==401 then
        return "\208\161\208\181\209\129\209\129\208\184\209\143 \208\184\209\129\209\130\208\181\208\186\208\187\208\176. \208\159\208\190\208\178\209\130\208\190\209\128\208\184\209\130\208\181 \208\176\208\186\209\130\208\184\208\178\208\176\209\134\208\184\209\142."
    end
    return "\208\157\208\181 \209\131\208\180\208\176\208\187\208\190\209\129\209\140 \208\176\208\186\209\130\208\184\208\178\208\184\209\128\208\190\208\178\208\176\209\130\209\140 BETA: "..tostring(err or ("HTTP "..tostring(code)))
end

keyBtn.MouseButton1Click:Connect(function()
    if busy then return end

    local credential=keyBox.Text:gsub("^%s+",""):gsub("%s+$","")
    if credential=="" then
        setStatus("\208\146\208\178\208\181\208\180\208\184\209\130\208\181 BETA \208\184\208\187\208\184 recovery-\208\186\208\190\208\180","busy")
        return
    end
    if string.sub(string.upper(credential),1,8)=="NN-BETA-" then
        setStatus("\208\161\209\130\208\176\209\128\209\139\208\181 BETA-\208\186\208\187\209\142\209\135\208\184 \208\177\208\190\208\187\209\140\209\136\208\181 \208\189\208\181 \208\180\208\181\208\185\209\129\209\130\208\178\209\131\209\142\209\130. \208\157\209\131\208\182\208\181\208\189 recovery-\208\186\208\190\208\180.","bad")
        return
    end
    if not persistentStorage then
        setStatus("\208\148\208\187\209\143 BETA executor \208\180\208\190\208\187\208\182\208\181\208\189 \209\131\208\188\208\181\209\130\209\140 \209\129\208\190\209\133\209\128\208\176\208\189\209\143\209\130\209\140 \209\132\208\176\208\185\208\187\209\139","bad")
        return
    end

    busy=true
    setReady(false)
    if not ensureSession() then busy=false; setReady(true); return end

    setStatus("\208\159\209\128\208\190\208\178\208\181\209\128\209\143\208\181\208\188 \208\186\208\190\208\180...","busy")
    local data,code,err=signedJson(device,session,"POST","/api/v5/access/claim",{credential=credential})
    if not data and code==401 then
        session=nil
        if ensureSession() then
            data,code,err=signedJson(device,session,"POST","/api/v5/access/claim",{credential=credential})
        end
    end

    if not data then
        warn("[NetNull] credential:",err or code)
        setStatus(accessErrorText(code,err,credential),"bad")
    else
        keyBox.Text=""
        setState(data.state)
        local replaced=data.claim and tonumber(data.claim.replaced_devices) or 0
        if replaced and replaced>0 then
            setStatus("BETA \208\178\208\190\209\129\209\129\209\130\208\176\208\189\208\190\208\178\208\187\208\181\208\189\208\176. \208\161\209\130\208\176\209\128\208\190\208\181 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\190 \208\190\209\130\208\178\209\143\208\183\208\176\208\189\208\190.","good")
        else
            setStatus("BETA \208\176\208\186\209\130\208\184\208\178\208\184\209\128\208\190\208\178\208\176\208\189\208\176","good")
        end
    end
    setReady(true)
    busy=false
end)

local function launch(channel)
    if busy then return end
    busy=true
    setReady(false)

    if not ensureSession() then
        busy=false
        setReady(true)
        return
    end

    local upper=string.upper(channel)
    setStatus("\208\159\209\128\208\190\208\178\208\181\209\128\209\143\208\181\208\188 \208\180\208\190\209\129\209\130\209\131\208\191 \208\186 "..upper.."...","busy")

    local path="/api/v5/releases/latest?channel="..channel
    local latest,code,err=signedJson(device,session,"GET",path,nil)

    if not latest then
        if code==401 then session=nil end
        warn("[NetNull] release denied:",err or code)
        if channel=="beta" then
            setStatus("BETA \208\189\208\181\208\180\208\190\209\129\209\130\209\131\208\191\208\189\208\176 \208\180\208\187\209\143 \209\141\209\130\208\190\208\179\208\190 \209\131\209\129\209\130\209\128\208\190\208\185\209\129\209\130\208\178\208\176","bad")
        else
            setStatus("\208\160\208\181\208\187\208\184\208\183 \208\178\209\128\208\181\208\188\208\181\208\189\208\189\208\190 \208\189\208\181\208\180\208\190\209\129\209\130\209\131\208\191\208\181\208\189","bad")
        end
        busy=false
        setReady(true)
        return
    end

    local rel=latest.release
    setStatus("\208\151\208\176\208\179\209\128\209\131\208\182\208\176\208\181\208\188 "..upper.."...","busy")

    local bytes,dcode,derr=signedBinaryJson(device,session,"/api/v5/releases/download",{ticket=rel.ticket})
    if not bytes then
        if dcode==401 then session=nil end
        warn("[NetNull] download:",derr or dcode)
        setStatus("\208\157\208\181 \209\131\208\180\208\176\208\187\208\190\209\129\209\140 \208\183\208\176\208\179\209\128\209\131\208\183\208\184\209\130\209\140 \209\128\208\181\208\187\208\184\208\183","bad")
        busy=false
        setReady(true)
        return
    end

    local actual=sha256(bytes)
    if string.lower(actual)~=string.lower(tostring(rel.sha256)) then
        setStatus("\208\159\209\128\208\190\208\178\208\181\209\128\208\186\208\176 \209\132\208\176\208\185\208\187\208\176 \208\189\208\181 \208\191\209\128\208\190\208\185\208\180\208\181\208\189\208\176. \208\151\208\176\208\191\209\131\209\129\208\186 \208\190\209\130\208\188\208\181\208\189\209\145\208\189.","bad")
        busy=false
        setReady(true)
        return
    end

    -- Compile only after the downloaded bytes passed the signed-release SHA check.
    -- Keep transport bytes unchanged for hashing; strip UTF-8 BOM only for compilation.
    local compileBytes=bytes
    if #compileBytes>=3
        and string.byte(compileBytes,1)==239
        and string.byte(compileBytes,2)==187
        and string.byte(compileBytes,3)==191 then
        compileBytes=string.sub(compileBytes,4)
    end

    -- Useful diagnostics for executors with broken/nonstandard parsers.
    local firstHighByte=nil
    for i=1,#compileBytes do
        if string.byte(compileBytes,i)>127 then
            firstHighByte=i
            break
        end
    end
    if firstHighByte then
        warn("[NetNull] payload contains non-ASCII byte at:",firstHighByte)
    end

    local compileOk,fn,cerr=pcall(runtimeCompiler,compileBytes,"=NetNull/"..channel.."/"..tostring(rel.version))
    bytes=nil
    compileBytes=nil

    if not compileOk then
        cerr=fn
        fn=nil
    end
    if not fn then
        warn("[NetNull] compile:",cerr,"channel=",channel,"version=",rel.version)
        setStatus("\208\158\209\136\208\184\208\177\208\186\208\176 \208\191\208\190\208\180\208\179\208\190\209\130\208\190\208\178\208\186\208\184 \209\128\208\181\208\187\208\184\208\183\208\176. \208\159\209\128\208\190\208\178\208\181\209\128\209\140\209\130\208\181 executor/\208\178\208\181\209\128\209\129\208\184\209\142.","bad")
        busy=false
        setReady(true)
        return
    end

    setStatus(upper.." \208\179\208\190\209\130\208\190\208\178. \208\151\208\176\208\191\209\131\209\129\208\186\208\176\208\181\208\188...","good")
    task.wait(.08)

    local ok,rerr=pcall(fn)
    if not ok then
        warn("[NetNull] payload runtime error:",rerr)
        setStatus("\208\158\209\136\208\184\208\177\208\186\208\176 \208\178\208\189\209\131\209\130\209\128\208\184 \208\183\208\176\208\179\209\128\209\131\208\182\208\181\208\189\208\189\208\190\208\179\208\190 \208\188\208\190\208\180\209\131\208\187\209\143","bad")
        busy=false
        setReady(true)
        return
    end

    gui:Destroy()
end

launchFree.MouseButton1Click:Connect(function()
    launch("free")
end)

launchBeta.MouseButton1Click:Connect(function()
    launch("beta")
end)

-- Drag only from the upper header area, so buttons/cards do not accidentally move the window.
do
    local dragging=false
    local dragStart=nil
    local startPos=nil

    main.InputBegan:Connect(function(input)
        local localY=input.Position.Y-main.AbsolutePosition.Y
        if localY>88 then return end
        if input.UserInputType==Enum.UserInputType.MouseButton1 or input.UserInputType==Enum.UserInputType.Touch then
            dragging=true
            dragStart=input.Position
            startPos=main.Position
        end
    end)

    UserInputService.InputChanged:Connect(function(input)
        if dragging and (input.UserInputType==Enum.UserInputType.MouseMovement or input.UserInputType==Enum.UserInputType.Touch) then
            local d=input.Position-dragStart
            main.Position=UDim2.new(startPos.X.Scale,startPos.X.Offset+d.X,startPos.Y.Scale,startPos.Y.Offset+d.Y)
        end
    end)

    UserInputService.InputEnded:Connect(function(input)
        if input.UserInputType==Enum.UserInputType.MouseButton1 or input.UserInputType==Enum.UserInputType.Touch then
            dragging=false
        end
    end)
end

-- Polished entrance, contained inside the main bounds.
mainScale.Scale=mainScale.Scale*0.965
main.BackgroundTransparency=1
task.spawn(function()
    tw(main,.18,{BackgroundTransparency=0},Enum.EasingStyle.Quad,Enum.EasingDirection.Out)
    tw(mainScale,.22,{Scale=mainScale.Scale/0.965},Enum.EasingStyle.Back,Enum.EasingDirection.Out)
end)

-- First launch: restore the safety manual flow before the main loader is used.
showManual(true)

task.spawn(function()
    if device then
        setStatus("\208\159\208\190\208\180\208\186\208\187\209\142\209\135\208\181\208\189\208\184\208\181 \208\186 NetNull...","busy")
        local ok,err=createSession()
        if not ok then
            warn("[NetNull] saved device:",err)
            clearDevice()
            device=nil
            session=nil
            if enrollFree() then createSession() end
        end
    else
        if enrollFree() then createSession() end
    end
end)
