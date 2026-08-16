--[[
    NetNull AutoGive
    Completely standalone client script.
    Inject on the alt account, choose the main account, then enable AutoGive.

    NOTE:
    This uses generic client-side character death (Humanoid.Health = 0 / BreakJoints).
    Some games use server-side custom death/drop systems. In such games the death function
    may need to be replaced with the game's own remote/event.
]]

local Players = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")
local RunService = game:GetService("RunService")
local CoreGui = game:GetService("CoreGui")

local LocalPlayer = Players.LocalPlayer

-- =========================================================
-- CONFIG
-- =========================================================

local CONFIG = {
    HoverHeight = 2.5,       -- how high above/near target to teleport
    DeathDelay = 0.15,       -- wait after arriving before dying
    RespawnTimeout = 15,     -- max wait for respawn
    CycleDelay = 0.35,       -- small delay before next cycle
}

-- =========================================================
-- STATE
-- =========================================================

local selectedPlayer = nil
local autoGiveEnabled = false
local autoGiveThread = nil
local alive = true

-- =========================================================
-- CLEAN OLD UI
-- =========================================================

local function getUiParent()
    local ok = pcall(function()
        local _ = CoreGui.Name
    end)

    if ok then
        return CoreGui
    end

    return LocalPlayer:WaitForChild("PlayerGui")
end

local uiParent = getUiParent()

local old = uiParent:FindFirstChild("NETNULL_AUTOGIVE")
if old then
    old:Destroy()
end

-- =========================================================
-- COLORS
-- =========================================================

local C = {
    Background = Color3.fromRGB(13, 14, 18),
    Panel = Color3.fromRGB(19, 21, 27),
    Panel2 = Color3.fromRGB(25, 27, 35),
    Border = Color3.fromRGB(42, 45, 58),
    Accent = Color3.fromRGB(125, 105, 255),
    Accent2 = Color3.fromRGB(155, 130, 255),
    Text = Color3.fromRGB(240, 241, 247),
    SubText = Color3.fromRGB(145, 150, 165),
    Green = Color3.fromRGB(80, 210, 135),
    Red = Color3.fromRGB(240, 85, 95),
}

-- =========================================================
-- HELPERS
-- =========================================================

local function corner(parent, radius)
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, radius)
    c.Parent = parent
    return c
end

local function stroke(parent, color, thickness, transparency)
    local s = Instance.new("UIStroke")
    s.Color = color or C.Border
    s.Thickness = thickness or 1
    s.Transparency = transparency or 0
    s.Parent = parent
    return s
end

local function tween(obj, time, props)
    TweenService:Create(
        obj,
        TweenInfo.new(time, Enum.EasingStyle.Quad, Enum.EasingDirection.Out),
        props
    ):Play()
end

local function getCharacter(player)
    player = player or LocalPlayer
    return player.Character
end

local function getHumanoid(player)
    local char = getCharacter(player)
    return char and char:FindFirstChildOfClass("Humanoid")
end

local function getRoot(player)
    local char = getCharacter(player)
    if not char then return nil end
    return char:FindFirstChild("HumanoidRootPart")
        or char:FindFirstChild("Torso")
        or char:FindFirstChild("UpperTorso")
end

local function waitForLocalCharacter(timeout)
    local started = os.clock()

    while alive and autoGiveEnabled do
        local char = LocalPlayer.Character
        local hum = char and char:FindFirstChildOfClass("Humanoid")
        local root = char and char:FindFirstChild("HumanoidRootPart")

        if char and hum and root and hum.Health > 0 then
            return char, hum, root
        end

        if os.clock() - started >= timeout then
            return nil
        end

        task.wait(0.1)
    end

    return nil
end

local function isValidTarget(player)
    return player
        and player ~= LocalPlayer
        and player.Parent == Players
end

local function killLocalCharacter()
    local char = LocalPlayer.Character
    local hum = char and char:FindFirstChildOfClass("Humanoid")

    if hum then
        pcall(function()
            hum.Health = 0
        end)
    end

    -- Fallback for executors/games where direct Health assignment is ignored locally.
    task.wait(0.05)

    if hum and hum.Health > 0 and char then
        pcall(function()
            char:BreakJoints()
        end)
    end
end

-- =========================================================
-- GUI
-- =========================================================

local Gui = Instance.new("ScreenGui")
Gui.Name = "NETNULL_AUTOGIVE"
Gui.ResetOnSpawn = false
Gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
Gui.Parent = uiParent

local Shadow = Instance.new("Frame")
Shadow.Size = UDim2.fromOffset(366, 292)
Shadow.Position = UDim2.new(0.5, -183, 0.5, -146)
Shadow.BackgroundColor3 = Color3.new(0, 0, 0)
Shadow.BackgroundTransparency = 0.55
Shadow.BorderSizePixel = 0
Shadow.Parent = Gui
corner(Shadow, 16)

local Main = Instance.new("Frame")
Main.Size = UDim2.fromOffset(360, 286)
Main.Position = UDim2.new(0.5, -180, 0.5, -143)
Main.BackgroundColor3 = C.Background
Main.BorderSizePixel = 0
Main.Parent = Gui
corner(Main, 14)
stroke(Main, C.Border, 1, 0.1)

local Header = Instance.new("Frame")
Header.Size = UDim2.new(1, 0, 0, 54)
Header.BackgroundTransparency = 1
Header.Parent = Main

local Title = Instance.new("TextLabel")
Title.Position = UDim2.fromOffset(18, 10)
Title.Size = UDim2.new(1, -90, 0, 22)
Title.BackgroundTransparency = 1
Title.Font = Enum.Font.GothamBold
Title.Text = "NetNull AutoGive"
Title.TextColor3 = C.Text
Title.TextSize = 18
Title.TextXAlignment = Enum.TextXAlignment.Left
Title.Parent = Header

local Subtitle = Instance.new("TextLabel")
Subtitle.Position = UDim2.fromOffset(18, 31)
Subtitle.Size = UDim2.new(1, -90, 0, 16)
Subtitle.BackgroundTransparency = 1
Subtitle.Font = Enum.Font.Gotham
Subtitle.Text = "alt account money-drop automation"
Subtitle.TextColor3 = C.SubText
Subtitle.TextSize = 11
Subtitle.TextXAlignment = Enum.TextXAlignment.Left
Subtitle.Parent = Header

local Brand = Instance.new("TextLabel")
Brand.AnchorPoint = Vector2.new(1, 0)
Brand.Position = UDim2.new(1, -16, 0, 15)
Brand.Size = UDim2.fromOffset(70, 20)
Brand.BackgroundTransparency = 1
Brand.Font = Enum.Font.GothamBold
Brand.Text = "by NetNull"
Brand.TextColor3 = C.Accent2
Brand.TextSize = 11
Brand.TextXAlignment = Enum.TextXAlignment.Right
Brand.Parent = Header

local Divider = Instance.new("Frame")
Divider.Position = UDim2.new(0, 14, 0, 54)
Divider.Size = UDim2.new(1, -28, 0, 1)
Divider.BackgroundColor3 = C.Border
Divider.BackgroundTransparency = 0.35
Divider.BorderSizePixel = 0
Divider.Parent = Main

-- Target box
local TargetLabel = Instance.new("TextLabel")
TargetLabel.Position = UDim2.fromOffset(18, 68)
TargetLabel.Size = UDim2.new(1, -36, 0, 18)
TargetLabel.BackgroundTransparency = 1
TargetLabel.Font = Enum.Font.GothamMedium
TargetLabel.Text = "Target player"
TargetLabel.TextColor3 = C.SubText
TargetLabel.TextSize = 12
TargetLabel.TextXAlignment = Enum.TextXAlignment.Left
TargetLabel.Parent = Main

local SelectButton = Instance.new("TextButton")
SelectButton.Position = UDim2.fromOffset(18, 91)
SelectButton.Size = UDim2.new(1, -36, 0, 38)
SelectButton.BackgroundColor3 = C.Panel
SelectButton.BorderSizePixel = 0
SelectButton.AutoButtonColor = false
SelectButton.Font = Enum.Font.GothamMedium
SelectButton.Text = "  Select player..."
SelectButton.TextColor3 = C.Text
SelectButton.TextSize = 13
SelectButton.TextXAlignment = Enum.TextXAlignment.Left
SelectButton.Parent = Main
corner(SelectButton, 8)
local selectStroke = stroke(SelectButton, C.Border, 1, 0)

local Arrow = Instance.new("TextLabel")
Arrow.AnchorPoint = Vector2.new(1, 0.5)
Arrow.Position = UDim2.new(1, -12, 0.5, 0)
Arrow.Size = UDim2.fromOffset(20, 20)
Arrow.BackgroundTransparency = 1
Arrow.Font = Enum.Font.GothamBold
Arrow.Text = "⌄"
Arrow.TextColor3 = C.SubText
Arrow.TextSize = 14
Arrow.Parent = SelectButton

local Dropdown = Instance.new("Frame")
Dropdown.Position = UDim2.fromOffset(18, 133)
Dropdown.Size = UDim2.new(1, -36, 0, 0)
Dropdown.BackgroundColor3 = C.Panel
Dropdown.BorderSizePixel = 0
Dropdown.ClipsDescendants = true
Dropdown.Visible = false
Dropdown.ZIndex = 20
Dropdown.Parent = Main
corner(Dropdown, 8)
stroke(Dropdown, C.Border, 1, 0)

local PlayerList = Instance.new("ScrollingFrame")
PlayerList.Position = UDim2.fromOffset(4, 4)
PlayerList.Size = UDim2.new(1, -8, 1, -8)
PlayerList.BackgroundTransparency = 1
PlayerList.BorderSizePixel = 0
PlayerList.ScrollBarThickness = 3
PlayerList.ScrollBarImageColor3 = C.Accent
PlayerList.CanvasSize = UDim2.new(0, 0, 0, 0)
PlayerList.AutomaticCanvasSize = Enum.AutomaticSize.Y
PlayerList.ZIndex = 21
PlayerList.Parent = Dropdown

local ListLayout = Instance.new("UIListLayout")
ListLayout.Padding = UDim.new(0, 4)
ListLayout.SortOrder = Enum.SortOrder.LayoutOrder
ListLayout.Parent = PlayerList

local StatusCard = Instance.new("Frame")
StatusCard.Position = UDim2.fromOffset(18, 145)
StatusCard.Size = UDim2.new(1, -36, 0, 52)
StatusCard.BackgroundColor3 = C.Panel
StatusCard.BorderSizePixel = 0
StatusCard.Parent = Main
corner(StatusCard, 8)

local StatusDot = Instance.new("Frame")
StatusDot.Position = UDim2.fromOffset(12, 16)
StatusDot.Size = UDim2.fromOffset(8, 8)
StatusDot.BackgroundColor3 = C.Red
StatusDot.BorderSizePixel = 0
StatusDot.Parent = StatusCard
corner(StatusDot, 999)

local StatusTitle = Instance.new("TextLabel")
StatusTitle.Position = UDim2.fromOffset(28, 8)
StatusTitle.Size = UDim2.new(1, -40, 0, 18)
StatusTitle.BackgroundTransparency = 1
StatusTitle.Font = Enum.Font.GothamMedium
StatusTitle.Text = "Stopped"
StatusTitle.TextColor3 = C.Text
StatusTitle.TextSize = 13
StatusTitle.TextXAlignment = Enum.TextXAlignment.Left
StatusTitle.Parent = StatusCard

local StatusText = Instance.new("TextLabel")
StatusText.Position = UDim2.fromOffset(28, 26)
StatusText.Size = UDim2.new(1, -40, 0, 16)
StatusText.BackgroundTransparency = 1
StatusText.Font = Enum.Font.Gotham
StatusText.Text = "Choose the account that should receive the drops"
StatusText.TextColor3 = C.SubText
StatusText.TextSize = 10
StatusText.TextXAlignment = Enum.TextXAlignment.Left
StatusText.Parent = StatusCard

local StartButton = Instance.new("TextButton")
StartButton.Position = UDim2.fromOffset(18, 209)
StartButton.Size = UDim2.new(1, -36, 0, 43)
StartButton.BackgroundColor3 = C.Accent
StartButton.BorderSizePixel = 0
StartButton.AutoButtonColor = false
StartButton.Font = Enum.Font.GothamBold
StartButton.Text = "START AUTOGIVE"
StartButton.TextColor3 = Color3.new(1, 1, 1)
StartButton.TextSize = 13
StartButton.Parent = Main
corner(StartButton, 8)

local Footer = Instance.new("TextLabel")
Footer.Position = UDim2.new(0, 18, 1, -24)
Footer.Size = UDim2.new(1, -36, 0, 14)
Footer.BackgroundTransparency = 1
Footer.Font = Enum.Font.Gotham
Footer.Text = "Inject on alt → choose main account → start"
Footer.TextColor3 = Color3.fromRGB(92, 96, 110)
Footer.TextSize = 10
Footer.TextXAlignment = Enum.TextXAlignment.Center
Footer.Parent = Main

-- =========================================================
-- DRAGGING
-- =========================================================

local dragging = false
local dragStart
local startPos

Header.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1
        or input.UserInputType == Enum.UserInputType.Touch then

        dragging = true
        dragStart = input.Position
        startPos = Main.Position
    end
end)

UserInputService.InputChanged:Connect(function(input)
    if dragging and (
        input.UserInputType == Enum.UserInputType.MouseMovement
        or input.UserInputType == Enum.UserInputType.Touch
    ) then
        local delta = input.Position - dragStart
        Main.Position = UDim2.new(
            startPos.X.Scale,
            startPos.X.Offset + delta.X,
            startPos.Y.Scale,
            startPos.Y.Offset + delta.Y
        )

        Shadow.Position = UDim2.new(
            Main.Position.X.Scale,
            Main.Position.X.Offset - 3,
            Main.Position.Y.Scale,
            Main.Position.Y.Offset - 3
        )
    end
end)

UserInputService.InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1
        or input.UserInputType == Enum.UserInputType.Touch then
        dragging = false
    end
end)

-- =========================================================
-- PLAYER DROPDOWN
-- =========================================================

local dropdownOpen = false

local function setStatus(title, text, active)
    StatusTitle.Text = title
    StatusText.Text = text
    tween(StatusDot, 0.15, {
        BackgroundColor3 = active and C.Green or C.Red
    })
end

local function closeDropdown()
    dropdownOpen = false
    tween(Dropdown, 0.16, {Size = UDim2.new(1, -36, 0, 0)})
    tween(Arrow, 0.16, {Rotation = 0})

    task.delay(0.17, function()
        if not dropdownOpen then
            Dropdown.Visible = false
        end
    end)
end

local function selectTarget(player)
    selectedPlayer = player
    SelectButton.Text = "  " .. player.DisplayName .. "  (@" .. player.Name .. ")"
    closeDropdown()

    if not autoGiveEnabled then
        setStatus(
            "Ready",
            "Target: " .. player.DisplayName,
            false
        )
    end
end

local function refreshPlayers()
    for _, child in ipairs(PlayerList:GetChildren()) do
        if child:IsA("TextButton") then
            child:Destroy()
        end
    end

    local list = {}

    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer then
            table.insert(list, player)
        end
    end

    table.sort(list, function(a, b)
        return a.Name:lower() < b.Name:lower()
    end)

    if #list == 0 then
        local Empty = Instance.new("TextLabel")
        Empty.Name = "Empty"
        Empty.Size = UDim2.new(1, 0, 0, 28)
        Empty.BackgroundTransparency = 1
        Empty.Font = Enum.Font.Gotham
        Empty.Text = "No other players"
        Empty.TextColor3 = C.SubText
        Empty.TextSize = 12
        Empty.ZIndex = 22
        Empty.Parent = PlayerList
        return
    end

    for _, player in ipairs(list) do
        local Btn = Instance.new("TextButton")
        Btn.Name = "Player_" .. player.Name
        Btn.Size = UDim2.new(1, 0, 0, 32)
        Btn.BackgroundColor3 = C.Panel2
        Btn.BackgroundTransparency = 0.35
        Btn.BorderSizePixel = 0
        Btn.AutoButtonColor = false
        Btn.Font = Enum.Font.GothamMedium
        Btn.Text = "  " .. player.DisplayName .. "  (@" .. player.Name .. ")"
        Btn.TextColor3 = C.Text
        Btn.TextSize = 12
        Btn.TextXAlignment = Enum.TextXAlignment.Left
        Btn.ZIndex = 22
        Btn.Parent = PlayerList
        corner(Btn, 6)

        Btn.MouseEnter:Connect(function()
            tween(Btn, 0.12, {
                BackgroundTransparency = 0,
                BackgroundColor3 = C.Panel2
            })
        end)

        Btn.MouseLeave:Connect(function()
            tween(Btn, 0.12, {
                BackgroundTransparency = 0.35
            })
        end)

        Btn.MouseButton1Click:Connect(function()
            selectTarget(player)
        end)
    end
end

local function openDropdown()
    refreshPlayers()
    dropdownOpen = true
    Dropdown.Visible = true
    tween(Dropdown, 0.16, {Size = UDim2.new(1, -36, 0, 120)})
    tween(Arrow, 0.16, {Rotation = 180})
end

SelectButton.MouseButton1Click:Connect(function()
    if dropdownOpen then
        closeDropdown()
    else
        openDropdown()
    end
end)

Players.PlayerRemoving:Connect(function(player)
    if selectedPlayer == player then
        selectedPlayer = nil
        SelectButton.Text = "  Select player..."

        if autoGiveEnabled then
            autoGiveEnabled = false
            setStatus("Stopped", "Target left the server", false)
            StartButton.Text = "START AUTOGIVE"
            tween(StartButton, 0.15, {BackgroundColor3 = C.Accent})
        end
    end

    if dropdownOpen then
        refreshPlayers()
    end
end)

Players.PlayerAdded:Connect(function()
    if dropdownOpen then
        refreshPlayers()
    end
end)

-- =========================================================
-- AUTOGIVE
-- =========================================================

local function teleportToTarget(localRoot, targetRoot)
    local offset = targetRoot.CFrame.LookVector * -1.5
        + Vector3.new(0, CONFIG.HoverHeight, 0)

    localRoot.AssemblyLinearVelocity = Vector3.zero
    localRoot.AssemblyAngularVelocity = Vector3.zero
    localRoot.CFrame = CFrame.new(
        targetRoot.Position + offset,
        targetRoot.Position
    )
end

local function autoGiveLoop()
    while alive and autoGiveEnabled do
        if not isValidTarget(selectedPlayer) then
            autoGiveEnabled = false
            break
        end

        local targetRoot = getRoot(selectedPlayer)

        if not targetRoot then
            setStatus(
                "Waiting",
                "Target character is not spawned",
                true
            )
            task.wait(0.25)
            continue
        end

        setStatus(
            "Respawning",
            "Waiting for alt character...",
            true
        )

        local char, hum, root = waitForLocalCharacter(CONFIG.RespawnTimeout)

        if not autoGiveEnabled then
            break
        end

        if not char or not hum or not root then
            setStatus(
                "Retrying",
                "Respawn timeout",
                true
            )
            task.wait(0.5)
            continue
        end

        if not isValidTarget(selectedPlayer) then
            autoGiveEnabled = false
            break
        end

        targetRoot = getRoot(selectedPlayer)

        if not targetRoot then
            task.wait(0.25)
            continue
        end

        setStatus(
            "Dropping",
            "Flying to " .. selectedPlayer.DisplayName,
            true
        )

        pcall(function()
            teleportToTarget(root, targetRoot)
        end)

        task.wait(CONFIG.DeathDelay)

        if not autoGiveEnabled then
            break
        end

        setStatus(
            "Dropping",
            "Killing alt near target...",
            true
        )

        killLocalCharacter()

        -- Wait until death is actually visible locally.
        local deathStart = os.clock()
        while autoGiveEnabled and hum.Parent and hum.Health > 0 do
            if os.clock() - deathStart > 2 then
                killLocalCharacter()
                break
            end
            task.wait(0.05)
        end

        task.wait(CONFIG.CycleDelay)
    end

    if alive then
        setStatus("Stopped", "AutoGive is disabled", false)
        StartButton.Text = "START AUTOGIVE"
        tween(StartButton, 0.15, {BackgroundColor3 = C.Accent})
    end
end

local function startAutoGive()
    if autoGiveEnabled then
        return
    end

    if not isValidTarget(selectedPlayer) then
        setStatus(
            "Select target",
            "Choose another player first",
            false
        )

        tween(selectStroke, 0.12, {Color = C.Red})
        task.delay(0.8, function()
            if selectStroke then
                tween(selectStroke, 0.2, {Color = C.Border})
            end
        end)

        return
    end

    autoGiveEnabled = true
    StartButton.Text = "STOP AUTOGIVE"
    tween(StartButton, 0.15, {BackgroundColor3 = C.Red})

    setStatus(
        "Active",
        "Target: " .. selectedPlayer.DisplayName,
        true
    )

    autoGiveThread = task.spawn(autoGiveLoop)
end

local function stopAutoGive()
    autoGiveEnabled = false
    setStatus("Stopped", "AutoGive is disabled", false)
    StartButton.Text = "START AUTOGIVE"
    tween(StartButton, 0.15, {BackgroundColor3 = C.Accent})
end

StartButton.MouseButton1Click:Connect(function()
    if autoGiveEnabled then
        stopAutoGive()
    else
        startAutoGive()
    end
end)

StartButton.MouseEnter:Connect(function()
    if autoGiveEnabled then
        tween(StartButton, 0.12, {
            BackgroundColor3 = Color3.fromRGB(255, 105, 115)
        })
    else
        tween(StartButton, 0.12, {
            BackgroundColor3 = C.Accent2
        })
    end
end)

StartButton.MouseLeave:Connect(function()
    if autoGiveEnabled then
        tween(StartButton, 0.12, {BackgroundColor3 = C.Red})
    else
        tween(StartButton, 0.12, {BackgroundColor3 = C.Accent})
    end
end)

SelectButton.MouseEnter:Connect(function()
    tween(selectStroke, 0.12, {Color = C.Accent})
end)

SelectButton.MouseLeave:Connect(function()
    tween(selectStroke, 0.12, {Color = C.Border})
end)

-- =========================================================
-- INITIAL STATE
-- =========================================================

setStatus(
    "Stopped",
    "Choose the account that should receive the drops",
    false
)

refreshPlayers()
