# 自动共享 Windows 的文件夹到 Docker 主机
## git clone https://github.com/huzhenghui/share-windows-folder-to-docker
## share-windows-folder-to-docker/share-windows-folder-to-docker.ps1
## Docker for Windows 使用 Hyper-V，而 Hyper-V 自身并没有包含设备驱动方式的文件共享，因此只能使用 Windows 自带的 SMB 文件共享，SMB 也称 CIFS
## Docker for Windows 的客户端可以使用图形界面设置文件共享，不过技术实现方式也是 SMB，而且自动创建的文件共享对于局域网是开放的，未免有安全隐患
# 本脚本用于使用 Docker-Machine 命令可以访问到的 Docker 主机
## 可以用于使用 Docker-Machine 命令在本机 Hyper-V 中创建的 Docker 虚拟机中共享文件，也就是 Host Windows - Guest Linux - Docker
## 也可以用于本机使用 Docker-Machine 命令可以管理的在相同局域网内的其他 Docker 主机，也就是 Windows - Intranet - Linux - Docker
## 本脚本假设 Docker-Machine 命令能查询到至少一台 Docker 主机，如果该 Docker 主机安装在当前 Windows 的 Hyper-V 中，则可以采用虚拟交换机方式保证在相同局域网
## 使用 Hyper-V 的虚拟交换机方式创建虚拟机的命令类似于：docker-machine create -d hyperv --hyperv-virtual-switch "myswitch" myvm1
# 本脚本运行时自动创建用于共享的用户，自动创建共享文件夹，自动在 Docker 主机中加载，并生成用于测试的命令
# 本脚本中的密码不仅随机生成，而且密码不保存在任何持久存储。不过仍旧建议不要在 Windows 的系统文件夹中运行本脚本，避免共享系统文件夹导致的安全隐患
# 免责声明：本脚本涉及技术较多，包括：PowerShell、Unix Shell、WMI、Docker，而且需要运行在管理员角色，在不同环境可能导致难以预期的结果，仅供学习参考
# 本脚本使用方法：创建一个英文名称的文件夹，其中创建一个 .ps1 文件，把本脚本的内容完整复制进去，然后运行 PowerShell 管理员控制台，进入文件夹，运行脚本
# 参数
## -workingDir 要共享的文件夹，如果不提供，或者不是文件夹，则使用当前文件夹
## -machineName Docker 主机的名称，应处于 docker-machine ls 列表中，如果不提供或者不存在或者不处于 Running 状态，则使用 docker-machine ls 列表中处于 Running 状态的第一台主机
## -volumeName 共享到 Docker 主机上的卷的名称，如果不提供，则自动生成
## -sharePath 共享的文件夹名称，如果不提供，则自动生成，该参数自动传入 Docker 主机，使用时并不涉及
## -userName 共享的文件夹的用户，如果不提供，则自动生成，该参数自动传入 Docker 主机，使用时并不涉及
## -password 共享的文件夹的用户的密码，如果不提供，则自动生成，该参数自动传入 Docker 主机，使用时并不涉及
## -replaceVolume 当 Docker 主机上包含同名的卷的名称时，替换已有设置，否则退出
Param(
    [string]$workingDir,
    [string]$machineName,
    [string]$volumeName,
    [string]$sharePath,
    [string]$userName,
    [string]$password,
    [switch]$replaceVolume
)
# 常量
## 安全字符
$safe_charactors = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
# 参数
## workingDir
### 判断要共享的文件夹，如果不提供，或者不是文件夹，则使用当前文件夹
if ([string]::IsNullOrEmpty($workingDir))
{
    $workingDir = (Get-Location).Path
}
else
{
    $workingDir = (Resolve-Path $workingDir).Path
    if ([string]::IsNullOrEmpty($workingDir))
    {
        $workingDir = (Get-Location).Path
    }
    elseif (-Not ([io.Directory]::Exists($workingDir)))
    {
        $workingDir = (Get-Location).Path
    }
    if([string]::IsNullOrEmpty([System.IO.Path]::GetFileName($workingDir)))
    {
        $workingDir = [System.IO.Path]::GetDirectoryName($workingDir)
    }
}
echo "Working Directory : " $workingDir
### 获取路径的最后一段，也就是文件夹名，由于后面会多次使用该文件夹名，避免出现字符集问题建议使用纯英文，或者手工设置
$directory_name = [System.IO.Path]::GetFileName($workingDir)
echo "Directory Name : " $directory_name
### 为了避免文件夹名重复，通过计算路径的散列值区分
### 把字符串转换成内存中的流计算散列值，从这里也可以看出 PowerShell 实现的合理性，因为 PowerShell 中的字符串是字符，而散列值需要按照字节计算，因此需要按照字符集转换，此处使用 MD5 算法
$directory_hash = Get-FileHash -Algorithm MD5 -InputStream ([System.IO.MemoryStream]::new((new-object -TypeName System.Text.UTF8Encoding).GetBytes($workingDir))) | Select-Object -ExpandProperty Hash
echo "Directory Hash : " $directory_hash
### 为了避免路径中的非ASCII字符，对文件夹名进行过滤
$directory_filter_name = ""
foreach($c in $directory_name.ToCharArray()) {if ($safe_charactors.Contains($c)) {$directory_filter_name += $c}}
echo "Directory Filter Name : " $directory_filter_name
## volumeName
### 判断是否设置了卷参数
if([string]::IsNullOrEmpty($volumeName))
{
    ### 卷的名称，使用前缀和散列值区分
    $volumeName = -Join('Share_for_Docker_', $directory_filter_name, '_', $directory_hash)
}
## sharePath
### 判断是否设置了共享路径参数
if([string]::IsNullOrEmpty($sharePath))
{
    ### 共享文件夹名称，使用前缀和散列值区分
    $sharePath = -Join('Share_for_Docker_', $directory_filter_name, '_', $directory_hash)
}
echo "Share Path : " $sharePath
## userName
### 判断是否设置了用户名参数
if([string]::IsNullOrEmpty($userName))
{
    ### 用于共享的用户名增加 Docker 前缀，以便于未来管理
    $userName = -Join('Docker_', $directory_filter_name)
    ### 由于 Windows 用户的用户名最长 20 字符，为了后面的散列值，按照 13 个字符截断
    if ($userName.Length -gt 13) {$userName = $userName.Substring(0, 13)}
    ### 用户名增加散列值作为后缀
    $userName = -Join($userName, '_', $directory_hash)
    ### 由于 Windows 用户的用户名最长 20 字符，按照 20 个字符截断
    if ($userName.Length -gt 20) {$userName = $userName.Substring(0, 20)}
}
echo "User Name :" $userName
## password
### 判断是否设置了密码参数
if([string]::IsNullOrEmpty($password))
{
    ### 密码使用随机自动生成
    for($password = $Null ; $password.length -le 32; $password += "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray() | Get-Random){}
}
echo "Password Generated"
# 判断参数
## machineName
### 判断是否设置了 machineName 参数
if(-not [string]::IsNullOrEmpty($machineName))
{
    ### 判断是否存在名称为 machineName 且正在运行的 Docker 主机
    if((docker-machine ls --filter 'STATE=Running' --filter "Name=${machineName}" --format '{{.Name}}') -eq $Null)
    {
        ### 如果不存在说明 machineName 参数无效，设置为空
        $machineName = $Null
    }
}
### 判断是否设置了 machineName 参数
if([string]::IsNullOrEmpty($machineName))
{
    $machineName = $(docker-machine ls --filter 'STATE=Running' --format "{{.Name}}" | Select-Object -First 1)
}
### 判断是否设置了 machineName 参数
if([string]::IsNullOrEmpty($machineName))
{
    echo 'machineName invalid and/or no running docker machine'
    exit
}
echo "Machine Name : " $machineName
### docker 环境变量
### 使用 docker-machine 命令生成环境变量并运行，以便于后续的的 docker 命令直接使用，注意此处为了解决中文问题做了转码，
foreach ($line in (& "C:\Program Files\Docker\Docker\Resources\bin\docker-machine.exe" env $machineName))
{
[System.Text.Encoding]::GetEncoding("utf-8").GetString([System.Text.Encoding]::GetEncoding("gb2312").GetBytes($line)) |  Invoke-Expression
}
## volumeName
### 判断是否存在名称为 volumeName 的卷
if((docker volume ls --filter "Name=${volumeName}" --format '{{.Name}}') -ne $Null)
{
    echo 'Volume Name exist : ' $volumeName
    if($replaceVolume.IsPresent)
    {
        echo 'Remove Existence volume'
        docker volume rm --force ${volumeName}
        echo 'Existence volume removed'
    }
    else
    {
        exit
    }
}
## sharePath
### 判断共享路径是否存在
#[WMICLASS]"WIN32_Share"
if((Get-WmiObject -Class Win32_Share -Filter "name = '$sharePath'") -ne $Null)
{
    ### 共享路径存在的时候退出，由人工处理
    echo "Share path exist : " $sharePath
    exit
}
## userName
### 判断用户名是否存在
if((Get-WmiObject -Class Win32_UserAccount -Filter "name = '${userName}'") -ne $Null)
{
    ### 用户存在的时候退出，由人工处理
    echo "User Exist : " $userName
    exit
}
# 创建用户
$winnt_localhost = [ADSI]"WinNT://localhost"
## 创建用户对象
$new_user = $winnt_localhost.create("user", $userName)
## 设置密码
$new_user.setpassword($password)
## 设置信息，用户只有设置信息后才会创建，因此没有参数也要调用
$new_user.setinfo()
## 设置这个账户的密码永远不过期
Get-WmiObject -Class Win32_UserAccount -Filter "name = '${username}'" | Set-WmiInstance -Argument @{PasswordExpires = 0}
# 文件夹权限
## 创建一个访问规则
$access_rule = New-Object System.Security.AccessControl.FileSystemAccessRule($userName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
## 获取当前路径的访问控制列表
$acl = Get-Acl $workingDir
## 在访问控制列表中添加访问规则
$acl.SetAccessRule($access_rule)
## 在当前路径中设置访问控制列表
Set-Acl -Path $workingDir -AclObject $acl
# 共享文件夹
## 创建一个信任用户对象
$Trustee = ([wmiclass]'Win32_trustee').psbase.CreateInstance()
## 设置信任用户的名字
$Trustee.Name = $userName
## 设置信任用户的域，本地域为空
$Trustee.Domain = $Null
## 创建一个访问控制对象
$ACE = ([WMIClass] "Win32_ACE").psbase.CreateInstance()
## 访问控制的掩码，Magic Number，具体含义请自行搜索
$ACE.AccessMask = 2032127
## 访问控制的标志
$ACE.AceFlags = 3
## 访问控制的类型
$ACE.AceType = 0
## 访问控制的信任用户
$ACE.Trustee = $Trustee
## 创建一个安全描述对象
$sd = ([WMIClass] "Win32_SecurityDescriptor").psbase.CreateInstance()
## 安全描述的标志
$sd.ControlFlags = 4
## 安全描述的访问控制
$sd.DACL = $ACE
## 安全描述的信任用户组
$sd.group = $Trustee
## 安全描述的信任用户
$sd.owner = $Trustee
## 获得共享对象
$Share = [WMICLASS]"WIN32_Share"
## 为当前文件夹创建共享文件夹
$Share.Create($workingDir, $sharePath, 0, $Null, "Share for Docker", "", $sd)
# 在虚拟机中运行脚本获取 Host Windows 的IP地址
## 此处欢迎集思广益：这种获取IP的方法不是很优雅，比较hack。先获取tty，然后切掉前面的/dev/，使用虚拟机上的w命令，按照tty过滤，最后输出第三个字段
$local_ip = $(docker-machine ssh $machineName 'tty=$(tty | cut -c 6-); w -i | grep $tty | awk ''{print $3;}''')
echo "Local IP : " $local_ip
# 加载共享文件夹
docker volume create --driver local --opt type=cifs --opt device=//${local_ip}/${sharePath} --opt o=username=${userName},password=${password} --name ${volumeName}
#演示命令
echo 'demo:'
## 这个命令在共享文件夹中随机创建一个文件
echo "docker run --rm -v ${volumeName}:/share alpine touch (get-date -Format '/\s\h\are/yyyy-MM-dd-HH-mm-ss-fffffff.\tx\t')"
## 这个命令列出共享文件夹，可以查询到刚才创建的文件
echo "docker run --rm -v ${volumeName}:/share alpine ls /share"
echo ""
echo "WARNING : '...input/output error' is a known error. This may occur with mobile storage devices"