package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// InitFlags 初始化命令行参数
func InitFlags() {
	// 定义参数
	flag.StringVar(&args.Host, "H", "", "VPN服务端主机地址")
	flag.StringVar(&args.OutputPath, "o", "./vpnconf", "输出路径")
	flag.StringVar(&args.CommonName, "n", "VpnServer", "服务器通用名称")
	flag.StringVar(&args.ProjectName, "p", "", "项目名称")
	flag.StringVar(&args.Country, "c", "CN", "国家")
	flag.StringVar(&args.Province, "v", "Beijing", "省份/州")
	flag.StringVar(&args.City, "t", "Beijing", "城市")
	flag.StringVar(&args.Organization, "z", "MyCompany", "组织名称")
	flag.BoolVar(&args.Help, "h", false, "显示帮助")
	flag.Usage = ArgsUsage

	// 格式化参数
	flag.Parse()

	// 显示帮助信息
	if args.Help {
		flag.Usage()
		os.Exit(0)
	}

	CheckHostArgs()
	CheckCommonNameArgs()
	CheckOutputPathArgs()
}

func ArgsUsage() {
	fmt.Println(`Openvpn crack v1.0
Usage: ovpn.exe {<-H host> [-o output] [-n CommonName] [-p ProjectName] [-c Country] [-v Province] [-t City] [-z Organization] | [-h help]}

Options:`)
	flag.PrintDefaults()
}

// CheckHostArgs 校验Host参数
func CheckHostArgs() {
	args.Host = cleanStringArgs(args.Host)
	// 正则表达式解释：
	// ^ : 字符串开始
	// (?: ... ){3} : 非捕获分组，重复3次（匹配前3组数字和点）
	// 25[0-5] : 250-255
	// 2[0-4][0-9] : 200-249
	// 1[0-9]{2} : 100-199
	// [1-9]?[0-9] : 0-99（禁止前导零，如01无效）
	// \\. : 匹配点（需要转义）
	// $ : 字符串结束
	pattern := `^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$`

	match, _ := regexp.MatchString(pattern, args.Host)
	if !match {
		fmt.Println("Host Error")
		flag.Usage()
		os.Exit(1)
	}
}

// CheckOutputPathArgs 校验OutputPath参数
func CheckOutputPathArgs() {
	args.OutputPath = cleanStringArgs(args.OutputPath)

	if DirExists(args.OutputPath) {
		fmt.Println("OutputPath exists")
		flag.Usage()
		os.Exit(1)
	}
}

// CheckCommonNameArgs 校验CommonName参数
func CheckCommonNameArgs() {
	args.CommonName = cleanStringArgs(args.CommonName)

	if args.CommonName == "" {
		args.CommonName = "VpnServer"
	}
}

func cleanStringArgs(val string) string {
	// 清除字符串开头结尾的双引号
	if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
		val = val[1 : len(val)-2]
	}

	return val
}

// DirExists 判断文件夹是否存在
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		// 其他错误（如权限问题）也视为不存在
		return false
	}
	// 确保是目录
	return info.IsDir()
}
