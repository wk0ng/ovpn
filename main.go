package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	keySize         = 2048 // RSA 密钥大小
	caExpireYears   = 10   // CA 有效期（年）
	certExpireYears = 5    // 证书有效期（年）
	dhParamBits     = 2048 // DH 参数位数
)

// 参数结构体
type Args struct {
	Host string
	Help bool
	// 可选配置
	OutputPath   string
	CommonName   string
	ProjectName  string
	Country      string
	Province     string
	City         string
	Organization string
}

// CertGenerator 证书生成器
type CertGenerator struct {
	Host         string
	OutputDir    string // 输出目录
	ProjectName  string
	Country      string // 国家
	Province     string // 省份
	Locality     string // 城市
	Organization string // 组织
	CommonName   string // 通用名称
}

// 全局变量
var args Args = Args{}

// NewCertGenerator 创建新的证书生成器
func NewCertGenerator(args Args) *CertGenerator {
	if args.ProjectName != "" {
		args.ProjectName += "_"
	} else {
		args.ProjectName = ""
	}

	return &CertGenerator{
		Host:         args.Host,
		OutputDir:    filepath.Clean(args.OutputPath),
		ProjectName:  args.ProjectName,
		Country:      args.Country,
		Province:     args.Province,
		Locality:     args.City,
		Organization: args.Organization,
		CommonName:   args.CommonName,
	}
}

// GenerateCA 生成CA证书和私钥
func (g *CertGenerator) GenerateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// 创建CA私钥
	caPrivKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("生成CA私钥失败: %v", err)
	}

	// 创建CA证书模板
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Country:      []string{g.Country},
			Province:     []string{g.Province},
			Locality:     []string{g.Locality},
			Organization: []string{g.Organization},
			CommonName:   g.CommonName + " Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caExpireYears, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// 自签名CA证书
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("创建CA证书失败: %v", err)
	}

	// 保存CA证书
	if err := g.saveCert(g.ProjectName+"ca.crt", caDER); err != nil {
		return nil, nil, err
	}

	// 保存CA私钥
	if err := g.savePrivateKey(g.ProjectName+"ca.key", caPrivKey); err != nil {
		return nil, nil, err
	}

	// 解析生成的CA证书
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	return caCert, caPrivKey, nil
}

// GenerateServerCert 生成服务器证书
func (g *CertGenerator) GenerateServerCert(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) error {
	// 创建服务器私钥
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("生成服务器私钥失败: %v", err)
	}

	// 创建服务器证书模板
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Country:      []string{g.Country},
			Province:     []string{g.Province},
			Locality:     []string{g.Locality},
			Organization: []string{g.Organization},
			CommonName:   g.CommonName + "-Server",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(certExpireYears, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{g.CommonName, "vpn.example.com"},
	}

	// 使用CA签名服务器证书
	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return fmt.Errorf("创建服务器证书失败: %v", err)
	}

	// 保存服务器证书
	if err := g.saveCert(g.ProjectName+"server.crt", serverDER); err != nil {
		return err
	}

	// 保存服务器私钥
	return g.savePrivateKey(g.ProjectName+"server.key", serverPrivKey)
}

// GenerateClientCert 生成客户端证书
func (g *CertGenerator) GenerateClientCert(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) error {
	// 创建客户端私钥
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("生成客户端私钥失败: %v", err)
	}

	// 创建客户端证书模板
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:      []string{g.Country},
			Province:     []string{g.Province},
			Locality:     []string{g.Locality},
			Organization: []string{g.Organization},
			CommonName:   g.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(certExpireYears, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// 使用CA签名客户端证书
	clientDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return fmt.Errorf("创建客户端证书失败: %v", err)
	}

	// 保存客户端证书
	if err := g.saveCert(g.ProjectName+"client.crt", clientDER); err != nil {
		return err
	}

	// 保存客户端私钥
	return g.savePrivateKey(g.ProjectName+"client.key", clientPrivKey)
}

// GenerateDHParams 生成安全的 DH 参数
func (g *CertGenerator) GenerateDHParams() error {
	start := time.Now()
	fmt.Printf("开始生成 %d 位安全素数（这可能需要几分钟）...\n", dhParamBits)

	// 使用并行算法加速生成
	p, err := generateSafePrime(dhParamBits)
	if err != nil {
		return err
	}

	elapsed := time.Since(start)
	fmt.Printf("安全素数生成完成! 耗时: %v\n", elapsed.Round(time.Second))
	fmt.Printf("素数长度: %d 位\n", p.BitLen())

	// 生成器 g 通常使用 2
	gVal := big.NewInt(2)

	// 创建 DH 参数结构
	params := struct {
		P *big.Int // 素数
		G *big.Int // 生成器
	}{
		P: p,
		G: gVal,
	}

	// ASN.1 编码
	der, err := asn1.Marshal(params)
	if err != nil {
		return fmt.Errorf("ASN.1 编码失败: %v", err)
	}

	// 创建 PEM 块
	block := &pem.Block{
		Type:  "DH PARAMETERS",
		Bytes: der,
	}

	// 保存到文件
	dhPath := filepath.Join(g.OutputDir, g.ProjectName+"dh.pem")
	file, err := os.Create(dhPath)
	if err != nil {
		return fmt.Errorf("创建DH参数文件失败: %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("写入DH参数失败: %v", err)
	}

	fmt.Printf("文件已保存到: %s\n", dhPath)

	// 打印参数摘要
	fmt.Printf("\nDH参数摘要:\n素数 p 长度: %d 位\n生成器 g: %d\n", p.BitLen(), gVal)
	return nil
}

// generateSafePrime 生成安全素数（并行优化版）
func generateSafePrime(bits int) (*big.Int, error) {
	start := time.Now()

	// 安全素数的定义：p = 2q + 1，其中 q 也是素数
	const maxAttempts = 10000
	const workers = 4 // 使用 CPU 核心数

	// 创建结果通道和取消通道
	result := make(chan *big.Int, 1)
	cancel := make(chan struct{})
	defer close(cancel)

	// 启动多个工作协程
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempt := 0
			for {
				select {
				case <-cancel:
					return // 任务已取消
				default:
					attempt++
					if attempt > maxAttempts {
						return // 超过最大尝试次数
					}

					// 1. 先生成一个素数 q (比目标位数少1位)
					q, err := rand.Prime(rand.Reader, bits-1)
					if err != nil {
						continue
					}

					// 2. 计算 p = 2q + 1
					p := new(big.Int).Mul(q, big.NewInt(2))
					p.Add(p, big.NewInt(1))

					// 3. 验证 p 是素数
					if !p.ProbablyPrime(20) {
						continue
					}

					// 4. 验证 q 是素数
					if !q.ProbablyPrime(20) {
						continue
					}

					// 5. 验证 p 是安全素数 (p = 2q + 1)
					check := new(big.Int).Sub(p, big.NewInt(1))
					check.Div(check, big.NewInt(2))

					if check.Cmp(q) == 0 {
						// 尝试发送结果
						select {
						case result <- p:
							return // 成功发送
						default:
							return // 结果已发送
						}
					}
				}
			}
		}()
	}

	// 等待结果
	var prime *big.Int
	select {
	case prime = <-result:
		// 成功获取素数
		elapsed := time.Since(start)
		fmt.Printf("在 %v 后找到安全素数\n", elapsed.Round(time.Second))
		return prime, nil
	case <-time.After(30 * time.Minute):
		// 超时处理
		return nil, fmt.Errorf("生成安全素数超时（30分钟）")
	}

	// 等待所有协程结束
	wg.Wait()

	// 检查是否找到素数
	if prime != nil {
		return prime, nil
	}
	return nil, fmt.Errorf("在 %d 次尝试后未能生成安全素数", maxAttempts*workers)
}

// saveCert 保存证书
func (g *CertGenerator) saveCert(filename string, derBytes []byte) error {
	// 确保目录存在
	if err := os.MkdirAll(g.OutputDir, 0700); err != nil {
		return err
	}

	certPath := filepath.Join(g.OutputDir, filename)
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %v", err)
	}
	defer certFile.Close()

	// 写入PEM格式
	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		return fmt.Errorf("写入证书失败: %v", err)
	}

	fmt.Printf("已生成: %s\n", certPath)
	return nil
}

// savePrivateKey 保存私钥
func (g *CertGenerator) savePrivateKey(filename string, key *rsa.PrivateKey) error {
	// 确保目录存在
	if err := os.MkdirAll(g.OutputDir, 0700); err != nil {
		return err
	}

	keyPath := filepath.Join(g.OutputDir, filename)
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer keyFile.Close()

	// 写入PEM格式
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return fmt.Errorf("写入私钥失败: %v", err)
	}

	fmt.Printf("已生成: %s\n", keyPath)
	return nil
}

// GenerateAll 生成所有证书
func (g *CertGenerator) GenerateAll() error {
	// 确保输出目录存在
	if err := os.MkdirAll(g.OutputDir, 0700); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Join(g.OutputDir, g.ProjectName+"server"), 0700); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Join(g.OutputDir, g.ProjectName+"client"), 0700); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	fmt.Println("开始生成证书...")
	fmt.Println("输出目录:", g.OutputDir)

	// 1. 生成CA
	fmt.Println("\n=== 生成CA证书 ===")
	caCert, caPrivKey, err := g.GenerateCA()
	if err != nil {
		return fmt.Errorf("生成CA失败: %v", err)
	}

	// 2. 生成服务器证书
	fmt.Println("\n=== 生成服务器证书 ===")
	if err := g.GenerateServerCert(caCert, caPrivKey); err != nil {
		return fmt.Errorf("生成服务器证书失败: %v", err)
	}

	// 3. 生成客户端证书
	fmt.Println("\n=== 生成客户端证书 ===")
	if err := g.GenerateClientCert(caCert, caPrivKey); err != nil {
		return fmt.Errorf("生成客户端证书失败: %v", err)
	}

	// 4. 生成DH参数
	fmt.Println("\n=== 生成DH参数 ===")
	if err := g.GenerateDHParams(); err != nil {
		return fmt.Errorf("生成DH参数失败: %v", err)
	}

	// 5. 复制文件
	fmt.Println("\n=== 复制文件 ===")
	serverFiles := map[string]string{
		g.ProjectName + "ca.crt":     filepath.Join(g.OutputDir, g.ProjectName+"ca.crt"),
		g.ProjectName + "ca.key":     filepath.Join(g.OutputDir, g.ProjectName+"ca.key"),
		g.ProjectName + "server.crt": filepath.Join(g.OutputDir, g.ProjectName+"server.crt"),
		g.ProjectName + "server.key": filepath.Join(g.OutputDir, g.ProjectName+"server.key"),
		g.ProjectName + "dh.pem":     filepath.Join(g.OutputDir, g.ProjectName+"dh.pem"),
	}
	clientFiles := map[string]string{
		g.ProjectName + "ca.crt":     filepath.Join(g.OutputDir, g.ProjectName+"ca.crt"),
		g.ProjectName + "client.crt": filepath.Join(g.OutputDir, g.ProjectName+"client.crt"),
		g.ProjectName + "client.key": filepath.Join(g.OutputDir, g.ProjectName+"client.key"),
	}

	for k, v := range serverFiles {
		destPath := filepath.Join(g.OutputDir, g.ProjectName+"server", k)
		err = g.CopyFile(v, destPath)
		if err != nil {
			return err
		}
	}

	for k, v := range clientFiles {
		destPath := filepath.Join(g.OutputDir, g.ProjectName+"client", k)
		err = g.CopyFile(v, destPath)
		if err != nil {
			return err
		}
	}

	// 6. 生成配置文件
	fmt.Println("\n=== 生成VPN配置文件 ===")
	if err = g.WriteServerConf(); err != nil {
		return err
	}
	if err = g.WriteClientConf(); err != nil {
		return err
	}

	// 7. 清理文件
	needCleanFiles := map[string]string{
		g.ProjectName + "ca.crt":     filepath.Join(g.OutputDir, g.ProjectName+"ca.crt"),
		g.ProjectName + "ca.key":     filepath.Join(g.OutputDir, g.ProjectName+"ca.key"),
		g.ProjectName + "server.crt": filepath.Join(g.OutputDir, g.ProjectName+"server.crt"),
		g.ProjectName + "server.key": filepath.Join(g.OutputDir, g.ProjectName+"server.key"),
		g.ProjectName + "dh.pem":     filepath.Join(g.OutputDir, g.ProjectName+"dh.pem"),
		g.ProjectName + "client.crt": filepath.Join(g.OutputDir, g.ProjectName+"client.crt"),
		g.ProjectName + "client.key": filepath.Join(g.OutputDir, g.ProjectName+"client.key"),
	}
	for k, v := range needCleanFiles {
		fmt.Printf("清理：%s\n", k)
		err := os.Remove(v)
		if err != nil {
			fmt.Printf("删除失败：%v\n", err)
		}
	}

	// 8. 输出后续操作提示
	fmt.Println("\n\n\n=== 后续操作 ===")
	fmt.Printf("1.将 %s/%s/ 目录下的文件拷贝到服务器 openvpn 配置文件夹内\n", g.OutputDir, g.ProjectName+"server")
	fmt.Println("2.服务器上执行（管理员权限）：reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v IPEnableRouter /t REG_DWORD /d 1 /f")
	fmt.Println("3.服务器设置以太网共享网络连接为：OpenVPN TAP-Windows6")
	fmt.Println("4.服务器上连接OpenVPN")
	fmt.Println("5.客户端导入配置文件并连接")

	return nil
}

func (g *CertGenerator) CopyFile(src, dest string) error {
	fmt.Printf("复制 %s -> %s\n", src, dest)

	inputFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("读取源文件失败: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer outputFile.Close()

	if _, err := io.Copy(outputFile, inputFile); err != nil {
		return fmt.Errorf("复制文件失败: %v", err)
	}

	return nil
}

func (g *CertGenerator) WriteServerConf() error {
	filename := filepath.Join(g.OutputDir, g.ProjectName+"server", g.ProjectName+"server.ovpn")
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("生成配置文件失败: %v", err)
	}
	defer file.Close()

	// 每行自动添加换行符
	fmt.Fprintln(file, "port 1194")
	fmt.Fprintln(file, "proto udp")
	fmt.Fprintln(file, "dev tun")
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "ca "+g.ProjectName+"ca.crt")
	fmt.Fprintln(file, "cert "+g.ProjectName+"server.crt")
	fmt.Fprintln(file, "key "+g.ProjectName+"server.key")
	fmt.Fprintln(file, "dh "+g.ProjectName+"dh.pem")
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "topology subnet")
	fmt.Fprintln(file, "server 10.8.0.0 255.255.255.0")
	fmt.Fprintln(file, "ifconfig-pool-persist ipp.txt")
	fmt.Fprintln(file, "push \"redirect-gateway def1 bypass-dhcp\"")
	fmt.Fprintln(file, "duplicate-cn")
	fmt.Fprintln(file, "keepalive 10 120")
	fmt.Fprintln(file, "persist-key")
	fmt.Fprintln(file, "persist-tun")
	fmt.Fprintln(file, "status openvpn-status.log")
	fmt.Fprintln(file, "verb 3")
	fmt.Fprintln(file, "explicit-exit-notify 1")

	fmt.Printf("%s....ok\n", filename)
	return nil
}

func (g *CertGenerator) WriteClientConf() error {
	filename := filepath.Join(g.OutputDir, g.ProjectName+"client", g.ProjectName+"client.ovpn")
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("生成配置文件失败: %v", err)
	}
	defer file.Close()

	// 每行自动添加换行符
	fmt.Fprintln(file, "client")
	fmt.Fprintln(file, "dev tun")
	fmt.Fprintln(file, "proto udp")
	fmt.Fprintln(file, "remote "+g.Host+" 1194")
	fmt.Fprintln(file, "resolv-retry infinite")
	fmt.Fprintln(file, "nobind")
	fmt.Fprintln(file, "persist-key")
	fmt.Fprintln(file, "persist-tun")
	fmt.Fprintln(file, "ca "+g.ProjectName+"ca.crt")
	fmt.Fprintln(file, "cert "+g.ProjectName+"client.crt")
	fmt.Fprintln(file, "key "+g.ProjectName+"client.key")
	fmt.Fprintln(file, "remote-cert-tls server")
	fmt.Fprintln(file, "verb 3")

	fmt.Printf("%s....ok\n", filename)
	return nil
}

func init() {
	InitFlags()
}

func main() {
	// 创建证书生成器
	generator := NewCertGenerator(args)

	// 执行生成流程
	if err := generator.GenerateAll(); err != nil {
		fmt.Printf("\n错误: %v\n", err)
		os.Exit(1)
	}
}
