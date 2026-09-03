// cipher_new.go — 第二代（PC 通道 6 算法）与第三代（新 Android 通道 9 算法）落地
//
// 结构决策（docs/08 §2.3）：本文件只新增内容，cipher.go 的旧 9 个 GUID 注册项与实现
// **一行不动**（回归红线）。映射组 6 个直接复用旧零参类型；PC 组使用参数化构造器
// （与旧零参类型并存，轻微代码重复换取旧路径零回归风险）。
//
// 参数化构造器与密钥照 debug 工具逐语句搬运（24/24 KAT 全绿 + 双 L3 实战确证：
// PC B306E770 见 docs/05 §10、新代 319FC5AB 见 docs/05 §11）。
// PC 源：算法验证/reference-c-pc/（BadGhost520/ESurfingClient-CVersion master @7f7618d，
// esp32_esurfing 同源交叉验证；AB6C8EBE 首轮密钥仲裁取 k[1]，见 docs/07 §4）。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"

	"github.com/emmansun/gmsm/sm4"
)

// ── 算法 ID 常量：第三代（新 Android 通道，0ffbf00 同步） ──
const (
	AlgoNewAesCbc     = "BB2EA626-590B-4C42-82BE-E052FCBBB88E" // = 旧 AesCbc 换 GUID
	AlgoNewAesEcb     = "DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61" // = 旧 AesEcb 换 GUID
	AlgoNewDesEdeCbc  = "9ABF4D29-34DB-4CE9-BB8C-7E371D637758" // = 旧 DesEdeCbc 换 GUID（blob=k2‖k1 层序绕回）
	AlgoNewDesEdeEcb  = "AD8BB5B0-0E72-4198-A362-96D52C1B7ED1" // = 旧 DesEdeEcb 换 GUID（EDE_k1→EDE_k2）
	AlgoNewSm4Cbc     = "D6544CFE-F2DE-459B-9B77-0F2B367EF169" // = 旧 Sm4Cbc 换 GUID（标准 SM4）
	AlgoNewSm4Ecb     = "D755A536-B551-468C-BD87-322182B223D4" // = 旧 Sm4Ecb 换 GUID（标准 SM4）
	AlgoTeaVariantEcb = "319FC5AB-EC0E-46B9-A252-2285F9DAE813" // 变体 TEA 三层 ECB（L3 实战确证）
	AlgoTeaVariantCbc = "35101415-A20F-4DFE-B00B-0B4F3B2F8C66" // 变体 TEA 三层 CBC（层序反转）
	AlgoSnow3gVariant = "07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA" // SNOW3G 变体流（密钥=旧 ZUC）
)

// ── 算法 ID 常量：第二代（PC 通道，CCTP/Linux64/1003） ──
const (
	AlgoPCDesEdeCbc = "1A7343EC-7F9B-4570-BF58-16279A81116B" // 双层 3DES-CBC（k2 层在前，与 Android 旧代层序相反）
	AlgoPCAesEcb    = "4BA5496A-2123-46A7-85F2-35956EA7BE39" // 双层 AES-ECB（E_k2 在前）
	AlgoPCAesCbc    = "45433DCF-9ECA-4BE5-83F2-F92BA0B4F291" // 双层 AES-CBC（双 IV 前缀，IV=全零）
	AlgoPCXTeaEcb   = "60639D8B-272E-4A4D-976E-AA270987A169" // XTEA 三层 ECB（变体 TEA 块函数）
	AlgoPCTeaCbc    = "AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91" // 变体 TEA 三层 CBC（本校 PC 池轮换成员）
	AlgoPCDesSixEcb = "B306E770-B7D5-49F2-A574-BCE2C5C650ED" // DES 六层 ECB（L3 实战确证）
)

// ── 第二代 PC 通道密钥（reference-c-pc/KeyData-pc.c 逐字节转录） ──
// 归约结论（docs/07 §2）：全部复用既有构造器，无新基元——
//
//	1A7343EC = CBC_k2(CBC_k1(pt))，零填充无前缀，iv1==iv2 → desEdeCbcCipher（密钥交换传入：先 k2 后 k1）
//	4BA5496A = E_k1(E_k2(pt))，零填充 → aesEcbCipher（密钥交换传入：先 k2 后 k1）
//	45433DCF = IV0‖CBC_k2(IV0‖CBC_k1(pt))，IV0=全零 → aesCbcCipher（密钥顺序正常，iv=全零）
//	60639D8B = 变体TEA三层ECB（块函数≡新代 teaEncLayer）→ teaVariantCipher（blob=uint32 小端序列化）
//	AB6C8EBE = 变体TEA三层CBC（层序同新代 35101415：加密 k2→k1→k0）→ teaVariantCipher
//	B306E770 = EDE_456→EDE_123 六层 DES-ECB → desSixPcCipher（6 独立钥）
var (
	pcDesCbcK1 = []byte{0x3C, 0x27, 0x73, 0x5A, 0x65, 0x2A, 0x54, 0x5E, 0x64, 0x41, 0x3D, 0x57, 0x73, 0x3A, 0x2F, 0x3B, 0x53, 0x28, 0x52, 0x47, 0x52, 0x44, 0x48, 0x51}
	pcDesCbcK2 = []byte{0x43, 0x74, 0x5C, 0x56, 0x5E, 0x6A, 0x22, 0x61, 0x65, 0x6E, 0x7A, 0x7A, 0x61, 0x7A, 0x2F, 0x63, 0x51, 0x44, 0x4E, 0x6B, 0x28, 0x2D, 0x27, 0x2E}
	pcDesCbcIV = []byte{0x41, 0x54, 0x74, 0x5A, 0x4C, 0x5E, 0x42, 0x5D} // iv1 == iv2（KeyData 同值）

	pcAesEcbK1 = []byte{0x77, 0x75, 0x79, 0x3E, 0x4A, 0x47, 0x56, 0x58, 0x6A, 0x5A, 0x53, 0x45, 0x66, 0x48, 0x6F, 0x27}
	pcAesEcbK2 = []byte{0x64, 0x24, 0x55, 0x75, 0x69, 0x6E, 0x2A, 0x25, 0x27, 0x59, 0x6D, 0x69, 0x57, 0x28, 0x65, 0x41}

	pcAesCbcK1 = []byte{0x46, 0x2D, 0x68, 0x78, 0x6B, 0x4F, 0x68, 0x73, 0x41, 0x50, 0x7E, 0x25, 0x22, 0x27, 0x49, 0x6F}
	pcAesCbcK2 = []byte{0x46, 0x58, 0x7D, 0x7A, 0x26, 0x4C, 0x59, 0x57, 0x42, 0x56, 0x48, 0x62, 0x41, 0x4F, 0x5F, 0x55}

	// B306E770 六钥（KeyData.c @0ffbf00；L3 实战确证）
	desSixPcK1 = []byte{0x43, 0x4D, 0x75, 0x3F, 0x3D, 0x54, 0x72, 0x49}
	desSixPcK2 = []byte{0x79, 0x7A, 0x7A, 0x49, 0x23, 0x53, 0x55, 0x51}
	desSixPcK3 = []byte{0x6C, 0x25, 0x5C, 0x7B, 0x41, 0x73, 0x77, 0x62}
	desSixPcK4 = []byte{0x75, 0x6C, 0x6A, 0x28, 0x3A, 0x48, 0x22, 0x68}
	desSixPcK5 = []byte{0x79, 0x24, 0x6C, 0x41, 0x77, 0x6F, 0x52, 0x2A}
	desSixPcK6 = []byte{0x70, 0x6A, 0x45, 0x58, 0x76, 0x73, 0x6D, 0x27}
)

// ═══════════════ 参数化构造器（照 debug/cipher.go 逐语句搬运） ═══════════════
// 与旧零参类型（cipher.go 的 AesCbc/AesEcb/...）并存：旧 9 注册项继续用旧类型。

type aesCbcCipher struct{ k1, k2, iv []byte }

func newAesCbc(k1, k2, iv []byte) *aesCbcCipher { return &aesCbcCipher{k1, k2, iv} }

func (c *aesCbcCipher) Encrypt(data []byte) ([]byte, error) {
	padded := zeroPadding(data, aes.BlockSize)

	b1, err := aes.NewCipher(c.k1)
	if err != nil {
		return nil, err
	}
	e1 := make([]byte, len(padded))
	cipher.NewCBCEncrypter(b1, c.iv).CryptBlocks(e1, padded)
	r1 := append(append([]byte{}, c.iv...), e1...)

	b2, err := aes.NewCipher(c.k2)
	if err != nil {
		return nil, err
	}
	e2 := make([]byte, len(r1))
	cipher.NewCBCEncrypter(b2, c.iv).CryptBlocks(e2, r1)

	return encodeHexUpper(append(append([]byte{}, c.iv...), e2...)), nil
}

func (c *aesCbcCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	if len(ct) < 2*aes.BlockSize || (len(ct)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	b2, err := aes.NewCipher(c.k2)
	if err != nil {
		return nil, err
	}
	d1 := make([]byte, len(ct)-aes.BlockSize)
	cipher.NewCBCDecrypter(b2, c.iv).CryptBlocks(d1, ct[aes.BlockSize:])
	if len(d1) < aes.BlockSize || (len(d1)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	b1, err := aes.NewCipher(c.k1)
	if err != nil {
		return nil, err
	}
	d2 := make([]byte, len(d1)-aes.BlockSize)
	cipher.NewCBCDecrypter(b1, c.iv).CryptBlocks(d2, d1[aes.BlockSize:])
	return zeroUnpadding(d2), nil
}

type aesEcbCipher struct{ k1, k2 []byte }

func newAesEcb(k1, k2 []byte) *aesEcbCipher { return &aesEcbCipher{k1, k2} }

func (c *aesEcbCipher) Encrypt(data []byte) ([]byte, error) {
	padded := zeroPadding(data, aes.BlockSize)
	b1, err := aes.NewCipher(c.k1)
	if err != nil {
		return nil, err
	}
	e1 := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		b1.Encrypt(e1[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	b2, err := aes.NewCipher(c.k2)
	if err != nil {
		return nil, err
	}
	e2 := make([]byte, len(e1))
	for i := 0; i < len(e1); i += aes.BlockSize {
		b2.Encrypt(e2[i:i+aes.BlockSize], e1[i:i+aes.BlockSize])
	}
	return encodeHexUpper(e2), nil
}

func (c *aesEcbCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	if len(ct) < aes.BlockSize || len(ct)%aes.BlockSize != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	b2, err := aes.NewCipher(c.k2)
	if err != nil {
		return nil, err
	}
	d1 := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		b2.Decrypt(d1[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	b1, err := aes.NewCipher(c.k1)
	if err != nil {
		return nil, err
	}
	d2 := make([]byte, len(d1))
	for i := 0; i < len(d1); i += aes.BlockSize {
		b1.Decrypt(d2[i:i+aes.BlockSize], d1[i:i+aes.BlockSize])
	}
	return zeroUnpadding(d2), nil
}

type desEdeCbcCipher struct{ k1, k2, iv []byte }

func newDesEdeCbc(k1, k2, iv []byte) *desEdeCbcCipher { return &desEdeCbcCipher{k1, k2, iv} }

func (c *desEdeCbcCipher) Encrypt(data []byte) ([]byte, error) {
	padded := zeroPadding(data, des.BlockSize)
	b1, err := des.NewTripleDESCipher(c.k1)
	if err != nil {
		return nil, err
	}
	e1 := make([]byte, len(padded))
	cipher.NewCBCEncrypter(b1, c.iv).CryptBlocks(e1, padded)
	b2, err := des.NewTripleDESCipher(c.k2)
	if err != nil {
		return nil, err
	}
	e2 := make([]byte, len(e1))
	cipher.NewCBCEncrypter(b2, c.iv).CryptBlocks(e2, e1)
	return encodeHexUpper(e2), nil
}

func (c *desEdeCbcCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	if len(ct) < des.BlockSize || len(ct)%des.BlockSize != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	b2, err := des.NewTripleDESCipher(c.k2)
	if err != nil {
		return nil, err
	}
	d1 := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b2, c.iv).CryptBlocks(d1, ct)
	b1, err := des.NewTripleDESCipher(c.k1)
	if err != nil {
		return nil, err
	}
	d2 := make([]byte, len(d1))
	cipher.NewCBCDecrypter(b1, c.iv).CryptBlocks(d2, d1)
	return zeroUnpadding(d2), nil
}

type desEdeEcbCipher struct{ k1, k2 []byte }

func newDesEdeEcb(k1, k2 []byte) *desEdeEcbCipher { return &desEdeEcbCipher{k1, k2} }

func (c *desEdeEcbCipher) Encrypt(data []byte) ([]byte, error) {
	padded := zeroPadding(data, des.BlockSize)
	b1, err := des.NewTripleDESCipher(c.k1)
	if err != nil {
		return nil, err
	}
	e1 := make([]byte, len(padded))
	for i := 0; i < len(padded); i += des.BlockSize {
		b1.Encrypt(e1[i:i+des.BlockSize], padded[i:i+des.BlockSize])
	}
	b2, err := des.NewTripleDESCipher(c.k2)
	if err != nil {
		return nil, err
	}
	e2 := make([]byte, len(e1))
	for i := 0; i < len(e1); i += des.BlockSize {
		b2.Encrypt(e2[i:i+des.BlockSize], e1[i:i+des.BlockSize])
	}
	return encodeHexUpper(e2), nil
}

func (c *desEdeEcbCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	if len(ct) < des.BlockSize || len(ct)%des.BlockSize != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	b2, err := des.NewTripleDESCipher(c.k2)
	if err != nil {
		return nil, err
	}
	d1 := make([]byte, len(ct))
	for i := 0; i < len(ct); i += des.BlockSize {
		b2.Decrypt(d1[i:i+des.BlockSize], ct[i:i+des.BlockSize])
	}
	b1, err := des.NewTripleDESCipher(c.k1)
	if err != nil {
		return nil, err
	}
	d2 := make([]byte, len(d1))
	for i := 0; i < len(d1); i += des.BlockSize {
		b1.Decrypt(d2[i:i+des.BlockSize], d1[i:i+des.BlockSize])
	}
	return zeroUnpadding(d2), nil
}

type sm4CbcCipher struct{ key, iv []byte }

func newSm4Cbc(key, iv []byte) *sm4CbcCipher { return &sm4CbcCipher{key, iv} }

func (c *sm4CbcCipher) Encrypt(data []byte) ([]byte, error) {
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Padding(data, block.BlockSize())
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, c.iv).CryptBlocks(encrypted, padded)
	return encodeHexUpper(encrypted), nil
}

func (c *sm4CbcCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	if len(ct) < block.BlockSize() || len(ct)%block.BlockSize() != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	decrypted := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, c.iv).CryptBlocks(decrypted, ct)
	return pkcs7Unpadding(decrypted, block.BlockSize())
}

type sm4EcbCipher struct{ key []byte }

func newSm4Ecb(key []byte) *sm4EcbCipher { return &sm4EcbCipher{key} }

func (c *sm4EcbCipher) Encrypt(data []byte) ([]byte, error) {
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Padding(data, block.BlockSize())
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += block.BlockSize() {
		block.Encrypt(encrypted[i:i+block.BlockSize()], padded[i:i+block.BlockSize()])
	}
	return encodeHexUpper(encrypted), nil
}

func (c *sm4EcbCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	block, err := sm4.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	if len(ct) < block.BlockSize() || len(ct)%block.BlockSize() != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	decrypted := make([]byte, len(ct))
	for i := 0; i < len(ct); i += block.BlockSize() {
		block.Decrypt(decrypted[i:i+block.BlockSize()], ct[i:i+block.BlockSize()])
	}
	return pkcs7Unpadding(decrypted, block.BlockSize())
}

// ═══════════════ PC 六层 DES-ECB（第二代 B306E770，实测下发，L3 实战确证） ═══════════════
// 照 reference-c-pc/des_ecb_six_pc.c 层序：
//   加密 = E(K4)D(K5)E(K6) 接 E(K1)D(K2)E(K3) = EDE_456 后 EDE_123
//   解密 = D(K3)E(K2)D(K1) 接 D(K6)E(K5)D(K4)（逆序，标准 3DES 逆）
// 零填充到 8（空输入 C 返回 NULL，本实现返回错误）；解密去尾零。

type desSixPcCipher struct{ b123, b456 cipher.Block }

func newDesSixPc(k1, k2, k3, k4, k5, k6 []byte) (*desSixPcCipher, error) {
	b123, err := des.NewTripleDESCipher(append(append([]byte{}, k1...), append(append([]byte{}, k2...), k3...)...))
	if err != nil {
		return nil, err
	}
	b456, err := des.NewTripleDESCipher(append(append([]byte{}, k4...), append(append([]byte{}, k5...), k6...)...))
	if err != nil {
		return nil, err
	}
	return &desSixPcCipher{b123: b123, b456: b456}, nil
}

func (c *desSixPcCipher) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input (C pad_2_multiple returns NULL)")
	}
	padded := zeroPadding(data, des.BlockSize)
	out := make([]byte, len(padded))
	t := make([]byte, des.BlockSize)
	for i := 0; i < len(padded); i += des.BlockSize {
		c.b456.Encrypt(t, padded[i:i+des.BlockSize]) // EDE(K4,K5,K6)
		c.b123.Encrypt(out[i:i+des.BlockSize], t)    // EDE(K1,K2,K3)
	}
	return encodeHexUpper(out), nil
}

func (c *desSixPcCipher) Decrypt(data []byte) ([]byte, error) {
	ct, err := decodeHex(data)
	if err != nil {
		return nil, err
	}
	if len(ct) < des.BlockSize || len(ct)%des.BlockSize != 0 {
		return nil, ErrInvalidCiphertextLength
	}
	out := make([]byte, len(ct))
	t := make([]byte, des.BlockSize)
	for i := 0; i < len(ct); i += des.BlockSize {
		c.b123.Decrypt(t, ct[i:i+des.BlockSize])  // D(K3)E(K2)D(K1)
		c.b456.Decrypt(out[i:i+des.BlockSize], t) // D(K6)E(K5)D(K4)
	}
	return zeroUnpadding(out), nil
}

// ═══════════════ 注册表扩展（三代 24 全集） ═══════════════
// 用 init() 追加，cipher.go 的旧 9 项与实现零改动（红线）。
// 变体/PC 实例为包级单例：构造后不可变（Encrypt/Decrypt 只读状态），并发安全。

func mustTeaVariantCipher(blob, iv []byte) *teaVariantCipher {
	c, err := newTeaVariant(blob, iv)
	if err != nil {
		panic("cipher_new: " + err.Error()) // 常量错误，启动期即暴露
	}
	return c
}

func mustDesSixPcCipher(k1, k2, k3, k4, k5, k6 []byte) *desSixPcCipher {
	c, err := newDesSixPc(k1, k2, k3, k4, k5, k6)
	if err != nil {
		panic("cipher_new: " + err.Error())
	}
	return c
}

var (
	cipherTeaVariantEcb = mustTeaVariantCipher(teaEcbBlob, nil)
	cipherTeaVariantCbc = mustTeaVariantCipher(teaCbcBlob, teaCbcIVBlob[:8])
	cipherSnow3gVariant = newSnow3gVariant(zucKey, zucIv)
	cipherPCDesSix      = mustDesSixPcCipher(desSixPcK1, desSixPcK2, desSixPcK3, desSixPcK4, desSixPcK5, desSixPcK6)
	cipherPCXTeaEcb     = mustTeaVariantCipher(pcXTeaBlob, nil)
	cipherPCTeaCbc      = mustTeaVariantCipher(pcTeaCbcBlob, pcTeaCbcIV)
)

func init() {
	// ── 第三代：映射组（结构=旧实现，密钥复用；docs/08 §2.1 归约验证）──
	cipherRegistry[AlgoNewAesCbc] = func() Cipher { return new(AesCbc) }
	cipherRegistry[AlgoNewAesEcb] = func() Cipher { return new(AesEcb) }
	cipherRegistry[AlgoNewDesEdeCbc] = func() Cipher { return new(DesEdeCbc) }
	cipherRegistry[AlgoNewDesEdeEcb] = func() Cipher { return new(DesEdeEcb) }
	cipherRegistry[AlgoNewSm4Cbc] = func() Cipher { return new(Sm4Cbc) }
	cipherRegistry[AlgoNewSm4Ecb] = func() Cipher { return new(Sm4Ecb) }

	// ── 第三代：移植组（真变体，逐语句照 reference-c @0ffbf00 转录）──
	cipherRegistry[AlgoTeaVariantEcb] = func() Cipher { return cipherTeaVariantEcb } // L3 实战确证（docs/05 §11）
	cipherRegistry[AlgoTeaVariantCbc] = func() Cipher { return cipherTeaVariantCbc }
	cipherRegistry[AlgoSnow3gVariant] = func() Cipher { return cipherSnow3gVariant }

	// ── 第二代：PC 通道 6 算法 ──
	cipherRegistry[AlgoPCDesSixEcb] = func() Cipher { return cipherPCDesSix } // L3 实战确证（docs/05 §10）
	// 1A7343EC：C 加密先 CBC_k2 后 CBC_k1（与 Android 旧 5BFBA864 层序相反）→ 密钥交换传入
	cipherRegistry[AlgoPCDesEdeCbc] = func() Cipher { return newDesEdeCbc(pcDesCbcK2, pcDesCbcK1, pcDesCbcIV) }
	// 4BA5496A：C 加密先 E_k2 后 E_k1（与 Android 旧 A474B1C2 层序相反）→ 密钥交换传入
	cipherRegistry[AlgoPCAesEcb] = func() Cipher { return newAesEcb(pcAesEcbK2, pcAesEcbK1) }
	// 45433DCF：内层 CBC_k1（IV 前缀）、外层 CBC_k2（IV 前缀），双 IV 全零 → 与旧 AesCbc 同构
	cipherRegistry[AlgoPCAesCbc] = func() Cipher { return newAesCbc(pcAesCbcK1, pcAesCbcK2, make([]byte, 16)) }
	// 60639D8B：块函数≡新代变体 TEA（加法混合公式、32 轮），加密层序 k1→k2→k3
	cipherRegistry[AlgoPCXTeaEcb] = func() Cipher { return cipherPCXTeaEcb }
	// AB6C8EBE：层序同新代 35101415（加密 k2→k1→k0）；首轮密钥取通式 k[1]
	// （上游 C 加密首轮写 k[3] 与其自身解密矛盾，判为转录噪声，docs/07 §4；本校 PC 池含此 GUID，待实战裁决）
	cipherRegistry[AlgoPCTeaCbc] = func() Cipher { return cipherPCTeaCbc }
}
