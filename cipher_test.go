// cipher_test.go — 算法层测试（L1）
//
// 覆盖（docs/08 §2.4 / Phase D）：
//  1. KAT 对拍：testdata/kat/*.json（新代 9 + PC 6，共 15 个文件）——真值由
//     debug/tools/kat_oracle.py 从 reference-c @0ffbf00 / reference-c-pc 独立转录生成，
//     加密与解密双向逐字节断言；
//  2. 24 ID roundtrip：全部注册算法加密后解密还原（含边界长度）；
//  3. 未知 GUID：NewCipher 返回 nil（Auth 层据此触发 UA 回退/明确报错）；
//  4. 交叉断言：映射组新 GUID 与对应旧 GUID 对同一明文输出必须一致（同钥同构的直接证明）；
//  5. 密钥等价性：新代 TEA blob / SNOW3G 密钥与旧代常量的镜像关系（02 规格 §1.1）。
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type katCase struct {
	Pt    string `json:"pt"`
	Ct    string `json:"ct"`
	PtOut string `json:"pt_out"`
}

type katDoc struct {
	Algo  string    `json:"algo"`
	Kind  string    `json:"kind"`
	Cases []katCase `json:"cases"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestKATVectors 逐字节对拍全部 KAT（加密方向 + 解密方向）
func TestKATVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "kat", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no KAT files found: %v", err)
	}
	if len(files) != 15 {
		t.Fatalf("expected 15 KAT files (9 new-gen + 6 PC), got %d", len(files))
	}

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var doc katDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		if len(doc.Cases) == 0 {
			t.Fatalf("%s: empty cases", file)
		}

		c := NewCipher(doc.Algo)
		if c == nil {
			t.Fatalf("%s: algo %s not registered", file, doc.Algo)
		}

		for i, tc := range doc.Cases {
			pt := mustHex(t, tc.Pt)

			ct, err := c.Encrypt(pt)
			if err != nil {
				t.Fatalf("%s case%d: encrypt error: %v", doc.Algo, i, err)
			}
			if !strings.EqualFold(string(ct), tc.Ct) {
				t.Fatalf("%s case%d: encrypt mismatch\n  pt=%s\n  got=%s\n  want=%s",
					doc.Algo, i, tc.Pt, shortHex(ct), shortHexStr(tc.Ct))
			}

			dec, err := c.Decrypt([]byte(tc.Ct))
			if err != nil {
				t.Fatalf("%s case%d: decrypt error: %v", doc.Algo, i, err)
			}
			if !bytes.Equal(dec, mustHex(t, tc.PtOut)) {
				t.Fatalf("%s case%d: decrypt mismatch\n  got=%x\n  want=%s", doc.Algo, i, dec, tc.PtOut)
			}
		}
	}
}

func shortHex(b []byte) string {
	s := hex.EncodeToString(b)
	if len(s) > 48 {
		return s[:48] + "…"
	}
	return s
}

func shortHexStr(s string) string {
	if len(s) > 48 {
		return s[:48] + "…"
	}
	return s
}

// allRegisteredAlgoIDs 返回注册表全部 GUID（排序以保证输出稳定）
func allRegisteredAlgoIDs() []string {
	ids := make([]string, 0, len(cipherRegistry))
	for id := range cipherRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// TestRegistry24IDs 注册表必须有且仅有 24 个 GUID（三代全集）
func TestRegistry24IDs(t *testing.T) {
	ids := allRegisteredAlgoIDs()
	if len(ids) != 24 {
		t.Fatalf("registry must hold 24 algo ids (old 9 + new 9 + pc 6), got %d: %v", len(ids), ids)
	}
}

// TestRoundTripAllAlgorithms 24 ID 全部加密→解密还原
func TestRoundTripAllAlgorithms(t *testing.T) {
	samples := [][]byte{
		[]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><user-agent>CCTP/android11_64/2104</user-agent><client-id>4395a527-1111-2222-3333-444444444444</client-id></request>"),
		[]byte("a"),
		[]byte("12345678"),               // 8B 对齐
		[]byte("123456789"),              // 8B+1
		[]byte("0123456789abcdef"),       // 16B 对齐
		[]byte("\x00a\x00bc"),            // 含零（⚠️ 不以零结尾：去零语义会截断尾部 NUL，协议 XML 不存在此形态，见 算法验证/02 §2.4）
		[]byte(strings.Repeat("x", 257)), // 跨多块
	}

	for _, id := range allRegisteredAlgoIDs() {
		c := NewCipher(id)
		if c == nil {
			t.Fatalf("algo %s: registered but NewCipher returned nil", id)
		}
		for _, pt := range samples {
			ct, err := c.Encrypt(pt)
			if err != nil {
				t.Fatalf("algo %s: encrypt len=%d: %v", id, len(pt), err)
			}
			dec, err := c.Decrypt(ct)
			if err != nil {
				t.Fatalf("algo %s: decrypt len=%d: %v", id, len(ct), err)
			}
			if !bytes.Equal(dec, pt) {
				t.Fatalf("algo %s: roundtrip mismatch (len=%d)\n  got=%x\n  want=%x", id, len(pt), dec, pt)
			}
		}
	}
}

// TestUnknownAlgoIDReturnsNil 未知 GUID 必须返回 nil（回退链触发条件之一）
func TestUnknownAlgoIDReturnsNil(t *testing.T) {
	for _, id := range []string{
		"376412D4-0000-0000-0000-000000000000", // Windows 族未知 GUID（uaprobe 实测形态）
		"634D7C6F-0000-0000-0000-000000000000", // Mac 族未知 GUID
		"",
		"not-a-guid",
	} {
		if c := NewCipher(id); c != nil {
			t.Fatalf("NewCipher(%q) must return nil", id)
		}
	}
}

// TestMappedNewEqualsOld 交叉断言：映射组新 GUID 输出 == 对应旧 GUID 输出（同钥同构）
func TestMappedNewEqualsOld(t *testing.T) {
	pairs := []struct{ newID, oldID string }{
		{AlgoNewAesCbc, AlgoAesCbc},
		{AlgoNewAesEcb, AlgoAesEcb},
		{AlgoNewDesEdeCbc, AlgoDesEdeCbc},
		{AlgoNewDesEdeEcb, AlgoDesEdeEcb},
		{AlgoNewSm4Cbc, AlgoSm4Cbc},
		{AlgoNewSm4Ecb, AlgoSm4Ecb},
	}
	pts := [][]byte{
		[]byte("<?xml version=\"1.0\"?><request><ticket>990d847136ffac085d5c45b22e3a4eff</ticket></request>"),
		[]byte("12345678"),
		[]byte("1234567"),
		[]byte(strings.Repeat("y", 33)),
	}
	for _, p := range pairs {
		nc, oc := NewCipher(p.newID), NewCipher(p.oldID)
		if nc == nil || oc == nil {
			t.Fatalf("pair %s/%s: nil cipher", p.newID, p.oldID)
		}
		for _, pt := range pts {
			nct, err := nc.Encrypt(pt)
			if err != nil {
				t.Fatalf("%s: %v", p.newID, err)
			}
			oct, err := oc.Encrypt(pt)
			if err != nil {
				t.Fatalf("%s: %v", p.oldID, err)
			}
			if !bytes.Equal(nct, oct) {
				t.Fatalf("mapped pair mismatch: new %s != old %s\n  new=%s\n  old=%s",
					p.newID, p.oldID, shortHex(nct), shortHex(oct))
			}
		}
	}
}

// TestNewGenKeyEquivalence 新代密钥 blob 与旧代常量的等价性（算法验证/02 §1.1 的运行时证明）
func TestNewGenKeyEquivalence(t *testing.T) {
	// 319FC5AB blob = 旧 XTea(B3047D4E) 三钥大端镜像
	if !teaBlobEqualsOld(teaEcbBlob, xteaKey1, xteaKey2, xteaKey3) {
		t.Fatal("319FC5AB blob != old XTea keys (big-endian mirror)")
	}
	// 35101415 blob = 旧 XTeaIv(C32C68F9) 三钥大端镜像
	if !teaBlobEqualsOld(teaCbcBlob, xteaIvKey1, xteaIvKey2, xteaIvKey3) {
		t.Fatal("35101415 blob != old XTeaIv keys (big-endian mirror)")
	}
	// 35101415 iv[0:8] = 旧 xteaIv 大端镜像
	ivBlob := teaCbcIVBlob[:8]
	if binary.BigEndian.Uint32(ivBlob[0:4]) != xteaIv[0] || binary.BigEndian.Uint32(ivBlob[4:8]) != xteaIv[1] {
		t.Fatal("35101415 iv != old xteaIv (big-endian mirror)")
	}
	// 07E824B2 密钥 = 旧 ZUC(B809531F) 字节原样（registry 已用同一常量，此处防御性断言）
	if !bytes.Equal(cipherSnow3gVariant.key, zucKey) || !bytes.Equal(cipherSnow3gVariant.iv, zucIv) {
		t.Fatal("07E824B2 key/iv != old ZUC bytes")
	}
}

// teaBlobEqualsOld 断言 48B blob 按 BigEndian 读出 == 三组旧 uint32 密钥
func teaBlobEqualsOld(blob []byte, k1, k2, k3 []uint32) bool {
	if len(blob) != 48 {
		return false
	}
	for l, keys := range [][]uint32{k1, k2, k3} {
		for i := 0; i < 4; i++ {
			if binary.BigEndian.Uint32(blob[l*16+i*4:l*16+i*4+4]) != keys[i] {
				return false
			}
		}
	}
	return true
}
